"""
ebpf.py — eBPF TC-ingress packet capture.
Called by launcher.py. Do not run directly unless testing.

Usage: sudo python3 ebpf.py --dest-ip 1.1.1.1 --dst-port 80 --count 10
"""

import argparse
import ctypes
from ctypes import *
import socket
import struct
import os
import sys
import subprocess
import fcntl
import threading
import random
import time

TC_ATTACHED = False

# ---------------- Args ----------------
parser = argparse.ArgumentParser(description="eBPF TC ingress packet monitor")
parser.add_argument("--dest-ip",  default="1.1.1.1", help="Destination IP to probe")
parser.add_argument("--dst-port", default=80, type=int, help="Destination port")
parser.add_argument("--count",    default=10, type=int, help="Number of packets to send/capture")
args = parser.parse_args()

DEST_IP  = args.dest_ip
DST_PORT = args.dst_port
COUNT    = args.count

# ---------------- Preflight checks ----------------
if os.geteuid() != 0:
    sys.exit("Must be run as root: sudo python3 ebpf.py")

kernel = tuple(int(x) for x in os.uname().release.split('-')[0].split('.')[:2])
if kernel < (4, 5):
    sys.exit(f"Kernel {os.uname().release} too old. Need 4.5+")

try:
    from bcc import BPF
except ImportError:
    sys.exit("BCC not installed. Run: sudo apt install python3-bpfcc")

# ---------------- Interface & source IP ----------------
def get_default_iface():
    try:
        result = subprocess.check_output("ip route | grep default", shell=True).decode()
        parts = result.split()
        if 'dev' in parts:
            return parts[parts.index('dev') + 1]
    except Exception:
        pass
    EXCLUDE = {'lo', 'docker0', 'virbr0', 'virbr0-nic'}
    return [i for i in os.listdir('/sys/class/net/') if i not in EXCLUDE][0]

def get_iface_ip(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915,
            struct.pack('256s', iface[:15].encode())
        )[20:24])
    finally:
        s.close()

def get_iface_mac(iface):
    try:
        with open(f'/sys/class/net/{iface}/address') as f:
            return f.read().strip()
    except Exception:
        return "00:00:00:00:00:00"

iface   = get_default_iface()
src_ip  = get_iface_ip(iface)
src_mac = get_iface_mac(iface)

print(f"[INFO] Interface: {iface}  MAC: {src_mac}")
print(f"[INFO] Source IP: {src_ip}")
print(f"[INFO] Destination: {DEST_IP}:{DST_PORT}  count={COUNT}")
sys.stdout.flush()

# ---------------- Checksum helpers ----------------
def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def tcp_checksum(src, dst, tcp_hdr):
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(src), socket.inet_aton(dst),
        0, socket.IPPROTO_TCP, len(tcp_hdr))
    return checksum(pseudo + tcp_hdr)

# ---------------- BPF program (TC ingress) ----------------
# We tag each probe packet with a unique IP ID range so we can identify replies.
# TC classifier fires on ingress, parses Eth+IP+TCP, filters by src IP == DEST_IP
# and our ephemeral src port range, then pushes full frame data to userspace.

BPF_SRC_PORT_BASE = 20000   # we'll use ports 20000–20009 for 10 packets
DEST_IP_INT = struct.unpack("!I", socket.inet_aton(DEST_IP))[0]

bpf_prog = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

// Full captured frame info
struct frame_t {
    // Layer 2
    u8  src_mac[6];
    u8  dst_mac[6];
    u16 eth_type;
    // Layer 3
    u8  ip_version;
    u8  ip_ihl;
    u8  ip_tos;
    u16 ip_tot_len;
    u16 ip_id;
    u16 ip_frag_off;
    u8  ip_ttl;
    u8  ip_protocol;
    u16 ip_check;
    u32 ip_saddr;
    u32 ip_daddr;
    // Layer 4 TCP
    u16 tcp_sport;
    u16 tcp_dport;
    u32 tcp_seq;
    u32 tcp_ack_seq;
    u8  tcp_doff;
    u8  tcp_flags;
    u16 tcp_window;
    u16 tcp_check;
    u16 tcp_urg;
    // timing (ns)
    u64 ts_ns;
    // packet index (which probe triggered this reply)
    u16 probe_idx;
};

BPF_PERF_OUTPUT(ingress_events);
BPF_ARRAY(dst_ip_map, u32, 1);       // destination IP filter
BPF_ARRAY(sport_base_map, u32, 1);   // base src port

int tc_ingress(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end) return TC_ACT_OK;

    // Filter: must come from our destination IP
    int key = 0;
    u32 *dst_filter = dst_ip_map.lookup(&key);
    if (!dst_filter) return TC_ACT_OK;
    if (ip->saddr != *dst_filter) return TC_ACT_OK;

    // Only handle TCP for now
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

    int ip_hdr_len = ip->ihl * 4;
    struct tcphdr *tcp = (void*)ip + ip_hdr_len;
    if ((void*)(tcp + 1) > data_end) return TC_ACT_OK;

    // Filter: dport must be in our probe range (sport_base .. sport_base+19)
    u32 *base = sport_base_map.lookup(&key);
    if (!base) return TC_ACT_OK;
    u16 dport = __constant_ntohs(tcp->dest);
    if (dport < (u16)*base || dport >= (u16)(*base + 20)) return TC_ACT_OK;

    struct frame_t frame = {};

    // Layer 2
    __builtin_memcpy(frame.src_mac, eth->h_source, 6);
    __builtin_memcpy(frame.dst_mac, eth->h_dest,   6);
    frame.eth_type = __constant_ntohs(eth->h_proto);

    // Layer 3
    frame.ip_version  = ip->version;
    frame.ip_ihl      = ip->ihl * 4;
    frame.ip_tos      = ip->tos;
    frame.ip_tot_len  = __constant_ntohs(ip->tot_len);
    frame.ip_id       = __constant_ntohs(ip->id);
    frame.ip_frag_off = __constant_ntohs(ip->frag_off);
    frame.ip_ttl      = ip->ttl;
    frame.ip_protocol = ip->protocol;
    frame.ip_check    = ip->check;
    frame.ip_saddr    = ip->saddr;
    frame.ip_daddr    = ip->daddr;

    // Layer 4
    frame.tcp_sport   = __constant_ntohs(tcp->source);
    frame.tcp_dport   = __constant_ntohs(tcp->dest);
    frame.tcp_seq     = __constant_ntohl(tcp->seq);
    frame.tcp_ack_seq = __constant_ntohl(tcp->ack_seq);
    frame.tcp_doff    = tcp->doff * 4;
    frame.tcp_flags   = (tcp->fin)       |
                        (tcp->syn  << 1) |
                        (tcp->rst  << 2) |
                        (tcp->psh  << 3) |
                        (tcp->ack  << 4) |
                        (tcp->urg  << 5);
    frame.tcp_window  = __constant_ntohs(tcp->window);
    frame.tcp_check   = tcp->check;
    frame.tcp_urg     = __constant_ntohs(tcp->urg_ptr);
    frame.ts_ns       = bpf_ktime_get_ns();
    frame.probe_idx   = dport - (u16)*base;

    ingress_events.perf_submit(skb, &frame, sizeof(frame));
    return TC_ACT_OK;
}
"""

# ---------------- ctypes struct matching BPF ----------------
class Frame(Structure):
    _fields_ = [
        ("src_mac",    c_uint8 * 6),
        ("dst_mac",    c_uint8 * 6),
        ("eth_type",   c_uint16),
        ("ip_version", c_uint8),
        ("ip_ihl",     c_uint8),
        ("ip_tos",     c_uint8),
        ("ip_tot_len", c_uint16),
        ("ip_id",      c_uint16),
        ("ip_frag_off",c_uint16),
        ("ip_ttl",     c_uint8),
        ("ip_protocol",c_uint8),
        ("ip_check",   c_uint16),
        ("ip_saddr",   c_uint32),
        ("ip_daddr",   c_uint32),
        ("tcp_sport",  c_uint16),
        ("tcp_dport",  c_uint16),
        ("tcp_seq",    c_uint32),
        ("tcp_ack_seq",c_uint32),
        ("tcp_doff",   c_uint8),
        ("tcp_flags",  c_uint8),
        ("tcp_window", c_uint16),
        ("tcp_check",  c_uint16),
        ("tcp_urg",    c_uint16),
        ("ts_ns",      c_uint64),
        ("probe_idx",  c_uint16),
    ]

def mac_str(arr): return ':'.join(f'{b:02x}' for b in arr)
def ip_str(addr):
    packed = struct.pack("I", addr)
    return socket.inet_ntoa(packed)

def flags_str(f):
    names = ['FIN','SYN','RST','PSH','ACK','URG']
    return ' '.join(n for i, n in enumerate(names) if f & (1 << i)) or 'NONE'

def dscp_str(tos): return tos >> 2
def ecn_str(tos):  return tos & 0x3

# ---------------- Shared state ----------------
captured   = {}          # probe_idx -> Frame data dict
send_times = {}          # probe_idx -> send timestamp (time.time())
lock       = threading.Lock()
done_event = threading.Event()

def handle_ingress(cpu, data, size):
    f = ctypes.cast(data, ctypes.POINTER(Frame)).contents
    recv_time = time.time()
    idx = f.probe_idx
    frag = f.ip_frag_off
    df  = bool(frag & 0x4000)
    mf  = bool(frag & 0x2000)
    frag_offset = frag & 0x1FFF

    with lock:
        rtt_ms = None
        if idx in send_times:
            rtt_ms = round((recv_time - send_times[idx]) * 1000, 3)

        # inter-packet delay: ns since the previous captured packet (arrival order)
        prev_ts_ns = max((v["bpf_ts_ns"] for v in captured.values()), default=None)
        inter_pkt_delay_us = (
            round((f.ts_ns - prev_ts_ns) / 1_000, 2)
            if prev_ts_ns is not None and f.ts_ns > prev_ts_ns
            else None
        )

        frame_dict = {
            # Layer 2
            "src_mac":    mac_str(f.src_mac),
            "dst_mac":    mac_str(f.dst_mac),
            "eth_type":   f"0x{f.eth_type:04x}",
            # Layer 3
            "ip_version":      f.ip_version,
            "ip_ihl":          f.ip_ihl,
            "ip_tos":          f.ip_tos,
            "ip_dscp":         dscp_str(f.ip_tos),
            "ip_ecn":          ecn_str(f.ip_tos),
            "ip_tot_len":      f.ip_tot_len,
            "ip_id":           f.ip_id,
            "ip_frag_off":     frag_offset,
            "ip_df":           df,
            "ip_mf":           mf,
            "ip_ttl":          f.ip_ttl,
            "ip_protocol":     f.ip_protocol,
            "ip_checksum":     f"0x{f.ip_check:04x}",
            "ip_src":          ip_str(f.ip_saddr),
            "ip_dst":          ip_str(f.ip_daddr),
            # Layer 4
            "tcp_sport":       f.tcp_sport,
            "tcp_dport":       f.tcp_dport,
            "tcp_seq":         f.tcp_seq,
            "tcp_ack":         f.tcp_ack_seq,
            "tcp_header_len":  f.tcp_doff,
            "tcp_flags":       flags_str(f.tcp_flags),
            "tcp_flags_raw":   f.tcp_flags,
            "tcp_window":      f.tcp_window,
            "tcp_checksum":    f"0x{f.tcp_check:04x}",
            "tcp_urgent":      f.tcp_urg,
            # Timing
            "bpf_ts_ns":           f.ts_ns,
            "rtt_ms":              rtt_ms,
            "inter_pkt_delay_us":  inter_pkt_delay_us,
        }
        captured[idx] = frame_dict

        syn  = bool(f.tcp_flags & 0x02)
        ack  = bool(f.tcp_flags & 0x10)
        rst  = bool(f.tcp_flags & 0x04)
        flag_label = flags_str(f.tcp_flags)

        print(f"\n[INGRESS eBPF] probe={idx}  {ip_str(f.ip_saddr)}:{f.tcp_sport} → {ip_str(f.ip_daddr)}:{f.tcp_dport}")
        print(f"  L2  src_mac={mac_str(f.src_mac)}  dst_mac={mac_str(f.dst_mac)}  eth_type=0x{f.eth_type:04x}")
        print(f"  L3  ttl={f.ip_ttl}  id={f.ip_id}  tot_len={f.ip_tot_len}  DF={df}  MF={mf}  frag_off={frag_offset}")
        print(f"  L3  tos={f.ip_tos}  dscp={dscp_str(f.ip_tos)}  ecn={ecn_str(f.ip_tos)}")
        print(f"  L4  flags={flag_label}  seq={f.tcp_seq}  ack={f.tcp_ack_seq}  win={f.tcp_window}  hdr_len={f.tcp_doff}")
        print(f"  TS  bpf_ns={f.ts_ns}  rtt={rtt_ms}ms")
        sys.stdout.flush()

        if len(captured) >= COUNT:
            done_event.set()

# ---------------- Load BPF + attach TC ----------------
b = BPF(text=bpf_prog)

# Set filter maps
dst_filter_map = b["dst_ip_map"]
dst_filter_map[ctypes.c_int(0)] = ctypes.c_uint32(
    struct.unpack("I", socket.inet_aton(DEST_IP))[0]
)
sport_base_map = b["sport_base_map"]
sport_base_map[ctypes.c_int(0)] = ctypes.c_uint32(BPF_SRC_PORT_BASE)

# Attach as TC ingress classifier
fn = b.load_func("tc_ingress", BPF.SCHED_CLS)
#b.attach_raw_socket(fn, iface)   # fallback — try TC first

try:
    from pyroute2 import IPRoute
    ip = IPRoute()
    idx = ip.link_lookup(ifname=iface)[0]

    try:
        ip.tc("del", "clsact", idx)
    except:
        pass

    ip.tc("add", "clsact", idx)
    ip.tc("add-filter", "bpf", idx, ":1",
          fd=fn.fd,
          name=fn.name,
          parent="ffff:fff2",
          classid=1,
          direct_action=True)

    print("[INFO] TC ingress classifier attached to", iface)
    TC_ATTACHED = True

except Exception as e:
    print(f"[FAIL] TC attach failed: {e}")
    sys.exit(1)

b["ingress_events"].open_perf_buffer(handle_ingress)

# ---------------- iptables: suppress RST for our probe ports ----------------
for i in range(COUNT):
    port = BPF_SRC_PORT_BASE + i
    os.system(f"iptables -A OUTPUT -p tcp --sport {port} --tcp-flags RST RST -j DROP 2>/dev/null")

# ---------------- Send raw SYN probes ----------------
def send_probes():
    raw_s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    for i in range(COUNT):
        src_port = BPF_SRC_PORT_BASE + i
        ip_id    = 0xA000 + i
        seq      = random.randint(1_000_000, 4_000_000_000)

        # TCP header (no checksum yet)
        tcp_hdr = struct.pack('!HHLLBBHHH',
            src_port, DST_PORT, seq, 0, 0x50, 0x02, 65535, 0, 0)
        csum = tcp_checksum(src_ip, DEST_IP, tcp_hdr)
        tcp_hdr = struct.pack('!HHLLBBHHH',
            src_port, DST_PORT, seq, 0, 0x50, 0x02, 65535, csum, 0)

        ip_hdr = struct.pack('!BBHHHBBH4s4s',
            0x45, 0x00, 40, ip_id, 0x4000, 64,
            socket.IPPROTO_TCP, 0,
            socket.inet_aton(src_ip),
            socket.inet_aton(DEST_IP),
        )

        with lock:
            send_times[i] = time.time()

        raw_s.sendto(ip_hdr + tcp_hdr, (DEST_IP, 0))
        print(f"[EGRESS] probe={i}  {src_ip}:{src_port} → {DEST_IP}:{DST_PORT}  ip_id=0x{ip_id:04x}  seq={seq}")
        sys.stdout.flush()
        time.sleep(0.05)   # 50ms spacing

    raw_s.close()

sender = threading.Thread(target=send_probes, daemon=True)
sender.start()

print(f"[INFO] Waiting for {COUNT} ingress replies...\n")
sys.stdout.flush()

# ---------------- Poll perf buffer ----------------
try:
    timeout_s = 15
    start = time.time()
    while not done_event.is_set():
        b.perf_buffer_poll(timeout=100)
        if time.time() - start > timeout_s:
            print(f"[WARN] Timeout. Captured {len(captured)}/{COUNT} packets.")
            sys.stdout.flush()
            break
except KeyboardInterrupt:
    pass
finally:
    # Cleanup iptables rules
    for i in range(COUNT):
        port = BPF_SRC_PORT_BASE + i
        os.system(f"iptables -D OUTPUT -p tcp --sport {port} --tcp-flags RST RST -j DROP 2>/dev/null")

    # Detach TC if we attached it
    if TC_ATTACHED:
        try:
            ip.tc("del", "clsact", idx)
        except Exception:
            pass

    # Emit final summary to stdout for launcher to parse
    import json
    print("\n[SUMMARY_JSON]")
    print(json.dumps(list(captured.values())))
    print("[/SUMMARY_JSON]")
    sys.stdout.flush()
    print("[DONE]")
    sys.stdout.flush()