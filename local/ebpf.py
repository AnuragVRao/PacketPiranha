"""
ebpf.py — eBPF packet capture program.
Called by launcher.py. Do not run directly unless testing.

Usage: sudo python3 ebpf.py --dest-ip 1.1.1.1 --dst-port 80
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

# ---------------- Args ----------------
parser = argparse.ArgumentParser(description="eBPF packet monitor")
parser.add_argument("--dest-ip",  default="1.1.1.1", help="Destination IP to probe")
parser.add_argument("--dst-port", default=80, type=int, help="Destination port")
args = parser.parse_args()

DEST_IP  = args.dest_ip
DST_PORT = args.dst_port

# ---------------- Preflight checks ----------------
if os.geteuid() != 0:
    sys.exit("Must be run as root: sudo python3 ebpf.py")

kernel = tuple(int(x) for x in os.uname().release.split('.')[:2])
if kernel < (4, 5):
    sys.exit(f"Kernel {os.uname().release} too old. Need 4.5+ (ideally 5.2+)")

try:
    from bcc import BPF
except ImportError:
    sys.exit("BCC not installed. Run: sudo apt install python3-bpfcc")

# ---------------- Configuration ----------------
SRC_PORT = 12345
IP_ID    = 54321

# ---------------- Interface & source IP ----------------
def get_default_iface():
    result = subprocess.check_output("ip route | grep default", shell=True).decode()
    parts = result.split()
    if 'dev' in parts:
        return parts[parts.index('dev') + 1]
    EXCLUDE = {'lo', 'docker0', 'virbr0', 'virbr0-nic'}
    return [i for i in os.listdir('/sys/class/net/') if i not in EXCLUDE][0]

def get_iface_ip(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', iface[:15].encode())
        )[20:24])
    finally:
        s.close()

iface  = get_default_iface()
src_ip = get_iface_ip(iface)
print(f"Using interface: {iface}")
print(f"Source IP:       {src_ip}")
print(f"Destination:     {DEST_IP}:{DST_PORT}")

# ---------------- Checksum ----------------
def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def compute_tcp_checksum(src, dst, tcp_hdr):
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(src),
        socket.inet_aton(dst),
        0,
        socket.IPPROTO_TCP,
        len(tcp_hdr),
    )
    return checksum(pseudo + tcp_hdr)

# ---------------- BPF program ----------------
bpf_prog = f"""
#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

struct packet_t {{
    u8  version;
    u8  ihl;
    u8  protocol;
    u8  ttl;
    u16 tot_len;
    u16 id;
    u16 frag_off;
    u32 saddr;
    u32 daddr;
}};

BPF_PERF_OUTPUT(events);

int monitor_egress(struct __sk_buff *skb) {{
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ip, sizeof(ip)) < 0)
        return 0;

    if (ip.id != __constant_htons({IP_ID}))
        return 0;

    struct packet_t pkt = {{}};
    pkt.version  = ip.version;
    pkt.ihl      = ip.ihl * 4;
    pkt.protocol = ip.protocol;
    pkt.ttl      = ip.ttl;
    pkt.tot_len  = ip.tot_len;
    pkt.id       = ip.id;
    pkt.frag_off = ip.frag_off;
    pkt.saddr    = ip.saddr;
    pkt.daddr    = ip.daddr;

    events.perf_submit_skb(skb, skb->len, &pkt, sizeof(pkt));
    return 0;
}}
"""

# ---------------- Perf struct ----------------
class Packet(Structure):
    _fields_ = [
        ("version",  c_uint8),
        ("ihl",      c_uint8),
        ("protocol", c_uint8),
        ("ttl",      c_uint8),
        ("tot_len",  c_uint16),
        ("id",       c_uint16),
        ("frag_off", c_uint16),
        ("saddr",    c_uint32),
        ("daddr",    c_uint32),
    ]

def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack("I", ip))

def handle_event(cpu, data, size):
    pkt = ctypes.cast(data, ctypes.POINTER(Packet)).contents
    frag_off_host = socket.ntohs(pkt.frag_off)
    print(f"\nCaptured packet [OUTGOING →]:")
    print(f"  ipVersion:      {pkt.version}")
    print(f"  srcIP:          {ip_to_str(pkt.saddr)}")
    print(f"  dstIP:          {ip_to_str(pkt.daddr)}")
    print(f"  TTL:            {pkt.ttl}")
    print(f"  protocol:       {pkt.protocol}")
    print(f"  headerLength:   {pkt.ihl}")
    print(f"  totalLength:    {socket.ntohs(pkt.tot_len)}")
    print(f"  identification: {socket.ntohs(pkt.id)}")
    print(f"  fragmentOffset: {frag_off_host & 0x1FFF}")
    print(f"  DF:             {bool(frag_off_host & 0x4000)}")
    print(f"  MF:             {bool(frag_off_host & 0x2000)}")

# ---------------- Ingress listener ----------------
def listen_for_reply(dest_ip, stop_event):
    try:
        rs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        rs.settimeout(1.0)
    except Exception as e:
        print(f"Raw ingress socket error: {e}")
        return

    dest_packed = socket.inet_aton(dest_ip)

    while not stop_event.is_set():
        try:
            raw, _ = rs.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            break

        if len(raw) < 20:
            continue

        saddr = raw[12:16]
        if saddr != dest_packed:
            continue

        version  = (raw[0] >> 4)
        ihl      = (raw[0] & 0x0F) * 4
        ttl      = raw[8]
        proto    = raw[9]
        tot_len  = struct.unpack('!H', raw[2:4])[0]
        ip_id    = struct.unpack('!H', raw[4:6])[0]
        frag_off = struct.unpack('!H', raw[6:8])[0]
        daddr    = raw[16:20]

        tcp_flags = ""
        if proto == 6 and len(raw) >= ihl + 14:
            flags_byte = raw[ihl + 13]
            tcp_flags += "SYN " if flags_byte & 0x02 else ""
            tcp_flags += "ACK " if flags_byte & 0x10 else ""
            tcp_flags += "RST " if flags_byte & 0x04 else ""
            tcp_flags += "FIN " if flags_byte & 0x01 else ""

        print(f"\nCaptured packet [← INCOMING] TCP flags: {tcp_flags.strip()}:")
        print(f"  ipVersion:      {version}")
        print(f"  srcIP:          {socket.inet_ntoa(saddr)}")
        print(f"  dstIP:          {socket.inet_ntoa(daddr)}")
        print(f"  TTL:            {ttl}")
        print(f"  protocol:       {proto}")
        print(f"  headerLength:   {ihl}")
        print(f"  totalLength:    {tot_len}")
        print(f"  identification: {ip_id}")
        print(f"  fragmentOffset: {frag_off & 0x1FFF}")
        print(f"  DF:             {bool(frag_off & 0x4000)}")
        print(f"  MF:             {bool(frag_off & 0x2000)}")
        sys.stdout.flush()

        # Signal done and stop
        stop_event.set()
        break

    rs.close()

# ---------------- Send raw SYN ----------------
def send_raw_syn():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    seq = random.randint(1000000, 4000000000)

    tcp_no_csum = struct.pack('!HHLLBBHHH',
        SRC_PORT, DST_PORT, seq, 0, 0x50, 0x02, 65535, 0, 0)
    tcp_csum = compute_tcp_checksum(src_ip, DEST_IP, tcp_no_csum)
    tcp_header = struct.pack('!HHLLBBHHH',
        SRC_PORT, DST_PORT, seq, 0, 0x50, 0x02, 65535, tcp_csum, 0)

    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 40, IP_ID, 0x4000, 64,
        socket.IPPROTO_TCP, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(DEST_IP),
    )

    s.sendto(ip_header + tcp_header, (DEST_IP, 0))
    s.close()
    print(f"Sent raw TCP SYN → {DEST_IP}:{DST_PORT} | IP ID={IP_ID} | seq={seq} | src={src_ip}")

# ---------------- Load BPF ----------------
b = BPF(text=bpf_prog)
fn_egress = b.load_func("monitor_egress", BPF.SOCKET_FILTER)
b.attach_raw_socket(fn_egress, iface)
b["events"].open_perf_buffer(handle_event)

# ---------------- Start ingress thread ----------------
stop_event = threading.Event()
t = threading.Thread(target=listen_for_reply, args=(DEST_IP, stop_event), daemon=True)
t.start()

# ---------------- Drop RST ----------------
os.system(f"iptables -A OUTPUT -p tcp --sport {SRC_PORT} --tcp-flags RST RST -j DROP 2>/dev/null")

# ---------------- Send packet ----------------
send_raw_syn()
print("Waiting for packets...\n")
sys.stdout.flush()

# ---------------- Poll until reply received ----------------
try:
    while not stop_event.is_set():
        b.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    pass
finally:
    stop_event.set()
    t.join(timeout=2)
    os.system(f"iptables -D OUTPUT -p tcp --sport {SRC_PORT} --tcp-flags RST RST -j DROP 2>/dev/null")
    print("Done.")
    sys.stdout.flush()
