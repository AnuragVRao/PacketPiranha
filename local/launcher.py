"""
launcher.py — run with: sudo python3 launcher.py
Requires: pip install flask flask-socketio eventlet
"""
from flask import Flask, request
from flask_socketio import SocketIO, emit
import subprocess
import threading
import os
import json
import statistics

app = Flask(__name__)
app.config["SECRET_KEY"] = "ebpf-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

EBPF_SCRIPT = os.path.join(os.path.dirname(__file__), "ebpf.py")

# ── Aggregate frames into OSI-layer structure ─────────────────────────────────
def _aggregate(frames: list[dict]) -> dict:
    """
    Takes a list of raw captured frame dicts from ebpf.py and produces
    a single aggregated packet object with real + derived stats per layer.
    """
    if not frames:
        return {}

    n = len(frames)

    # ── helpers ──
    def vals(key):
        return [f[key] for f in frames if f.get(key) is not None]

    def avg(key):
        v = [x for x in vals(key) if isinstance(x, (int, float))]
        return round(statistics.mean(v), 3) if v else None

    def mn(key):
        v = [x for x in vals(key) if isinstance(x, (int, float))]
        return min(v) if v else None

    def mx(key):
        v = [x for x in vals(key) if isinstance(x, (int, float))]
        return max(v) if v else None

    def most_common(key):
        v = vals(key)
        return max(set(v), key=v.count) if v else None

    def count_flag(flag_str):
        return sum(1 for f in frames if flag_str in f.get("tcp_flags", ""))

    # ── Layer 1 (physical — best-effort from interface) ──
    layer1 = {
        "interface":       frames[0].get("_iface", "eth0"),
        "direction":       "ingress",
        "packetsObserved": n,
        "layer":           "Physical",
    }

    # ── Layer 2 (Data Link — real from eBPF) ──
    src_macs = list(set(vals("src_mac")))
    dst_macs = list(set(vals("dst_mac")))
    layer2 = {
        "srcMAC":          src_macs[0] if src_macs else "n/a",
        "dstMAC":          dst_macs[0] if dst_macs else "n/a",
        "uniqueSrcMACs":   len(src_macs),
        "ethType":         most_common("eth_type") or "0x0800",
        "framesCapured":   n,
        "avgFrameLen":     avg("ip_tot_len"),   # IP total length (best proxy without L2 len)
        "minFrameLen":     mn("ip_tot_len"),
        "maxFrameLen":     mx("ip_tot_len"),
    }

    # ── Layer 3 (Network — real from eBPF) ──
    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    proto_num = most_common("ip_protocol")
    ttls = [f["ip_ttl"] for f in frames if "ip_ttl" in f]
    ids  = [f["ip_id"]  for f in frames if "ip_id"  in f]
    layer3 = {
        "srcIP":           most_common("ip_src"),
        "dstIP":           most_common("ip_dst"),
        "ipVersion":       most_common("ip_version"),
        "protocol":        proto_map.get(proto_num, str(proto_num)),
        "avgTTL":          round(statistics.mean(ttls), 2) if ttls else None,
        "minTTL":          min(ttls) if ttls else None,
        "maxTTL":          max(ttls) if ttls else None,
        "ttlVariance":     round(statistics.variance(ttls), 4) if len(ttls) > 1 else 0,
        "avgTotalLen":     avg("ip_tot_len"),
        "dfSet":           sum(1 for f in frames if f.get("ip_df")),
        "mfSet":           sum(1 for f in frames if f.get("ip_mf")),
        "fragmented":      sum(1 for f in frames if f.get("ip_frag_off", 0) > 0),
        "uniqueIPIDs":     len(set(ids)),
        "avgDSCP":         avg("ip_dscp"),
        "avgECN":          avg("ip_ecn"),
    }

    # ── Layer 4 (Transport — real from eBPF) ──
    # Sort frames by probe_idx so per-packet series are in send order
    ordered = sorted(frames, key=lambda f: f.get("probe_idx", 0) if "probe_idx" in f
                     else frames.index(f))

    rtts = [f["rtt_ms"] for f in ordered if f.get("rtt_ms") is not None]
    windows = [f["tcp_window"] for f in ordered if "tcp_window" in f]

    # Real per-packet RTT series (probe_idx → rtt_ms), None where no reply
    rtt_series = [f.get("rtt_ms") for f in ordered]

    # Inter-packet delays from BPF kernel timestamps (µs), arrival order
    bpf_ts_ordered = sorted(
        [f["bpf_ts_ns"] for f in frames if f.get("bpf_ts_ns")],
    )
    inter_delays_us = [
        round((bpf_ts_ordered[i] - bpf_ts_ordered[i-1]) / 1_000, 2)
        for i in range(1, len(bpf_ts_ordered))
    ]

    # TCP sequence number deltas between consecutive captured packets
    seqs = [f["tcp_seq"] for f in ordered if "tcp_seq" in f]
    seq_deltas = [seqs[i] - seqs[i-1] for i in range(1, len(seqs))]

    layer4 = {
        "protocol":        "TCP",
        "dstPort":         most_common("tcp_dport"),
        "srcPort":         most_common("tcp_sport"),
        "synAckCount":     count_flag("SYN") + count_flag("ACK") - count_flag("RST"),
        "rstCount":        count_flag("RST"),
        "finCount":        count_flag("FIN"),
        "flagCounts": {
            "SYN": count_flag("SYN"),
            "ACK": count_flag("ACK"),
            "RST": count_flag("RST"),
            "FIN": count_flag("FIN"),
            "PSH": count_flag("PSH"),
            "URG": count_flag("URG"),
        },
        "avgRTT_ms":       round(statistics.mean(rtts), 3) if rtts else None,
        "minRTT_ms":       round(min(rtts), 3) if rtts else None,
        "maxRTT_ms":       round(max(rtts), 3) if rtts else None,
        "rttJitter_ms":    round(statistics.stdev(rtts), 3) if len(rtts) > 1 else 0,
        "rttSeries":       rtt_series,           # real per-packet RTTs
        "interPktDelays_us": inter_delays_us,    # inter-arrival times from BPF clock
        "seqDeltas":       seq_deltas,           # TCP seq number deltas
        "avgWindowSize":   round(statistics.mean(windows), 1) if windows else None,
        "minWindowSize":   min(windows) if windows else None,
        "maxWindowSize":   max(windows) if windows else None,
        "totalPackets":    n,
    }

    # ── Layer 5/6 (Session/Presentation — derived) ──
    src_ip = most_common("ip_src")
    dst_ip = most_common("ip_dst")
    bpf_ts = [f["bpf_ts_ns"] for f in frames if f.get("bpf_ts_ns")]
    session_duration_ms = None
    if len(bpf_ts) >= 2:
        session_duration_ms = round((max(bpf_ts) - min(bpf_ts)) / 1e6, 3)

    # infer TLS based on port
    dst_port = most_common("tcp_dport")
    tls_hint = "TLS (likely)" if dst_port in (443, 8443) else "plaintext (port 80)"

    layer5_6 = {
        "flowID":              f"{src_ip} ↔ {dst_ip}",
        "sessionPackets":      n,
        "sessionDuration_ms":  session_duration_ms,
        "estimatedState":      "SYN_SENT → SYN_ACK received",
        "encryptionHint":      tls_hint,
        "compressionHint":     "none detected",
        "firstSeqSeen":        frames[0].get("tcp_seq") if frames else None,
        "lastSeqSeen":         frames[-1].get("tcp_seq") if frames else None,
    }

    # ── Layer 7 (Application — inferred from port) ──
    port_app_map = {
        80:   {"protocol": "HTTP",  "description": "Hypertext Transfer Protocol"},
        443:  {"protocol": "HTTPS", "description": "HTTP over TLS"},
        53:   {"protocol": "DNS",   "description": "Domain Name System"},
        22:   {"protocol": "SSH",   "description": "Secure Shell"},
        25:   {"protocol": "SMTP",  "description": "Simple Mail Transfer Protocol"},
        8080: {"protocol": "HTTP",  "description": "HTTP alternate port"},
    }
    app_info = port_app_map.get(dst_port, {"protocol": "unknown", "description": f"port {dst_port}"})
    layer7 = {
        "inferredProtocol":  app_info["protocol"],
        "description":       app_info["description"],
        "destinationPort":   dst_port,
        "note":              "Application layer data not decoded (raw TCP SYN probes)",
    }

    # ── Kernel Metadata (partial — from eBPF ktime) ──
    bpf_ts_sorted = sorted(bpf_ts)
    kernel_meta = {
        "captureMethod":   "eBPF TC ingress classifier",
        "ebpfProgram":     "tc_ingress / SCHED_CLS",
        "firstCapture_ns": bpf_ts_sorted[0]  if bpf_ts_sorted else None,
        "lastCapture_ns":  bpf_ts_sorted[-1] if bpf_ts_sorted else None,
        "captureSpan_ms":  round((bpf_ts_sorted[-1] - bpf_ts_sorted[0]) / 1e6, 3) if len(bpf_ts_sorted) >= 2 else 0,
        "packetsMatched":  n,
        "pid":             "n/a (ingress — no socket ownership)",
        "note":            "TC ingress; process attribution requires egress eBPF or kprobe",
    }

    # ── Payload (from IP total length vs headers) ──
    payloads = []
    for f in frames:
        tot = f.get("ip_tot_len", 0)
        ihl = f.get("ip_ihl", 20)
        thl = f.get("tcp_header_len", 20)
        pay = tot - ihl - thl
        if pay >= 0:
            payloads.append(pay)

    payload = {
        "avgPayloadBytes":  round(statistics.mean(payloads), 1) if payloads else 0,
        "minPayloadBytes":  min(payloads) if payloads else 0,
        "maxPayloadBytes":  max(payloads) if payloads else 0,
        "totalPayloadBytes": sum(payloads),
        "note":             "SYN-ACK replies carry no application payload",
    }

    return {
        "layer1":              layer1,
        "layer2":              layer2,
        "layer3":              layer3,
        "layer4":              layer4,
        "sessionPresentation": layer5_6,
        "layer7":              layer7,
        "kernelMetadata":      kernel_meta,
        "payload":             payload,
        "_meta": {
            "totalFramesCaptured": n,
            "captureTarget":       f"{dst_ip}:{dst_port}",
        }
    }

# ── SocketIO events ────────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    print("Frontend connected")
    emit("status", {"message": "Connected to launcher"})

@socketio.on("start_capture")
def on_start_capture(data):
    dest_ip  = data.get("destIp",  "1.1.1.1")
    dst_port = int(data.get("dstPort", 80))
    count    = int(data.get("count", 10))
    sid      = request.sid
    emit("status", {"message": f"Starting capture → {dest_ip}:{dst_port} x{count}"})
    thread = threading.Thread(
        target=_run_capture,
        args=(dest_ip, dst_port, count, sid),
        daemon=True
    )
    thread.start()

def _run_capture(dest_ip: str, dst_port: int, count: int, sid: str):

    PYTHON_BIN = os.path.join(os.path.dirname(__file__), "venv/bin/python")

    try:
        proc = subprocess.Popen(
            ["sudo", "-E", PYTHON_BIN , "-u", EBPF_SCRIPT,
             "--dest-ip", dest_ip,
             "--dst-port", str(dst_port),
             "--count",    str(count)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as e:
        socketio.emit("error", {"message": f"Failed to start ebpf.py: {e}"}, room=sid)
        return

    summary_json = None
    collecting_json = False
    json_lines = []

    def _reader():
        nonlocal summary_json, collecting_json, json_lines
        for raw_line in proc.stdout:
            line = raw_line.rstrip()
            print(f"[ebpf stdout] {line}")

            # Stream per-packet status to frontend
            if line.startswith("[INGRESS eBPF]"):
                parts = line.split()
                probe = next((p.split("=")[1] for p in parts if p.startswith("probe=")), "?")
                socketio.emit("status", {"message": f"Captured reply {probe}/{count}"}, room=sid)
                socketio.sleep(0)

            # Collect the JSON summary block
            if line.strip() == "[SUMMARY_JSON]":
                collecting_json = True
                json_lines = []
                continue
            if line.strip() == "[/SUMMARY_JSON]":
                collecting_json = False
                raw_json = "\n".join(json_lines)
                try:
                    summary_json = json.loads(raw_json)
                except Exception as e:
                    print(f"[ERROR] JSON parse failed: {e}")
                continue
            if collecting_json:
                json_lines.append(line)
                continue

            if line == "[DONE]":
                break

    def _stderr_reader():
        for line in proc.stderr:
            line = line.strip()
            if line:
                print(f"[ebpf stderr] {line}")
                socketio.emit("status", {"message": f"[ebpf] {line}"}, room=sid)
                socketio.sleep(0)

    reader = threading.Thread(target=_reader, daemon=True)
    stderr_r = threading.Thread(target=_stderr_reader, daemon=True)
    reader.start()
    stderr_r.start()
    reader.join(timeout=20)

    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        proc.kill()

    if summary_json:
        aggregated = _aggregate(summary_json)
        socketio.emit("packet_data", aggregated, room=sid)
        socketio.emit("status", {"message": f"Capture complete — {len(summary_json)} packets"}, room=sid)
    else:
        socketio.emit("error", {"message": "No packets captured / timed out"}, room=sid)
    socketio.sleep(0)

# ── HTTP ───────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return "eBPF launcher running. Connect via SocketIO."

if __name__ == "__main__":
    print("Starting eBPF launcher on http://localhost:4242")
    socketio.run(app, host="0.0.0.0", port=4242, debug=False)