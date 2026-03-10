"""
launcher.py — run with: sudo python3 launcher.py
Requires: pip install flask flask-socketio eventlet
"""

import eventlet
eventlet.monkey_patch()

from flask import Flask, request
from flask_socketio import SocketIO, emit
import subprocess
import threading
import os

app    = Flask(__name__)
app.config["SECRET_KEY"] = "ebpf-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

EBPF_SCRIPT = os.path.join(os.path.dirname(__file__), "ebpf.py")

# ── Packet parser ──────────────────────────────────────────────────────────────

def _parse_packet_lines(lines: list[str]) -> dict:
    type_map = {
        "ipVersion":      int,
        "srcIP":          str,
        "dstIP":          str,
        "TTL":            int,
        "protocol":       int,
        "headerLength":   int,
        "totalLength":    int,
        "identification": int,
        "fragmentOffset": int,
        "DF":             lambda v: v == "True",
        "MF":             lambda v: v == "True",
    }
    result = {}
    for line in lines:
        line = line.strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key in type_map:
            try:
                result[key] = type_map[key](value)
            except (ValueError, TypeError):
                result[key] = value
    return result


def _build_packet(dest_ip: str, raw: dict) -> dict:
    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    proto_str = proto_map.get(raw.get("protocol", 0), str(raw.get("protocol", "unknown")))

    return {
        "layer1": {
            "interface":      "eth0",           # placeholder
            "interfaceIndex": 2,                # placeholder
            "linkSpeed":      "1Gbps",          # placeholder
            "duplexMode":     "full",           # placeholder
            "direction":      "ingress",        # placeholder
            "timestamp":      "10:23:41.12341"  # placeholder
        },
        "layer2": {
            "packetNum":    134,                   # placeholder
            "packetLength": "74 bytes",            # placeholder
            "srcMAC":       "00:1A:2B:3C:4D:5E",  # placeholder
            "dstMAC":       "10:22:33:44:55:66",  # placeholder
            "etherType":    "Ethernet II",         # placeholder
            "frameType":    "unicast",             # placeholder
            "vlanID":       100,                   # placeholder
            "vlanPriority": 3,                     # placeholder
            "dei":          0                      # placeholder
        },
        "layer3": {
            "ipVersion":      raw.get("ipVersion",      None),  # real
            "srcIP":          raw.get("srcIP",          None),  # real
            "dstIP":          raw.get("dstIP",          None),  # real
            "TTL":            raw.get("TTL",            None),  # real
            "protocol":       proto_str,                        # real
            "headerLength":   raw.get("headerLength",   None),  # real
            "totalLength":    raw.get("totalLength",    None),  # real
            "identification": raw.get("identification", None),  # real
            "fragmentOffset": raw.get("fragmentOffset", None),  # real
            "df":             raw.get("DF",             None),  # real
            "mf":             raw.get("MF",             None),  # real
            "checksum":       "0x0000",  # placeholder
            "dscp":           0,         # placeholder
            "ecn":            0          # placeholder
        },
        "layer4": {
            "srcPort":         54321,     # placeholder
            "dstPort":         443,       # placeholder
            "protocol":        "TCP",     # placeholder
            "seq":             1001,      # placeholder
            "ack":             2001,      # placeholder
            "flags":           "syn",     # placeholder
            "windowSize":      64240,     # placeholder
            "tcpHeaderLength": 32,        # placeholder
            "checksum":        "0x4fa2",  # placeholder
            "urgentPointer":   0,         # placeholder
            "mss":             1460,      # placeholder
            "windowScale":     7,         # placeholder
            "sackPermitted":   True       # placeholder
        },
        "sessionPresentation": {
            "flowID":             f"{raw.get('srcIP', '?')}:?-{dest_ip}:?",  # partial real
            "sessionState":       "SYN_SENT",              # placeholder
            "packetsInFlow":      5,                        # placeholder
            "bytesInFlow":        740,                      # placeholder
            "flowDuration":       "0.3s",                   # placeholder
            "tlsVersion":         "TLS1.3",                 # placeholder
            "cipherSuite":        "TLS_AES_128_GCM_SHA256", # placeholder
            "compression":        "none",                   # placeholder
            "certificateIssuer":  "Google Trust Services",  # placeholder
            "certificateSubject": "google.com"              # placeholder
        },
        "layer7": {
            "applicationProtocol": "HTTP",        # placeholder
            "httpMethod":          "GET",          # placeholder
            "httpHost":            "google.com",   # placeholder
            "httpPath":            "/search",      # placeholder
            "statusCode":          200,            # placeholder
            "userAgent":           "Mozilla/5.0",  # placeholder
            "contentType":         "text/html"     # placeholder
        },
        "kernelMetadata": {
            "pid":              4321,               # placeholder
            "processName":      "curl",             # placeholder
            "uid":              1000,               # placeholder
            "cgroupID":         "docker-abc123",    # placeholder
            "containerID":      "container_78fa12", # placeholder
            "networkNamespace": 4026531993          # placeholder
        },
        "payload": {
            "payloadLength": 8,                          # placeholder
            "hexDump":       "48 54 54 50 2F 31 2E 31"   # placeholder
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
    sid      = request.sid

    emit("status", {"message": f"Starting capture → {dest_ip}:{dst_port}"})

    thread = threading.Thread(
        target=_run_capture,
        args=(dest_ip, dst_port, sid),
        daemon=True
    )
    thread.start()


def _run_capture(dest_ip: str, dst_port: int, sid: str):
    raw         = {}
    found_event = threading.Event()

    try:
        proc = subprocess.Popen(
            ["sudo", "python3", "-u", EBPF_SCRIPT,
             "--dest-ip", dest_ip,
             "--dst-port", str(dst_port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as e:
        socketio.emit("error", {"message": f"Failed to start ebpf.py: {e}"})
        return

    def _reader():
        in_incoming_block = False
        block_lines       = []

        print("[DEBUG] reader thread started, waiting for ebpf.py output...")
        for line in proc.stdout:
            print(f"[DEBUG] ebpf stdout: {line.rstrip()}")
            if "← INCOMING" in line:
                in_incoming_block = True
                block_lines       = []
                continue
            if "Captured packet" in line:
                in_incoming_block = False
                block_lines       = []
                continue
            if in_incoming_block:
                block_lines.append(line)
                if "MF:" in line:   # last field — block complete
                    parsed = _parse_packet_lines(block_lines)
                    print(f"[DEBUG] parsed block: {parsed}")
                    raw.update(parsed)
                    found_event.set()
                    return

    def _stderr_reader():
        for line in proc.stderr:
            line = line.strip()
            if line:
                print(f"[ebpf.py stderr]: {line}")
                socketio.emit("status", {"message": f"[ebpf] {line}"}, room=sid)

    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()
    stderr_reader = threading.Thread(target=_stderr_reader, daemon=True)
    stderr_reader.start()

    got_it = found_event.wait(timeout=15)

    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        proc.kill()

    if got_it:
        packet = _build_packet(dest_ip, raw)
        socketio.emit("packet_data", packet, room=sid)
        socketio.emit("status", {"message": "Capture complete"}, room=sid)
        socketio.sleep(0)
    else:
        socketio.emit("error", {"message": "Timed out — no reply received"}, room=sid)
        socketio.sleep(0)


# ── HTTP routes ────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return "eBPF launcher running. Connect via SocketIO."


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting eBPF launcher on http://localhost:4242")
    print("Run with: sudo python3 launcher.py")
    socketio.run(app, host="0.0.0.0", port=4242, debug=False)
