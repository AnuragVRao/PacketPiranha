#!/usr/bin/env python3
"""
preflight.py — Run this before launcher.py to verify your WSL2 environment
is correctly set up for eBPF packet capture.

Usage: sudo python3 preflight.py
"""

import os
import sys
import shutil
import struct
import subprocess

REQUIRED_KERNEL = (5, 15)
REQUIRED_PYTHON  = (3, 10)

PASS  = "\033[92m[PASS]\033[0m"
FAIL  = "\033[91m[FAIL]\033[0m"
WARN  = "\033[93m[WARN]\033[0m"
INFO  = "\033[94m[INFO]\033[0m"

all_passed = True

def check(label: str, ok: bool, fix: str = "", warn_only: bool = False):
    global all_passed
    if ok:
        print(f"  {PASS} {label}")
    elif warn_only:
        print(f"  {WARN} {label}")
        if fix:
            print(f"         → {fix}")
    else:
        all_passed = False
        print(f"  {FAIL} {label}")
        if fix:
            print(f"         → {fix}")

def run(cmd: str) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as e:
        return 1, str(e)


print()
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("  eBPF Launcher — Preflight Check")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print()

# ── 1. Running on Linux ────────────────────────────────────────────────────────
print("[ System ]")
check(
    "Running on Linux",
    sys.platform == "linux",
    fix="This program must run inside WSL2, not on Windows directly."
)

# ── 2. Running inside WSL ─────────────────────────────────────────────────────
_, proc_version = run("cat /proc/version")
is_wsl = "microsoft" in proc_version.lower() or "wsl" in proc_version.lower()
check(
    "Running inside WSL2",
    is_wsl,
    fix="Run this script from a WSL2 terminal, not a native Linux VM.",
    warn_only=not is_wsl  # warn only — might work on native Linux too
)

# ── 3. Root privileges ────────────────────────────────────────────────────────
check(
    "Running as root",
    os.geteuid() == 0,
    fix="Re-run with sudo:  sudo python3 preflight.py"
)

# ── 4. Python version ─────────────────────────────────────────────────────────
pv = sys.version_info[:2]
check(
    f"Python version {pv[0]}.{pv[1]} (need {REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]}+)",
    pv >= REQUIRED_PYTHON,
    fix=f"Upgrade Python:  sudo apt install python3.{REQUIRED_PYTHON[1]}"
)

# ── 5. Kernel version ─────────────────────────────────────────────────────────
print()
print("[ Kernel & eBPF ]")
raw_release = os.uname().release
parts = raw_release.split(".")
try:
    kv = (int(parts[0]), int(parts[1]))
except Exception:
    kv = (0, 0)

check(
    f"Kernel {raw_release} (need {REQUIRED_KERNEL[0]}.{REQUIRED_KERNEL[1]}+)",
    kv >= REQUIRED_KERNEL,
    fix=(
        "Your WSL2 kernel is too old for eBPF.\n"
        "         Install a newer kernel:\n"
        "           1. In PowerShell (admin): wsl --update\n"
        "           2. Or build a custom kernel with CONFIG_BPF=y\n"
        "              See: https://github.com/microsoft/WSL2-Linux-Kernel"
    )
)

# ── 6. BPF filesystem ────────────────────────────────────────────────────────
bpf_mounted = os.path.exists("/sys/fs/bpf")
check(
    "/sys/fs/bpf is available",
    bpf_mounted,
    fix=(
        "BPF filesystem not mounted. Try:\n"
        "         sudo mount -t bpf bpf /sys/fs/bpf\n"
        "         Or add to /etc/fstab:\n"
        "           bpf  /sys/fs/bpf  bpf  defaults  0  0"
    )
)

# ── 7. BPF syscall ────────────────────────────────────────────────────────────
_, bpf_out = run("bpftool version 2>/dev/null || echo 'missing'")
has_bpftool = "missing" not in bpf_out
check(
    "bpftool available (optional but useful)",
    has_bpftool,
    fix="sudo apt install linux-tools-common linux-tools-$(uname -r)",
    warn_only=True
)

# ── 8. Kernel headers ────────────────────────────────────────────────────────
headers_path = f"/lib/modules/{raw_release}/build"
has_headers  = os.path.exists(headers_path)
# WSL2 has BPF built into its kernel — headers aren't needed
if is_wsl:
    check("Kernel headers (skipped — WSL2 has BPF built in)", True)
else:
    check(
        f"Kernel headers at {headers_path}",
        has_headers,
        fix="sudo apt install linux-headers-$(uname -r)\n         If unavailable: sudo apt install linux-headers-generic"
    )

# ── 9. BCC Python bindings ───────────────────────────────────────────────────
print()
print("[ Python Packages ]")
try:
    import bcc
    check("bcc (BPF Compiler Collection) installed", True)
except ImportError:
    check(
        "bcc (BPF Compiler Collection) installed",
        False,
        fix="sudo apt install python3-bpfcc"
    )

# ── 10. Flask ────────────────────────────────────────────────────────────────
try:
    import flask
    check(f"flask {flask.__version__} installed", True)
except ImportError:
    check("flask installed", False, fix="pip3 install flask")

# ── 11. Flask-SocketIO ───────────────────────────────────────────────────────
try:
    import flask_socketio
    check(f"flask-socketio installed", True)
except ImportError:
    check("flask-socketio installed", False, fix="pip3 install flask-socketio")

# ── 12. eventlet ─────────────────────────────────────────────────────────────
try:
    import eventlet
    check("eventlet installed", True)
except ImportError:
    check("eventlet installed", False, fix="pip3 install eventlet")

# ── 13. scapy (optional, used in older versions) ─────────────────────────────
try:
    import scapy
    check("scapy installed (optional)", True)
except ImportError:
    check("scapy installed (optional)", False,
          fix="pip3 install scapy", warn_only=True)

# ── 14. Network interface ────────────────────────────────────────────────────
print()
print("[ Network ]")
rc, route_out = run("ip route | grep default")
has_default_route = rc == 0 and "dev" in route_out
check(
    "Default network route exists",
    has_default_route,
    fix="No default route found. Check WSL2 network: try restarting WSL."
)

if has_default_route:
    parts = route_out.split()
    if "dev" in parts:
        iface = parts[parts.index("dev") + 1]
        print(f"  {INFO} Default interface: {iface}")

        rc2, addr_out = run(f"ip addr show {iface} | grep 'inet '")
        if rc2 == 0:
            ip = addr_out.strip().split()[1].split("/")[0]
            print(f"  {INFO} Interface IP:     {ip}")

# ── 15. Raw socket capability ────────────────────────────────────────────────
try:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.close()
    check("Raw socket creation (CAP_NET_RAW)", True)
except PermissionError:
    check(
        "Raw socket creation (CAP_NET_RAW)",
        False,
        fix="Run as root: sudo python3 preflight.py"
    )

# ── 16. iptables available ───────────────────────────────────────────────────
has_iptables = shutil.which("iptables") is not None
check(
    "iptables available (for RST suppression)",
    has_iptables,
    fix="sudo apt install iptables"
)

# ── 17. Port 4242 free ───────────────────────────────────────────────────────
print()
print("[ Ports ]")
try:
    import socket as _s
    test = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
    test.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
    test.bind(("0.0.0.0", 4242))
    test.close()
    check("Port 4242 is free (launcher)", True)
except OSError:
    check(
        "Port 4242 is free (launcher)",
        False,
        fix="Something is already running on port 4242. Kill it or change the port in launcher.py."
    )

# ── Summary ───────────────────────────────────────────────────────────────────
print()
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
if all_passed:
    print("  \033[92mAll checks passed — ready to run launcher.py\033[0m")
    print("  → sudo python3 launcher.py")
else:
    print("  \033[91mSome checks failed — fix the issues above before running.\033[0m")
    print("  Quick install of all Python deps:")
    print("    sudo apt install python3-bpfcc linux-headers-$(uname -r) iptables")
    print("    pip3 install flask flask-socketio eventlet scapy")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print()

sys.exit(0 if all_passed else 1)
