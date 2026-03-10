#!/bin/bash
# start.sh — run this once in your WSL terminal to start the eBPF launcher
# Usage: bash start.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  eBPF Launcher — Startup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Check WSL ────────────────────────────────────────────────────────────────
if ! grep -qi microsoft /proc/version 2>/dev/null; then
    echo "  [WARN] Not running inside WSL — proceed with caution."
fi

# ── Check root ───────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "  [INFO] Re-launching with sudo..."
    echo ""
    exec sudo bash "$0" "$@"
fi

# ── Install missing dependencies ──────────────────────────────────────────────
echo "  [INFO] Checking dependencies..."

NEED_APT=()
python3 -c "import bcc" 2>/dev/null           || NEED_APT+=("python3-bpfcc")
python3 -c "import flask" 2>/dev/null          || NEED_APT+=("python3-flask")
python3 -c "import flask_socketio" 2>/dev/null || NEED_APT+=("python3-flask-socketio")
python3 -c "import eventlet" 2>/dev/null       || NEED_APT+=("python3-eventlet")

if ! command -v iptables &>/dev/null; then
    NEED_APT+=("iptables")
fi

# Skip kernel headers on WSL2 — not needed, BPF is built into the WSL2 kernel
if ! grep -qi microsoft /proc/version 2>/dev/null; then
    KERNEL=$(uname -r)
    if [ ! -d "/lib/modules/$KERNEL/build" ]; then
        NEED_APT+=("linux-headers-generic")
    fi
fi

if [ ${#NEED_APT[@]} -gt 0 ]; then
    echo "  [INFO] Installing apt packages: ${NEED_APT[*]}"
    apt-get install -y "${NEED_APT[@]}" -qq
fi

echo "  [INFO] Dependencies OK"
echo ""

# ── Run preflight ────────────────────────────────────────────────────────────
echo "  [INFO] Running preflight checks..."
echo ""
if ! python3 "$SCRIPT_DIR/preflight.py"; then
    echo ""
    echo "  [FAIL] Preflight checks failed. Fix the issues above and re-run."
    exit 1
fi

# ── Start launcher ───────────────────────────────────────────────────────────
echo ""
echo "  [INFO] All checks passed. Starting launcher on http://localhost:4242"
echo "  [INFO] Press Ctrl+C to stop."
echo ""
python3 "$SCRIPT_DIR/launcher.py"
