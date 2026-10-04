#!/usr/bin/env bash
# =============================================================================
# traffic_capture/zeek_runner.sh
#
# Start Zeek (formerly Bro) in live capture mode on the specified interface.
# Zeek writes conn.log, dns.log, http.log, etc. to /var/log/zeek/current/,
# which the TrafficAgent tails in real time.
#
# Usage:
#   sudo bash traffic_capture/zeek_runner.sh [INTERFACE]
#
# Arguments:
#   INTERFACE   Network interface to monitor (default: eth0)
#
# Requirements:
#   - Zeek >= 4.0 installed (apt install zeek / brew install zeek)
#   - Run as root (or with CAP_NET_RAW)
#   - config/zeek_config.zeek present
#
# Environment variables:
#   ZEEK_INTERFACE   Override the network interface
#   ZEEK_CONFIG      Path to zeek_config.zeek (default: config/zeek_config.zeek)
#   ZEEK_LOG_DIR     Directory for log output (default: logs/zeek/current)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INTERFACE="${1:-${ZEEK_INTERFACE:-eth0}}"
CONFIG="${ZEEK_CONFIG:-$PROJECT_ROOT/config/zeek_config.zeek}"
LOG_DIR="${ZEEK_LOG_DIR:-$PROJECT_ROOT/logs/zeek/current}"

echo "[zeek_runner.sh] Interface : $INTERFACE"
echo "[zeek_runner.sh] Config    : $CONFIG"
echo "[zeek_runner.sh] Log dir   : $LOG_DIR"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if ! command -v zeek &>/dev/null && ! command -v bro &>/dev/null; then
    echo "ERROR: zeek (or bro) not found. Install it first:"
    echo "  Ubuntu/Debian: sudo apt install zeek"
    echo "  macOS:         brew install zeek"
    echo "  Or see: https://docs.zeek.org/en/master/install.html"
    exit 1
fi

ZEEK_BIN="zeek"
command -v zeek &>/dev/null || ZEEK_BIN="bro"

if [[ ! -f "$CONFIG" ]]; then
    echo "ERROR: Zeek config not found at $CONFIG"
    exit 1
fi

if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "ERROR: Network interface '$INTERFACE' not found."
    echo "Available interfaces:"
    ip link show | grep -oP '^\d+: \K[^:@]+'
    exit 1
fi

# Create log directory
mkdir -p "$LOG_DIR"

# ---------------------------------------------------------------------------
# Start Zeek
# ---------------------------------------------------------------------------
echo "[zeek_runner.sh] Starting Zeek on $INTERFACE..."
echo "[zeek_runner.sh] conn.log will be written to $LOG_DIR/conn.log"
echo "[zeek_runner.sh] Press Ctrl+C to stop."

cd "$LOG_DIR"

exec "$ZEEK_BIN" \
    -i "$INTERFACE" \
    "$CONFIG" \
    LogAscii::output_to_stdout=F \
    Log::default_rotation_interval=1hr
