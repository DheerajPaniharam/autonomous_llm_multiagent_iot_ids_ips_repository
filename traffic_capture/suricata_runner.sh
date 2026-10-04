#!/usr/bin/env bash
# =============================================================================
# traffic_capture/suricata_runner.sh
#
# Start Suricata in IDS mode on the specified network interface.
# Suricata writes alerts and flow records to /var/log/suricata/eve.json,
# which the TrafficAgent tails in real time.
#
# Usage:
#   sudo bash traffic_capture/suricata_runner.sh [INTERFACE]
#
# Arguments:
#   INTERFACE   Network interface to monitor (default: eth0)
#
# Requirements:
#   - Suricata >= 6.0 installed (apt install suricata / yum install suricata)
#   - Run as root (or with CAP_NET_RAW + CAP_NET_ADMIN)
#   - config/suricata.yaml present
#
# Environment variables:
#   SURICATA_INTERFACE   Override the network interface
#   SURICATA_CONFIG      Path to suricata.yaml (default: config/suricata.yaml)
#   SURICATA_LOG_DIR     Directory for eve.json output (default: logs/suricata)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INTERFACE="${1:-${SURICATA_INTERFACE:-eth0}}"
CONFIG="${SURICATA_CONFIG:-$PROJECT_ROOT/config/suricata.yaml}"
LOG_DIR="${SURICATA_LOG_DIR:-$PROJECT_ROOT/logs/suricata}"

echo "[suricata_runner.sh] Interface : $INTERFACE"
echo "[suricata_runner.sh] Config    : $CONFIG"
echo "[suricata_runner.sh] Log dir   : $LOG_DIR"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if ! command -v suricata &>/dev/null; then
    echo "ERROR: suricata not found. Install it first:"
    echo "  Ubuntu/Debian: sudo apt install suricata"
    echo "  RHEL/CentOS:   sudo yum install suricata"
    exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
    echo "ERROR: Suricata config not found at $CONFIG"
    exit 1
fi

if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "ERROR: Network interface '$INTERFACE' not found."
    echo "Available interfaces:"
    ip link show | grep -oP '^\d+: \K[^:@]+'
    exit 1
fi

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"
PID_FILE="${SURICATA_PIDFILE:-$LOG_DIR/suricata.pid}"
mkdir -p "$(dirname "$PID_FILE")"

if [[ -f "$PID_FILE" ]]; then
    EXISTING_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ -n "$EXISTING_PID" ]] && kill -0 "$EXISTING_PID" 2>/dev/null; then
        echo "[suricata_runner.sh] Existing Suricata process detected at PID $EXISTING_PID. Removing stale pidfile."
    fi
    rm -f "$PID_FILE"
fi

# ---------------------------------------------------------------------------
# Update Suricata rules (optional — skip if offline)
# ---------------------------------------------------------------------------
echo "[suricata_runner.sh] Updating Suricata rules..."
suricata-update --no-reload 2>/dev/null || echo "[suricata_runner.sh] Rule update skipped (offline or not installed)."

# ---------------------------------------------------------------------------
# Start Suricata
# ---------------------------------------------------------------------------
echo "[suricata_runner.sh] Starting Suricata on $INTERFACE..."
echo "[suricata_runner.sh] eve.json will be written to $LOG_DIR/eve.json"
echo "[suricata_runner.sh] Press Ctrl+C to stop."

exec suricata \
    -c "$CONFIG" \
    -i "$INTERFACE" \
    --pidfile "$PID_FILE" \
    -l "$LOG_DIR" \
    -v
