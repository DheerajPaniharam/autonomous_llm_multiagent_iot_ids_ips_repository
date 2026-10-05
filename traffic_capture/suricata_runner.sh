#!/usr/bin/env bash
# =============================================================================
# traffic_capture/suricata_runner.sh
#
# Start Suricata in IDS mode on one or more network interfaces. Each interface
# gets a separate log directory when capturing on multiple interfaces.
#
# Usage:
#   sudo bash traffic_capture/suricata_runner.sh [INTERFACE ...]
#
# Arguments:
#   INTERFACE   One or more network interfaces (default: eth0)
#
# Requirements:
#   - Suricata >= 6.0 installed (apt install suricata / yum install suricata)
#   - Run as root (or with CAP_NET_RAW + CAP_NET_ADMIN)
#   - config/suricata.yaml present
#
# Environment variables:
#   SURICATA_INTERFACES  Space-separated interfaces (e.g. "eth0 wlan0")
#   SURICATA_INTERFACE   Legacy single-interface override
#   SURICATA_CONFIG      Path to suricata.yaml (default: config/suricata.yaml)
#   SURICATA_LOG_DIR     Directory for eve.json output (default: logs/suricata)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
if (($#)); then
    INTERFACES=("$@")
else
    read -r -a INTERFACES <<< "${SURICATA_INTERFACES:-${SURICATA_INTERFACE:-eth0}}"
fi
CONFIG="${SURICATA_CONFIG:-$PROJECT_ROOT/config/suricata.yaml}"
BASE_LOG_DIR="${SURICATA_LOG_DIR:-$PROJECT_ROOT/logs/suricata}"

if ((${#INTERFACES[@]} == 0)); then
    echo "ERROR: at least one network interface must be specified." >&2
    exit 1
fi

echo "[suricata_runner.sh] Interfaces: ${INTERFACES[*]}"
echo "[suricata_runner.sh] Config     : $CONFIG"
echo "[suricata_runner.sh] Base log dir: $BASE_LOG_DIR"

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

RUN_DIRS=()
for interface in "${INTERFACES[@]}"; do
    if ! ip link show "$interface" &>/dev/null; then
        echo "ERROR: Network interface '$interface' not found." >&2
        echo "Available interfaces:"
        ip link show | grep -oP '^\d+: \K[^:@]+'
        exit 1
    fi
    run_dir="$BASE_LOG_DIR"
    if ((${#INTERFACES[@]} > 1)); then
        run_dir="$BASE_LOG_DIR/$interface"
    fi
    RUN_DIRS+=("$run_dir")
    mkdir -p "$run_dir"

    pid_file="${SURICATA_PIDFILE:-$run_dir/suricata.pid}"
    if ((${#INTERFACES[@]} > 1)) && [[ -n "${SURICATA_PIDFILE:-}" ]]; then
        pid_file="${SURICATA_PIDFILE}.${interface}"
    fi
    mkdir -p "$(dirname "$pid_file")"
    if [[ -f "$pid_file" ]]; then
        existing_pid="$(cat "$pid_file" 2>/dev/null || true)"
        if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
            echo "ERROR: Suricata is already running with PID $existing_pid (pidfile: $pid_file)." >&2
            exit 1
        fi
        rm -f "$pid_file"
    fi
done

# ---------------------------------------------------------------------------
# Update Suricata rules (optional — skip if offline)
# ---------------------------------------------------------------------------
echo "[suricata_runner.sh] Updating Suricata rules..."
suricata-update --no-reload 2>/dev/null || echo "[suricata_runner.sh] Rule update skipped (offline or not installed)."

# ---------------------------------------------------------------------------
# Start Suricata
# ---------------------------------------------------------------------------
PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for index in "${!INTERFACES[@]}"; do
    interface="${INTERFACES[$index]}"
    log_dir="${RUN_DIRS[$index]}"
    pid_file="${SURICATA_PIDFILE:-$log_dir/suricata.pid}"
    if ((${#INTERFACES[@]} > 1)) && [[ -n "${SURICATA_PIDFILE:-}" ]]; then
        pid_file="${SURICATA_PIDFILE}.${interface}"
    fi
    echo "[suricata_runner.sh] Starting Suricata on $interface; eve.json: $log_dir/eve.json"
    suricata \
        -c "$CONFIG" \
        -i "$interface" \
        --pidfile "$pid_file" \
        -l "$log_dir" \
        -v &
    PIDS+=("$!")
done
echo "[suricata_runner.sh] Capturing all interfaces. Press Ctrl+C to stop."
wait -n "${PIDS[@]}"
