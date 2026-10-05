#!/usr/bin/env bash
# =============================================================================
# traffic_capture/zeek_runner.sh
#
# Start one Zeek process per selected interface. Each interface gets its own
# log directory when capturing on multiple interfaces.
#
# Usage:
#   sudo bash traffic_capture/zeek_runner.sh [INTERFACE ...]
#
# Arguments:
#   INTERFACE   One or more network interfaces (default: eth0)
#
# Requirements:
#   - Zeek >= 4.0 installed (apt install zeek / brew install zeek)
#   - Run as root (or with CAP_NET_RAW)
#   - config/zeek_config.zeek present
#
# Environment variables:
#   ZEEK_INTERFACES  Space-separated interfaces (e.g. "eth0 wlan0")
#   ZEEK_INTERFACE   Legacy single-interface override
#   ZEEK_CONFIG      Path to zeek_config.zeek (default: config/zeek_config.zeek)
#   ZEEK_LOG_DIR     Directory for log output (default: logs/zeek/current)
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
    read -r -a INTERFACES <<< "${ZEEK_INTERFACES:-${ZEEK_INTERFACE:-eth0}}"
fi
CONFIG="${ZEEK_CONFIG:-$PROJECT_ROOT/config/zeek_config.zeek}"
BASE_LOG_DIR="${ZEEK_LOG_DIR:-$PROJECT_ROOT/logs/zeek/current}"

if ((${#INTERFACES[@]} == 0)); then
    echo "ERROR: at least one network interface must be specified." >&2
    exit 1
fi

echo "[zeek_runner.sh] Interfaces: ${INTERFACES[*]}"
echo "[zeek_runner.sh] Config     : $CONFIG"
echo "[zeek_runner.sh] Base log dir: $BASE_LOG_DIR"

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
    mkdir -p "$run_dir"
    RUN_DIRS+=("$run_dir")
done

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
    echo "[zeek_runner.sh] Starting Zeek on $interface; conn.log: $log_dir/conn.log"
    (
        cd "$log_dir"
        exec "$ZEEK_BIN" \
            -i "$interface" \
            "$CONFIG" \
            LogAscii::output_to_stdout=F \
            Log::default_rotation_interval=1hr
    ) &
    PIDS+=("$!")
done
echo "[zeek_runner.sh] Capturing all interfaces. Press Ctrl+C to stop."
wait -n "${PIDS[@]}"
