#!/usr/bin/env bash
# =============================================================================
# scripts/stop_gateway.sh
#
# Gracefully stop the IoT IDS/IPS gateway.
#
# Modes:
#   --docker    Stop via docker compose (default)
#   --local     Send SIGTERM to a running uvicorn process
#   --force     Force-kill immediately (no graceful drain)
#
# Usage:
#   bash scripts/stop_gateway.sh              # docker mode
#   bash scripts/stop_gateway.sh --local      # local dev mode
#   bash scripts/stop_gateway.sh --force      # force kill
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="docker"
FORCE=false

for arg in "$@"; do
    case "$arg" in
        --local) MODE="local" ;;
        --force) FORCE=true ;;
        --docker) MODE="docker" ;;
    esac
done

cd "$PROJECT_ROOT"

# ---------------------------------------------------------------------------
# Docker mode
# ---------------------------------------------------------------------------
if [[ "$MODE" == "docker" ]]; then
    echo "[stop_gateway.sh] Stopping all services via docker compose..."

    if $FORCE; then
        docker compose kill
        docker compose rm -f
    else
        # docker compose stop sends SIGTERM, which triggers FastAPI's lifespan
        # shutdown and queue draining before the container exits.
        docker compose stop --timeout 60
    fi

    echo "[stop_gateway.sh] All services stopped."
    exit 0
fi

# ---------------------------------------------------------------------------
# Local mode — find and stop the uvicorn process
# ---------------------------------------------------------------------------
if [[ "$MODE" == "local" ]]; then
    echo "[stop_gateway.sh] Looking for running uvicorn process..."

    PIDS=$(pgrep -f "uvicorn backend.main:app" 2>/dev/null || true)

    if [[ -z "$PIDS" ]]; then
        echo "[stop_gateway.sh] No running uvicorn process found."
        exit 0
    fi

    echo "[stop_gateway.sh] Found PIDs: $PIDS"

    if $FORCE; then
        echo "[stop_gateway.sh] Force-killing..."
        kill -9 $PIDS
    else
        echo "[stop_gateway.sh] Sending SIGTERM (graceful shutdown with queue drain)..."
        kill -TERM $PIDS

        # Wait up to 90 seconds for the process to exit
        for i in $(seq 1 45); do
            if ! kill -0 $PIDS 2>/dev/null; then
                echo "[stop_gateway.sh] Process exited cleanly."
                exit 0
            fi
            sleep 2
        done

        echo "WARNING: Process did not exit within 90s. Force-killing..."
        kill -9 $PIDS 2>/dev/null || true
    fi

    echo "[stop_gateway.sh] Done."
    exit 0
fi
