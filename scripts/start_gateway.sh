#!/usr/bin/env bash
# =============================================================================
# scripts/start_gateway.sh
#
# Start the IoT IDS/IPS gateway (FastAPI backend + all 9 agents).
#
# Modes:
#   --docker    Start via docker compose (default for production)
#   --local     Start directly with uvicorn (for development)
#   --help      Show this help message
#
# Usage:
#   bash scripts/start_gateway.sh              # docker mode
#   bash scripts/start_gateway.sh --local      # local dev mode
#   bash scripts/start_gateway.sh --docker     # explicit docker mode
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="docker"
if [[ "${1:-}" == "--local" ]]; then
    MODE="local"
elif [[ "${1:-}" == "--help" ]]; then
    sed -n '2,20p' "$0"
    exit 0
fi

cd "$PROJECT_ROOT"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
echo "[start_gateway.sh] Pre-flight checks..."

if [[ ! -f ".env" ]]; then
    echo "ERROR: .env file not found. Copy .env.example and configure it first:"
    echo "  cp .env.example .env"
    exit 1
fi

# Check JWT_SECRET_KEY is set
if ! grep -q "^JWT_SECRET_KEY=.\+" .env 2>/dev/null; then
    echo "ERROR: JWT_SECRET_KEY is not set in .env"
    echo "  Generate one with: openssl rand -hex 32"
    exit 1
fi

# ---------------------------------------------------------------------------
# Docker mode
# ---------------------------------------------------------------------------
if [[ "$MODE" == "docker" ]]; then
    echo "[start_gateway.sh] Starting all services via docker compose..."

    if ! command -v docker &>/dev/null; then
        echo "ERROR: docker not found. Install Docker first."
        exit 1
    fi

    docker compose up -d

    echo "[start_gateway.sh] Waiting for API to become healthy..."
    for i in $(seq 1 30); do
        if curl -sf http://localhost:8000/health/live &>/dev/null; then
            echo "[start_gateway.sh] Gateway is up and healthy."
            echo ""
            echo "  Dashboard:  http://localhost:5173"
            echo "  API docs:   http://localhost:8000/docs"
            echo "  Kibana:     http://localhost:5601"
            echo "  Metrics:    http://localhost:8000/metrics"
            exit 0
        fi
        sleep 2
    done

    echo "WARNING: Gateway did not become healthy within 60s. Check logs:"
    echo "  docker compose logs -f api"
    exit 1
fi

# ---------------------------------------------------------------------------
# Local development mode
# ---------------------------------------------------------------------------
if [[ "$MODE" == "local" ]]; then
    echo "[start_gateway.sh] Starting in local development mode..."

    # Check Python
    if ! command -v python3 &>/dev/null; then
        echo "ERROR: python3 not found."
        exit 1
    fi

    # Check virtual environment
    if [[ -d ".venv" ]]; then
        source .venv/bin/activate
    elif [[ -d "venv" ]]; then
        source venv/bin/activate
    else
        echo "WARNING: No virtual environment found. Using system Python."
    fi

    # Apply baseline firewall rules (requires root; skip if not root)
    if [[ $EUID -eq 0 ]]; then
        echo "[start_gateway.sh] Applying baseline firewall rules..."
        bash config/firewall_rules.sh || true
    else
        echo "[start_gateway.sh] Not root — skipping firewall setup (simulation mode)."
        export FIREWALL_MODE=simulation
    fi

    echo "[start_gateway.sh] Starting uvicorn..."
    exec uvicorn backend.main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --reload \
        --log-level info
fi
