#!/usr/bin/env bash
# =============================================================================
# validate_compose.sh — Docker Compose Deployment Validation
# =============================================================================
# Validates the Docker Compose deployment for the IoT IDS/IPS system.
# Covers requirements 6.2, 6.3, 6.11.
#
# Usage:
#   ./scripts/validate_compose.sh              # full validation (requires Docker)
#   ./scripts/validate_compose.sh --syntax-only # YAML/Dockerfile syntax only
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yml"
DOCKERFILE="$PROJECT_ROOT/Dockerfile"

SYNTAX_ONLY=false
if [[ "${1:-}" == "--syntax-only" ]]; then
  SYNTAX_ONLY=true
fi

PASS=0
FAIL=0

ok()   { echo "[PASS] $*"; ((PASS++)) || true; }
fail() { echo "[FAIL] $*"; ((FAIL++)) || true; }
info() { echo "[INFO] $*"; }
section() { echo; echo "--- $* ---"; }

# =============================================================================
# 1. File existence checks
# =============================================================================
section "File Existence"

[[ -f "$COMPOSE_FILE" ]] && ok "docker-compose.yml exists" || fail "docker-compose.yml not found at $COMPOSE_FILE"
[[ -f "$DOCKERFILE" ]]   && ok "Dockerfile exists"         || fail "Dockerfile not found at $DOCKERFILE"
[[ -f "$PROJECT_ROOT/.env.example" ]] && ok ".env.example exists" || fail ".env.example not found"

# =============================================================================
# 2. YAML syntax validation
# =============================================================================
section "YAML Syntax"

if command -v python3 &>/dev/null || command -v python &>/dev/null; then
  PY=$(command -v python3 2>/dev/null || command -v python)
  if $PY -c "import yaml; yaml.safe_load(open('$COMPOSE_FILE'))" 2>/dev/null; then
    ok "docker-compose.yml is valid YAML"
  else
    fail "docker-compose.yml has YAML syntax errors"
  fi
elif command -v docker &>/dev/null; then
  if docker compose -f "$COMPOSE_FILE" config --quiet 2>/dev/null; then
    ok "docker-compose.yml passes docker compose config"
  else
    fail "docker-compose.yml fails docker compose config"
  fi
else
  info "Neither python nor docker available — skipping YAML syntax check"
fi

# =============================================================================
# 3. Dockerfile syntax checks (grep-based)
# =============================================================================
section "Dockerfile Syntax"

grep -q "^FROM python:3.11" "$DOCKERFILE"   && ok "Dockerfile: FROM python:3.11" || fail "Dockerfile: missing FROM python:3.11"
grep -q "^WORKDIR /app"     "$DOCKERFILE"   && ok "Dockerfile: WORKDIR /app"     || fail "Dockerfile: missing WORKDIR /app"
grep -q "^EXPOSE 8000"      "$DOCKERFILE"   && ok "Dockerfile: EXPOSE 8000"      || fail "Dockerfile: missing EXPOSE 8000"
grep -q "uvicorn"           "$DOCKERFILE"   && ok "Dockerfile: CMD uses uvicorn"  || fail "Dockerfile: CMD does not use uvicorn"
grep -q "backend.main:app"  "$DOCKERFILE"   && ok "Dockerfile: CMD targets backend.main:app" || fail "Dockerfile: CMD does not target backend.main:app"
grep -q "requirements.txt"  "$DOCKERFILE"   && ok "Dockerfile: requirements.txt referenced" || fail "Dockerfile: requirements.txt not referenced"
grep -q "curl"              "$DOCKERFILE"   && ok "Dockerfile: curl installed"    || fail "Dockerfile: curl not installed (needed for health check)"

# =============================================================================
# 4. docker-compose.yml structural checks (grep-based)
# =============================================================================
section "docker-compose.yml Structure"

# Required services
for svc in db loki promtail grafana api ollama; do
  grep -q "^  $svc:" "$COMPOSE_FILE" && ok "Service '$svc' defined" || fail "Service '$svc' missing"
done

# Named volumes
for vol in postgres_data loki_data ollama_data; do
  grep -q "$vol:" "$COMPOSE_FILE" && ok "Volume '$vol' defined" || fail "Volume '$vol' missing"
done

# Health checks
grep -q "pg_isready" "$COMPOSE_FILE"        && ok "db health check uses pg_isready"          || fail "db health check missing pg_isready"
grep -q "3100" "$COMPOSE_FILE"   && ok "loki health check present" || fail "loki health check missing"
grep -q "/health/live" "$COMPOSE_FILE"      && ok "api health check uses /health/live"        || fail "api health check missing /health/live"

# Dependency ordering (Req 6.2, 6.3)
grep -q "service_healthy" "$COMPOSE_FILE"   && ok "service_healthy conditions present (Req 6.2, 6.3)" || fail "service_healthy conditions missing"

# Backend environment variables (Req 6.4, 6.5)
grep -q "DATABASE_URL.*db:5432"             "$COMPOSE_FILE" && ok "DATABASE_URL references db service (Req 6.4)"             || fail "DATABASE_URL does not reference db service"
grep -q "LOKI_URL.*loki"  "$COMPOSE_FILE" && ok "LOKI_URL references loki service" || fail "LOKI_URL does not reference loki service"
grep -q "OLLAMA_HOST.*ollama"               "$COMPOSE_FILE" && ok "OLLAMA_HOST references ollama service"                    || fail "OLLAMA_HOST does not reference ollama service"

# Volume mounts (Req 6.6, 6.7)
grep -q "./models:/app/models:ro"  "$COMPOSE_FILE" && ok "models/ mounted read-only (Req 6.6)"  || fail "models/ not mounted read-only"
grep -q "./config:/app/config:ro"  "$COMPOSE_FILE" && ok "config/ mounted read-only (Req 6.7)"  || fail "config/ not mounted read-only"

# Restart policies (Req 6.12)
RESTART_COUNT=$(grep -c "restart: unless-stopped" "$COMPOSE_FILE" || true)
[[ "$RESTART_COUNT" -ge 5 ]] && ok "restart: unless-stopped on ≥5 services (Req 6.12)" || fail "restart: unless-stopped missing on some services (found $RESTART_COUNT)"

# Ollama port (Req 6.10)
grep -q "11434:11434" "$COMPOSE_FILE" && ok "ollama exposes port 11434 (Req 6.10)" || fail "ollama port 11434 not exposed"

if $SYNTAX_ONLY; then
  echo
  echo "=== Syntax-only mode: skipping live Docker checks ==="
  echo
  echo "Results: $PASS passed, $FAIL failed"
  [[ $FAIL -eq 0 ]] && exit 0 || exit 1
fi

# =============================================================================
# 5. Live Docker checks (requires Docker daemon)
# =============================================================================
section "Live Docker Checks"

if ! command -v docker &>/dev/null; then
  info "Docker not found — skipping live checks"
  info "Install Docker Desktop and re-run without --syntax-only to perform live checks"
  echo
  echo "Results: $PASS passed, $FAIL failed (live checks skipped)"
  [[ $FAIL -eq 0 ]] && exit 0 || exit 1
fi

if ! docker info &>/dev/null; then
  info "Docker daemon not running — skipping live checks"
  info "Start Docker Desktop and re-run to perform live checks"
  echo
  echo "Results: $PASS passed, $FAIL failed (live checks skipped)"
  [[ $FAIL -eq 0 ]] && exit 0 || exit 1
fi

ok "Docker daemon is running"

# Validate compose config
if docker compose -f "$COMPOSE_FILE" config --quiet 2>/dev/null; then
  ok "docker compose config validation passed"
else
  fail "docker compose config validation failed"
fi

# =============================================================================
# 6. Full deployment test (docker compose up)
# =============================================================================
section "Full Deployment Test"

info "Starting services with docker compose up -d ..."
cd "$PROJECT_ROOT"

# Start only infrastructure services first (postgres + monitoring stack)
docker compose -f "$COMPOSE_FILE" up -d db loki promtail grafana

info "Waiting for postgres to be healthy (up to 60s)..."
TIMEOUT=60
ELAPSED=0
while ! docker compose -f "$COMPOSE_FILE" exec -T db pg_isready -U ids -d idsdb &>/dev/null; do
  sleep 2
  ELAPSED=$((ELAPSED + 2))
  if [[ $ELAPSED -ge $TIMEOUT ]]; then
    fail "postgres did not become healthy within ${TIMEOUT}s (Req 6.2)"
    break
  fi
done
[[ $ELAPSED -lt $TIMEOUT ]] && ok "postgres healthy within ${ELAPSED}s (Req 6.2)"

info "Waiting for loki to be healthy (up to 120s)..."
TIMEOUT=120
ELAPSED=0
while ! docker compose -f "$COMPOSE_FILE" exec -T loki wget -qO- http://localhost:3100/ready &>/dev/null; do
  sleep 5
  ELAPSED=$((ELAPSED + 5))
  if [[ $ELAPSED -ge $TIMEOUT ]]; then
    fail "loki did not become healthy within ${TIMEOUT}s"
    break
  fi
done
[[ $ELAPSED -lt $TIMEOUT ]] && ok "loki healthy within ${ELAPSED}s"

# Start backend
info "Starting backend service..."
docker compose -f "$COMPOSE_FILE" up -d api

info "Waiting for backend health check to pass (up to 60s)..."
TIMEOUT=60
ELAPSED=0
while ! docker compose -f "$COMPOSE_FILE" exec -T api curl -sf http://localhost:8000/health/live &>/dev/null; do
  sleep 3
  ELAPSED=$((ELAPSED + 3))
  if [[ $ELAPSED -ge $TIMEOUT ]]; then
    fail "backend /health/live did not respond within ${TIMEOUT}s (Req 6.11)"
    break
  fi
done
[[ $ELAPSED -lt $TIMEOUT ]] && ok "backend /health/live responded within ${ELAPSED}s (Req 6.11)"

# Verify backend health endpoint
info "Checking backend /health endpoint..."
HEALTH_RESPONSE=$(docker compose -f "$COMPOSE_FILE" exec -T api curl -sf http://localhost:8000/health 2>/dev/null || echo "")
if echo "$HEALTH_RESPONSE" | grep -q '"status"'; then
  ok "backend /health returns JSON with status field"
  if echo "$HEALTH_RESPONSE" | grep -q '"database"'; then
    ok "backend /health includes database component status"
  else
    fail "backend /health missing database component status"
  fi
else
  fail "backend /health did not return expected JSON"
fi

# Verify postgres connection from backend
info "Checking postgres connection from backend..."
READY_RESPONSE=$(docker compose -f "$COMPOSE_FILE" exec -T api curl -sf http://localhost:8000/health/ready 2>/dev/null || echo "")
if echo "$READY_RESPONSE" | grep -qE '"status".*"(healthy|ready)"' || [[ $(docker compose -f "$COMPOSE_FILE" exec -T api curl -so /dev/null -w "%{http_code}" http://localhost:8000/health/ready 2>/dev/null) == "200" ]]; then
  ok "backend /health/ready returns 200 — postgres connection verified (Req 6.2)"
else
  info "backend /health/ready response: $READY_RESPONSE"
  fail "backend /health/ready did not return 200 — postgres connection may have failed"
fi

# Verify Loki connection from backend
info "Checking Loki connection from backend..."
HEALTH_JSON=$(docker compose -f "$COMPOSE_FILE" exec -T api curl -sf http://localhost:8000/health 2>/dev/null || echo "{}")
if echo "$HEALTH_JSON" | grep -q '"loki"'; then
  ok "backend /health includes Loki status"
else
  info "Loki status not separately reported in /health — checking connectivity directly"
  LOKI_STATUS=$(docker compose -f "$COMPOSE_FILE" exec -T api curl -sf http://loki:3100/ready 2>/dev/null || echo "")
  if echo "$LOKI_STATUS" | grep -q 'ready'; then
    ok "Loki reachable from backend container"
  else
    fail "Loki not reachable from backend container"
  fi
fi

# =============================================================================
# 7. Cleanup
# =============================================================================
section "Cleanup"
info "Stopping test services..."
docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true
ok "Services stopped and volumes removed"

# =============================================================================
# Summary
# =============================================================================
echo
echo "============================================================"
echo "Validation Summary"
echo "============================================================"
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo

if [[ $FAIL -eq 0 ]]; then
  echo "All checks passed. Docker Compose deployment is valid."
  exit 0
else
  echo "Some checks failed. Review the output above."
  exit 1
fi
