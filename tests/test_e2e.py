"""
End-to-end integration tests for the IoT IDS/IPS system.

Uses FastAPI TestClient (no real Docker needed) with mocked database sessions,
ML pipeline, and agent queues to exercise the full request/response cycle.

Covers:
- POST /auth/token  (login flow)
- GET  /api/v1/alerts
- GET  /api/v1/incidents
- GET  /health/ready
- Unauthenticated requests return 401
- Graceful shutdown calls close_db

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 2.1, 3.2, 4.2, 13.7
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

# Must be set before any backend imports
os.environ.setdefault("JWT_SECRET_KEY", "e2e-test-secret-key-for-testing-only")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost/testdb")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.auth import AuthService, get_current_user, require_role, router as auth_router
from backend.api.health import router as health_router
from backend.api.routes import router as api_router
from backend.api.schemas import TokenData
from backend.database.connection import get_session
import backend.metrics as _m


# ---------------------------------------------------------------------------
# Helpers — build a minimal FastAPI app without the full lifespan
# ---------------------------------------------------------------------------

def _make_mock_session():
    """Return an AsyncMock that behaves like an AsyncSession."""
    session = AsyncMock()
    # execute() returns a result whose scalar() / scalars().all() return empty data
    result = MagicMock()
    result.scalar.return_value = 0
    result.scalar_one_or_none.return_value = None
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = []
    result.scalars.return_value = scalars_mock
    session.execute = AsyncMock(return_value=result)
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    return session


def _make_mock_pipeline():
    """Return a MagicMock ML pipeline with both models available."""
    pipeline = MagicMock()
    pipeline.lightgbm_available = True
    pipeline.if_available = True
    pipeline.get_latency_stats = MagicMock(return_value={})
    return pipeline


def _make_mock_agents():
    """Return a dict of mock agents whose tasks are all running."""
    names = [
        "traffic", "analysis", "orchestrator", "response", "observability",
    ]
    agents = {}
    for name in names:
        a = MagicMock()
        a.stop = AsyncMock()
        a.start = AsyncMock()
        agents[name] = a
    return agents


def _make_mock_agent_tasks():
    """Return a dict of non-done asyncio Tasks (placeholder sleeps)."""
    tasks = {}
    names = [
        "traffic", "analysis", "orchestrator", "response", "observability",
    ]
    for name in names:
        t = MagicMock()
        t.done.return_value = False
        tasks[name] = t
    return tasks


# ---------------------------------------------------------------------------
# App fixture — minimal FastAPI app with all routers, no real lifespan
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    """
    Build a minimal FastAPI app with all routers registered.
    State is pre-populated with mocks so no real DB/agents are needed.
    """
    _app = FastAPI()
    _app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
    _app.include_router(api_router, prefix="/api/v1", tags=["API"])
    _app.include_router(health_router, tags=["Health"])

    # Pre-populate app.state
    _app.state.pipeline = _make_mock_pipeline()
    _app.state.agents = _make_mock_agents()
    _app.state.agent_tasks = _make_mock_agent_tasks()
    _app.state.ollama_url = "http://localhost:11434"
    _app.state.config = None  # will fall back to load_config()

    return _app


@pytest.fixture()
def mock_session():
    return _make_mock_session()


@pytest.fixture()
def client(app, mock_session):
    """
    TestClient with the DB session dependency overridden to use a mock.
    Also patches health_check and check_ollama_health so no real I/O occurs.
    """
    # FastAPI Depends() with get_session (an asynccontextmanager) needs an async generator override
    async def _mock_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _mock_get_session

    with patch("backend.api.health.health_check", new=AsyncMock(return_value=True)), \
         patch("backend.api.health.check_ollama_health", new=AsyncMock(return_value=True)), \
         patch("backend.utils.config_loader.load_config") as mock_cfg:
        from backend.utils.config_loader import SystemConfig
        mock_cfg.return_value = SystemConfig()
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


# ---------------------------------------------------------------------------
# Helper — create a valid JWT for test users
# ---------------------------------------------------------------------------

def _make_token(username: str = "testuser", role: str = "admin") -> str:
    return AuthService.create_access_token(username=username, role=role)


def _auth_headers(username: str = "testuser", role: str = "admin") -> dict:
    return {"Authorization": f"Bearer {_make_token(username, role)}"}


# ---------------------------------------------------------------------------
# 1. POST /auth/token — login flow
# ---------------------------------------------------------------------------

class TestAuthToken:
    """
    Verify the /auth/token endpoint login flow.
    Requirements: 1.4, 5.1, 5.2, 5.3
    """

    def test_login_success_returns_token(self, client, mock_session):
        """Valid credentials return a JWT access token (Req 5.1)."""
        from backend.database.models import UserModel
        from backend.api.auth import AuthService as _AS

        # Build a mock user — bypass real bcrypt by mocking verify_password
        mock_user = MagicMock(spec=UserModel)
        mock_user.username = "admin"
        mock_user.role = "admin"
        mock_user.password_hash = "hashed_secret"

        result = MagicMock()
        result.scalar_one_or_none.return_value = mock_user
        mock_session.execute = AsyncMock(return_value=result)

        with patch.object(_AS, "verify_password", return_value=True):
            resp = client.post(
                "/auth/token",
                data={"username": "admin", "password": "secret"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert body["expires_in"] > 0

    def test_login_invalid_password_returns_401(self, client, mock_session):
        """Wrong password returns HTTP 401 (Req 5.3)."""
        from backend.database.models import UserModel
        from backend.api.auth import AuthService as _AS

        mock_user = MagicMock(spec=UserModel)
        mock_user.username = "admin"
        mock_user.role = "admin"
        mock_user.password_hash = "hashed_correct"

        result = MagicMock()
        result.scalar_one_or_none.return_value = mock_user
        mock_session.execute = AsyncMock(return_value=result)

        with patch.object(_AS, "verify_password", return_value=False):
            resp = client.post(
                "/auth/token",
                data={"username": "admin", "password": "wrong"},
            )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid credentials"

    def test_login_unknown_user_returns_401(self, client, mock_session):
        """Unknown username returns HTTP 401 (Req 5.3)."""
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=result)

        resp = client.post(
            "/auth/token",
            data={"username": "nobody", "password": "pass"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid credentials"


# ---------------------------------------------------------------------------
# 2. GET /api/v1/alerts — alerts endpoint
# ---------------------------------------------------------------------------

class TestAlertsEndpoint:
    """
    Verify the /api/v1/alerts endpoint.
    Requirements: 2.1, 5.6
    """

    def test_alerts_returns_200_with_empty_list(self, client):
        """Authenticated GET /api/v1/alerts returns 200 with empty alerts list (Req 2.1)."""
        resp = client.get("/api/v1/alerts", headers=_auth_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert "alerts" in body
        assert isinstance(body["alerts"], list)
        assert body["total"] == 0

    def test_alerts_unauthenticated_returns_401(self, client):
        """GET /api/v1/alerts without token returns 401 (Req 5.6)."""
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 401

    def test_alerts_limit_too_large_returns_422(self, client):
        """limit > 500 returns HTTP 422 (Req 15.1)."""
        resp = client.get("/api/v1/alerts?limit=501", headers=_auth_headers())
        assert resp.status_code == 422

    def test_alerts_invalid_offset_returns_422(self, client):
        """Negative offset returns HTTP 422 (Req 15.2)."""
        resp = client.get("/api/v1/alerts?offset=-1", headers=_auth_headers())
        assert resp.status_code == 422

    def test_alerts_viewer_role_allowed(self, client):
        """viewer role can access GET /api/v1/alerts (Req 5.8)."""
        resp = client.get("/api/v1/alerts", headers=_auth_headers(role="viewer"))
        assert resp.status_code == 200

    def test_alerts_default_pagination(self, client):
        """Response includes limit and offset fields (Req 2.1)."""
        resp = client.get("/api/v1/alerts", headers=_auth_headers())
        body = resp.json()
        assert body["limit"] == 50
        assert body["offset"] == 0


# ---------------------------------------------------------------------------
# 3. GET /api/v1/incidents — incidents endpoint
# ---------------------------------------------------------------------------

class TestIncidentsEndpoint:
    """
    Verify the /api/v1/incidents endpoint.
    Requirements: 2.3, 5.6
    """

    def test_incidents_returns_200_with_empty_list(self, client):
        """Authenticated GET /api/v1/incidents returns 200 (Req 2.3)."""
        resp = client.get("/api/v1/incidents", headers=_auth_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert "incidents" in body
        assert isinstance(body["incidents"], list)

    def test_incidents_unauthenticated_returns_401(self, client):
        """GET /api/v1/incidents without token returns 401 (Req 5.6)."""
        resp = client.get("/api/v1/incidents")
        assert resp.status_code == 401

    def test_incidents_viewer_role_allowed(self, client):
        """viewer role can access GET /api/v1/incidents (Req 5.8)."""
        resp = client.get("/api/v1/incidents", headers=_auth_headers(role="viewer"))
        assert resp.status_code == 200

    def test_incidents_invalid_limit_returns_422(self, client):
        """limit > 500 returns HTTP 422 (Req 15.1)."""
        resp = client.get("/api/v1/incidents?limit=999", headers=_auth_headers())
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 4. GET /health/ready — readiness probe
# ---------------------------------------------------------------------------

class TestHealthReady:
    """
    Verify the /health/ready readiness probe.
    Requirements: 4.2, 4.8
    """

    def test_ready_returns_200_when_all_healthy(self, client):
        """All components healthy → HTTP 200 (Req 4.2)."""
        resp = client.get("/health/ready")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ready"

    def test_ready_returns_503_when_db_down(self, app, mock_session):
        """DB unavailable → HTTP 503 with database_unavailable reason (Req 4.8)."""
        @asynccontextmanager
        async def _override_get_session():
            yield mock_session

        app.dependency_overrides[get_session] = _override_get_session

        with patch("backend.api.health.health_check", new=AsyncMock(return_value=False)), \
             patch("backend.api.health.check_ollama_health", new=AsyncMock(return_value=True)):
            with TestClient(app, raise_server_exceptions=False) as c:
                resp = c.get("/health/ready")

        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "not_ready"
        assert body["reason"] == "database_unavailable"

    def test_ready_returns_503_when_ml_models_unavailable(self, app, mock_session):
        """No ML models loaded → HTTP 503 with ml_models_unavailable reason (Req 4.2)."""
        app.state.pipeline.lightgbm_available = False
        app.state.pipeline.if_available = False

        @asynccontextmanager
        async def _override_get_session():
            yield mock_session

        app.dependency_overrides[get_session] = _override_get_session

        with patch("backend.api.health.health_check", new=AsyncMock(return_value=True)), \
             patch("backend.api.health.check_ollama_health", new=AsyncMock(return_value=True)):
            with TestClient(app, raise_server_exceptions=False) as c:
                resp = c.get("/health/ready")

        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "not_ready"
        assert body["reason"] == "ml_models_unavailable"

    def test_live_always_returns_200(self, client):
        """GET /health/live always returns 200 (Req 4.3)."""
        resp = client.get("/health/live")
        assert resp.status_code == 200
        assert resp.json()["status"] == "alive"

    def test_health_endpoint_returns_component_details(self, client):
        """GET /health returns database, ml_models, ollama, agents fields (Req 4.1)."""
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert "database" in body
        assert "ml_models" in body
        assert "ollama" in body
        assert "agents" in body
        assert "timestamp" in body


# ---------------------------------------------------------------------------
# 6. RBAC — unauthenticated and insufficient-role requests
# ---------------------------------------------------------------------------

class TestRBAC:
    """
    Verify role-based access control enforcement.
    Requirements: 5.6, 5.7, 5.8, 5.9, 5.10, 5.11
    """

    def test_missing_auth_header_returns_401(self, client):
        """No Authorization header → 401 on protected endpoint (Req 5.6)."""
        for path in ["/api/v1/alerts", "/api/v1/incidents", "/api/v1/devices"]:
            resp = client.get(path)
            assert resp.status_code == 401, f"Expected 401 for {path}, got {resp.status_code}"

    def test_malformed_token_returns_401(self, client):
        """Malformed JWT → 401 (Req 5.7)."""
        resp = client.get(
            "/api/v1/alerts",
            headers={"Authorization": "Bearer not.a.valid.jwt"},
        )
        assert resp.status_code == 401

    def test_viewer_cannot_put_config(self, client):
        """viewer role cannot PUT /api/v1/config → 403 (Req 5.11)."""
        resp = client.put(
            "/api/v1/config",
            json={"composite_threshold": 0.7},
            headers=_auth_headers(role="viewer"),
        )
        assert resp.status_code == 403

    def test_analyst_cannot_put_config(self, client):
        """analyst role cannot PUT /api/v1/config → 403 (Req 5.11)."""
        resp = client.put(
            "/api/v1/config",
            json={"composite_threshold": 0.7},
            headers=_auth_headers(role="analyst"),
        )
        assert resp.status_code == 403

    def test_admin_can_access_all_get_endpoints(self, client):
        """admin role can access all GET endpoints (Req 5.10)."""
        for path in ["/api/v1/alerts", "/api/v1/incidents", "/api/v1/devices"]:
            resp = client.get(path, headers=_auth_headers(role="admin"))
            assert resp.status_code == 200, f"Expected 200 for {path}, got {resp.status_code}"

    def test_viewer_can_access_read_endpoints(self, client):
        """viewer role can access read-only endpoints (Req 5.8)."""
        for path in ["/api/v1/alerts", "/api/v1/incidents", "/api/v1/devices"]:
            resp = client.get(path, headers=_auth_headers(role="viewer"))
            assert resp.status_code == 200, f"Expected 200 for {path}, got {resp.status_code}"

    def test_viewer_cannot_access_config(self, client):
        """viewer role cannot GET /api/v1/config → 403 (Req 5.8)."""
        resp = client.get("/api/v1/config", headers=_auth_headers(role="viewer"))
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 7. Graceful shutdown — close_db is called
# ---------------------------------------------------------------------------

class TestGracefulShutdown:
    """
    Verify that the lifespan context manager calls close_db on shutdown.
    Requirements: 1.5, 1.6
    """

    def test_lifespan_calls_close_db_on_shutdown(self):
        """
        When the FastAPI app shuts down via lifespan, close_db() is called.
        We test this by running the lifespan context manager directly.
        Requirements: 1.6
        """
        import asyncio
        from backend.main import lifespan

        close_db_called = []

        async def _run():
            with patch("backend.main.init_db", new=AsyncMock()), \
                 patch("backend.main.close_db", new=AsyncMock(side_effect=lambda: close_db_called.append(True))), \
                 patch("backend.main.get_queues", return_value=MagicMock()), \
                 patch("backend.main.MLInferencePipeline") as mock_pipeline_cls, \
                 patch("backend.main.load_config", return_value=MagicMock(composite_threshold=0.65, whitelist_ips=[])), \
                 patch("backend.main._create_agents", return_value={}), \
                 patch("backend.main._start_agents", new=AsyncMock(return_value={})), \
                 patch("backend.main._start_supervisors", new=AsyncMock(return_value=[])), \
                 patch("backend.main._graceful_shutdown", new=AsyncMock(return_value={"timed_out_queues": [], "total_drain_time_seconds": 0.0})):

                mock_pipeline_cls.return_value = _make_mock_pipeline()
                _app = FastAPI(lifespan=lifespan)
                async with lifespan(_app):
                    pass  # startup then immediate shutdown

            return close_db_called

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(_run())
        finally:
            loop.close()
        assert result, "close_db() was not called during shutdown"
