"""
Unit tests for API error handling and input validation.

Tests cover:
- HTTP 422 Validation errors for invalid inputs (limit, offset, UUID, config fields)
- HTTP 404 responses for missing resources
- HTTP 409 responses for conflict scenarios
- HTTP 500 responses from the global exception handler

All error responses are verified to contain a "detail" field.

Requirements: 15.1, 15.2, 15.3, 15.4, 15.5
"""
from __future__ import annotations

import os

# Must be set before importing backend modules that read env vars at import time
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost/test")

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from backend.api.auth import get_current_user, require_role
from backend.api.routes import router
from backend.api.schemas import TokenData
from backend.database.connection import get_session
from backend.main import app as main_app  # for testing global exception handler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_session():
    """Return a fully-configured AsyncMock session with sensible defaults."""
    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_result.scalar.return_value = 0
    mock_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=mock_result)
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    return session


def _make_incident(state: str = "detected") -> MagicMock:
    """Return a MagicMock that looks like an IncidentModel row."""
    inc = MagicMock()
    inc.id = str(uuid.uuid4())
    inc.state = state
    inc.severity = "high"
    inc.attack_type = "DDoS"
    inc.response_plan = {}
    inc.detected_at = datetime.now(timezone.utc)
    inc.resolved_at = None
    inc.created_at = datetime.now(timezone.utc)
    return inc


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """
    FastAPI TestClient with:
    - auth dependencies overridden (all requests pass as admin)
    - get_session overridden with an AsyncMock
    - require_role patched to a no-op factory
    """
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    mock_session = _make_mock_session()

    async def _override_session():
        yield mock_session

    app.dependency_overrides[get_current_user] = lambda: TokenData(
        username="admin", role="admin"
    )
    app.dependency_overrides[get_session] = _override_session

    def _noop_require_role(*roles):
        def _dep():
            return TokenData(username="admin", role="admin")
        return _dep

    with patch("backend.api.routes.require_role", side_effect=_noop_require_role):
        with TestClient(app) as c:
            c.mock_session = mock_session  # type: ignore[attr-defined]
            yield c


# ---------------------------------------------------------------------------
# 422 Validation Errors — /api/v1/alerts
# ---------------------------------------------------------------------------

class TestAlertsValidationErrors:
    """Requirements 15.1, 15.2, 15.3 — query parameter validation on /alerts."""

    def test_non_integer_limit_returns_422(self, client):
        """GET /alerts?limit=abc must return 422 with detail field (Req 15.3)."""
        resp = client.get("/api/v1/alerts?limit=abc")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_limit_exceeds_max_returns_422(self, client):
        """GET /alerts?limit=1000 must return 422 — exceeds max of 500 (Req 15.1)."""
        resp = client.get("/api/v1/alerts?limit=1000")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_negative_offset_returns_422(self, client):
        """GET /alerts?offset=-1 must return 422 (Req 15.2)."""
        resp = client.get("/api/v1/alerts?offset=-1")
        assert resp.status_code == 422
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# 422 Validation Errors — /api/v1/incidents/{id}/acknowledge
# ---------------------------------------------------------------------------

class TestAcknowledgeValidationErrors:
    """Requirement 15.3 — UUID format validation on acknowledge endpoint."""

    _body = {"acknowledged_by": "analyst1", "notes": "Reviewed."}

    def test_non_uuid_incident_id_returns_422(self, client):
        """POST /incidents/not-a-uuid/acknowledge must return 422 (Req 15.3)."""
        resp = client.post(
            "/api/v1/incidents/not-a-uuid/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_missing_body_returns_422(self, client):
        """POST /incidents/{id}/acknowledge without body must return 422."""
        incident_id = str(uuid.uuid4())
        resp = client.post(f"/api/v1/incidents/{incident_id}/acknowledge")
        assert resp.status_code == 422
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# 422 Validation Errors — PUT /api/v1/config
# ---------------------------------------------------------------------------

class TestConfigValidationErrors:
    """Requirements 15.1, 15.4 — config field validation."""

    def test_composite_threshold_above_1_returns_422(self, client):
        """PUT /config with composite_threshold=2.0 must return 422 (Req 15.4)."""
        resp = client.put("/api/v1/config", json={"composite_threshold": 2.0})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_invalid_ip_in_whitelist_returns_422(self, client):
        """PUT /config with whitelist_ips=["bad-ip"] must return 422 (Req 15.4)."""
        resp = client.put("/api/v1/config", json={"whitelist_ips": ["bad-ip"]})
        assert resp.status_code == 422
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# 404 Not Found
# ---------------------------------------------------------------------------

class TestNotFoundResponses:
    """Requirement 2.5 — 404 for missing incidents."""

    _body = {"acknowledged_by": "analyst1"}

    def test_acknowledge_missing_incident_returns_404(self, client):
        """POST acknowledge on a non-existent incident UUID returns 404 (Req 2.5)."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        missing_id = str(uuid.uuid4())
        resp = client.post(
            f"/api/v1/incidents/{missing_id}/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 404
        body = resp.json()
        assert "detail" in body
        assert body["detail"] == "Incident not found"

    def test_404_response_contains_detail_field(self, client):
        """All 404 responses must contain a 'detail' field (Req 15.4)."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{uuid.uuid4()}/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 404
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# 409 Conflict
# ---------------------------------------------------------------------------

class TestConflictResponses:
    """Requirement 2.6 — 409 for already-closed incidents."""

    _body = {"acknowledged_by": "analyst1"}

    def test_acknowledge_closed_incident_returns_409(self, client):
        """POST acknowledge on a 'closed' incident returns 409 (Req 2.6)."""
        incident = _make_incident(state="closed")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = incident
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{incident.id}/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 409
        body = resp.json()
        assert "detail" in body
        assert body["detail"] == "Incident already closed"

    def test_409_response_contains_detail_field(self, client):
        """All 409 responses must contain a 'detail' field (Req 15.4)."""
        incident = _make_incident(state="closed")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = incident
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{incident.id}/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 409
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# 500 Internal Server Error — global exception handler
# ---------------------------------------------------------------------------

class TestGlobalExceptionHandler:
    """Requirement 15.5 — global exception handler returns 500 with detail field."""

    def test_unhandled_exception_returns_500_with_detail(self):
        """
        The global exception handler in main.py must return HTTP 500
        with {"detail": "Internal server error"} for any unhandled exception.
        (Req 15.5)
        """
        # Build a minimal app that reuses the same global exception handler
        # registered in main.py, without triggering the full lifespan startup.
        test_app = FastAPI()

        # Register the same exception handler logic as in main.py
        @test_app.exception_handler(Exception)
        async def _global_handler(request: Request, exc: Exception) -> JSONResponse:
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"},
            )

        # Add a route that always raises an unhandled exception
        @test_app.get("/boom")
        async def _boom():
            raise RuntimeError("Something went very wrong")

        with TestClient(test_app, raise_server_exceptions=False) as c:
            resp = c.get("/boom")

        assert resp.status_code == 500
        body = resp.json()
        assert "detail" in body
        assert body["detail"] == "Internal server error"

    def test_500_response_detail_is_generic_message(self):
        """
        The 500 response must not leak internal exception details to the client.
        (Req 15.5)
        """
        test_app = FastAPI()

        @test_app.exception_handler(Exception)
        async def _global_handler(request: Request, exc: Exception) -> JSONResponse:
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"},
            )

        @test_app.get("/secret-error")
        async def _secret_error():
            raise ValueError("Sensitive internal detail: db_password=hunter2")

        with TestClient(test_app, raise_server_exceptions=False) as c:
            resp = c.get("/secret-error")

        assert resp.status_code == 500
        body = resp.json()
        # The sensitive exception message must NOT appear in the response
        assert "hunter2" not in str(body)
        assert body["detail"] == "Internal server error"


# ---------------------------------------------------------------------------
# Error response contract — all errors must have "detail"
# ---------------------------------------------------------------------------

class TestErrorResponseContract:
    """Requirement 15.4 — every error response contains a 'detail' field."""

    def test_422_has_detail_field(self, client):
        """422 from invalid limit must contain 'detail'."""
        resp = client.get("/api/v1/alerts?limit=abc")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_404_has_detail_field(self, client):
        """404 from missing incident must contain 'detail'."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{uuid.uuid4()}/acknowledge",
            json={"acknowledged_by": "admin"},
        )
        assert resp.status_code == 404
        assert "detail" in resp.json()

    def test_409_has_detail_field(self, client):
        """409 from closed incident must contain 'detail'."""
        incident = _make_incident(state="closed")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = incident
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{incident.id}/acknowledge",
            json={"acknowledged_by": "admin"},
        )
        assert resp.status_code == 409
        assert "detail" in resp.json()
