"""
Unit tests for REST API endpoints.

Tests cover:
- Pagination validation (limit/offset bounds, 422 for out-of-range values)
- Incident acknowledgment state transitions (200, 404, 409, 422)
- Config validation rules (composite_threshold, whitelist_ips)
- Error responses always contain a "detail" field

Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.4, 3.5, 15.1, 15.2, 15.3
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

# Must be set before importing backend modules that read env vars at import time
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost/test")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.routes import router
from backend.api.auth import get_current_user, require_role
from backend.api.schemas import TokenData
from backend.database.connection import get_session


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
# Pagination – /api/v1/alerts
# ---------------------------------------------------------------------------

class TestAlertPagination:
    """Requirement 15.1 – limit/offset validation on the alerts endpoint."""

    def test_default_pagination_returns_200(self, client):
        """GET /alerts with no params returns 200 with correct defaults."""
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200
        body = resp.json()
        assert body["limit"] == 50
        assert body["offset"] == 0
        assert "alerts" in body
        assert "total" in body

    def test_explicit_valid_pagination(self, client):
        """GET /alerts?limit=10&offset=20 returns 200 echoing the params."""
        resp = client.get("/api/v1/alerts?limit=10&offset=20")
        assert resp.status_code == 200
        body = resp.json()
        assert body["limit"] == 10
        assert body["offset"] == 20

    def test_limit_above_500_returns_422(self, client):
        """GET /alerts?limit=501 must return 422 (Req 15.1)."""
        resp = client.get("/api/v1/alerts?limit=501")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_limit_exactly_500_returns_200(self, client):
        """GET /alerts?limit=500 is the maximum allowed value."""
        resp = client.get("/api/v1/alerts?limit=500")
        assert resp.status_code == 200

    def test_negative_limit_returns_422(self, client):
        """GET /alerts?limit=-1 must return 422 (Req 15.2)."""
        resp = client.get("/api/v1/alerts?limit=-1")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_negative_offset_returns_422(self, client):
        """GET /alerts?offset=-1 must return 422 (Req 15.2)."""
        resp = client.get("/api/v1/alerts?offset=-1")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_non_integer_limit_returns_422(self, client):
        """GET /alerts?limit=abc must return 422 (Req 15.3)."""
        resp = client.get("/api/v1/alerts?limit=abc")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_non_integer_offset_returns_422(self, client):
        """GET /alerts?offset=xyz must return 422 (Req 15.3)."""
        resp = client.get("/api/v1/alerts?offset=xyz")
        assert resp.status_code == 422
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# Pagination – /api/v1/incidents
# ---------------------------------------------------------------------------

class TestIncidentPagination:
    """Requirement 15.1 – limit/offset validation on the incidents endpoint."""

    def test_default_pagination_returns_200(self, client):
        resp = client.get("/api/v1/incidents")
        assert resp.status_code == 200
        body = resp.json()
        assert body["limit"] == 50
        assert body["offset"] == 0

    def test_limit_above_500_returns_422(self, client):
        resp = client.get("/api/v1/incidents?limit=600")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_negative_offset_returns_422(self, client):
        resp = client.get("/api/v1/incidents?offset=-5")
        assert resp.status_code == 422
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# Incident acknowledge – /api/v1/incidents/{id}/acknowledge
# ---------------------------------------------------------------------------

class TestAcknowledgeIncident:
    """Requirements 2.5, 2.6 – acknowledge endpoint state transitions."""

    _body = {"acknowledged_by": "analyst1", "notes": "Reviewed and resolved."}

    def test_acknowledge_success_returns_200(self, client):
        """POST acknowledge on a 'detected' incident returns 200 (Req 2.5)."""
        incident = _make_incident(state="detected")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = incident
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{incident.id}/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 200
        body = resp.json()
        # The route returns an IncidentResponse; state should be updated to resolved
        assert body["state"] == "resolved"

    def test_acknowledge_not_found_returns_404(self, client):
        """POST acknowledge on a missing incident returns 404 (Req 2.6)."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        missing_id = str(uuid.uuid4())
        resp = client.post(
            f"/api/v1/incidents/{missing_id}/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 404
        assert "detail" in resp.json()

    def test_acknowledge_already_closed_returns_409(self, client):
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
        assert "detail" in resp.json()

    def test_acknowledge_invalid_uuid_returns_422(self, client):
        """POST acknowledge with a non-UUID path param returns 422 (Req 15.3)."""
        resp = client.post(
            "/api/v1/incidents/not-a-valid-uuid/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_acknowledge_missing_body_returns_422(self, client):
        """POST acknowledge without a request body returns 422."""
        incident_id = str(uuid.uuid4())
        resp = client.post(f"/api/v1/incidents/{incident_id}/acknowledge")
        assert resp.status_code == 422
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# Config validation – PUT /api/v1/config
# ---------------------------------------------------------------------------

class TestConfigValidation:
    """Requirements 3.4, 3.5 – config update validation."""

    def _mock_config(self):
        """Return a minimal SystemConfig-like MagicMock."""
        from backend.utils.config_loader import SystemConfig
        cfg = SystemConfig()
        return cfg

    def test_composite_threshold_above_1_returns_422(self, client):
        """PUT /config with composite_threshold > 1.0 must return 422 (Req 3.5)."""
        resp = client.put("/api/v1/config", json={"composite_threshold": 1.5})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_composite_threshold_equal_1_returns_422(self, client):
        """PUT /config with composite_threshold == 1.0 must return 422 (boundary)."""
        resp = client.put("/api/v1/config", json={"composite_threshold": 1.0})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_invalid_ip_in_whitelist_returns_422(self, client):
        """PUT /config with an invalid IP in whitelist_ips must return 422 (Req 3.5)."""
        resp = client.put(
            "/api/v1/config",
            json={"whitelist_ips": ["not.an.ip.address"]},
        )
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_invalid_ip_in_blacklist_returns_422(self, client):
        """PUT /config with an invalid IP in blacklist_ips must return 422."""
        resp = client.put(
            "/api/v1/config",
            json={"blacklist_ips": ["999.999.999.999"]},
        )
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_valid_config_update_returns_200(self, client):
        """PUT /config with valid fields returns 200 (Req 3.4)."""
        with patch("backend.api.routes.load_config", return_value=self._mock_config()), \
             patch("backend.utils.config_loader._validate"):
            resp = client.put(
                "/api/v1/config",
                json={"composite_threshold": 0.75, "whitelist_ips": ["10.0.0.1"]},
            )
        assert resp.status_code == 200

    def test_detection_threshold_out_of_range_returns_422(self, client):
        """PUT /config with detection_threshold <= 0 must return 422."""
        resp = client.put("/api/v1/config", json={"detection_threshold": 0.0})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_log_retention_days_too_large_returns_422(self, client):
        """PUT /config with log_retention_days > 3650 must return 422."""
        resp = client.put("/api/v1/config", json={"log_retention_days": 9999})
        assert resp.status_code == 422
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# Metrics endpoint – GET /api/v1/metrics
# ---------------------------------------------------------------------------

class TestMetricsEndpoint:
    """Requirement 3.3 – metrics endpoint returns structured data."""

    def test_metrics_returns_200(self, client):
        """GET /metrics returns 200 with expected top-level keys."""
        # get_queues is imported inside the route function body, so patch at source
        with patch("backend.agents.queues.get_queues") as mock_get_queues:
            mock_q = MagicMock()
            mock_q.detection_queue.qsize.return_value = 0
            mock_q.anomaly_queue.qsize.return_value = 0
            mock_q.risk_queue.qsize.return_value = 0
            mock_q.orchestrator_queue.qsize.return_value = 0
            mock_q.prevention_queue.qsize.return_value = 0
            mock_q.healing_queue.qsize.return_value = 0
            mock_q.logging_queue.qsize.return_value = 0
            mock_get_queues.return_value = mock_q

            resp = client.get("/api/v1/metrics")

        assert resp.status_code == 200
        body = resp.json()
        assert "queue_depths" in body
        assert "ml_latency_ms" in body
        assert "total_events_processed" in body
        assert "active_incidents" in body


# ---------------------------------------------------------------------------
# Devices endpoint – GET /api/v1/devices
# ---------------------------------------------------------------------------

class TestDevicesEndpoint:
    """Requirement 3.3 – devices endpoint pagination."""

    def test_devices_default_pagination(self, client):
        resp = client.get("/api/v1/devices")
        assert resp.status_code == 200
        body = resp.json()
        assert body["limit"] == 50
        assert body["offset"] == 0
        assert "devices" in body

    def test_devices_limit_above_500_returns_422(self, client):
        resp = client.get("/api/v1/devices?limit=501")
        assert resp.status_code == 422
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# Error response contract
# ---------------------------------------------------------------------------

class TestErrorResponseContract:
    """All error responses must contain a 'detail' field (Req 15.1–15.3)."""

    def test_422_has_detail_field(self, client):
        resp = client.get("/api/v1/alerts?limit=abc")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_404_has_detail_field(self, client):
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        missing_id = str(uuid.uuid4())
        resp = client.post(
            f"/api/v1/incidents/{missing_id}/acknowledge",
            json={"acknowledged_by": "admin"},
        )
        assert resp.status_code == 404
        assert "detail" in resp.json()

    def test_409_has_detail_field(self, client):
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
