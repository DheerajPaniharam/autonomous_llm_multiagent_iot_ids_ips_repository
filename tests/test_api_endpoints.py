"""
Unit tests for REST API endpoints.

Tests cover:
- Pagination and filtering logic (alerts severity, incidents state, devices isolation)
- Incident acknowledgment state transitions (200, 404, 409, 422)
- Config validation rules (all VALIDATION_RULES fields)
- Error responses (404, 409, 422) always contain a "detail" field

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


def _make_alert(composite_score: float = 0.8) -> MagicMock:
    """Return a MagicMock that looks like an AttackEventModel row."""
    alert = MagicMock()
    alert.id = str(uuid.uuid4())
    alert.flow_id = str(uuid.uuid4())
    alert.timestamp = datetime.now(timezone.utc)
    alert.src_ip = "192.168.1.10"
    alert.dst_ip = "10.0.0.1"
    alert.src_port = 12345
    alert.dst_port = 80
    alert.protocol = "TCP"
    alert.attack_type = "DDoS"
    alert.lightgbm_score = composite_score
    alert.if_score = composite_score
    alert.composite_score = composite_score
    alert.llm_analysis = None
    alert.incident_id = None
    return alert


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


def _make_device(is_isolated: bool = False) -> MagicMock:
    """Return a MagicMock that looks like an IoTDeviceModel row."""
    dev = MagicMock()
    dev.device_id = str(uuid.uuid4())
    dev.ip_address = "192.168.1.50"
    dev.mac_address = "AA:BB:CC:DD:EE:FF"
    dev.device_type = "sensor"
    dev.protocols = ["MQTT"]
    dev.first_seen = datetime.now(timezone.utc)
    dev.last_seen = datetime.now(timezone.utc)
    dev.is_isolated = is_isolated
    dev.baseline_packet_rate = 10.0
    dev.baseline_byte_rate = 1024.0
    return dev


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
# Pagination – /api/v1/alerts  (Req 15.1, 15.2, 15.3)
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

    def test_limit_exactly_1_returns_200(self, client):
        """GET /alerts?limit=1 is the minimum allowed value."""
        resp = client.get("/api/v1/alerts?limit=1")
        assert resp.status_code == 200

    def test_limit_exactly_500_returns_200(self, client):
        """GET /alerts?limit=500 is the maximum allowed value."""
        resp = client.get("/api/v1/alerts?limit=500")
        assert resp.status_code == 200

    def test_limit_above_500_returns_422(self, client):
        """GET /alerts?limit=501 must return 422 (Req 15.1)."""
        resp = client.get("/api/v1/alerts?limit=501")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_limit_zero_returns_422(self, client):
        """GET /alerts?limit=0 must return 422 (below minimum of 1)."""
        resp = client.get("/api/v1/alerts?limit=0")
        assert resp.status_code == 422
        assert "detail" in resp.json()

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
# Severity filtering – /api/v1/alerts  (Req 2.1, 2.2)
# ---------------------------------------------------------------------------

class TestAlertSeverityFilter:
    """Requirement 2.1, 2.2 – severity filter on the alerts endpoint."""

    def test_valid_severity_critical_returns_200(self, client):
        """GET /alerts?severity=critical returns 200 (Req 2.1)."""
        resp = client.get("/api/v1/alerts?severity=critical")
        assert resp.status_code == 200

    def test_valid_severity_high_returns_200(self, client):
        """GET /alerts?severity=high returns 200 (Req 2.1)."""
        resp = client.get("/api/v1/alerts?severity=high")
        assert resp.status_code == 200

    def test_valid_severity_medium_returns_200(self, client):
        """GET /alerts?severity=medium returns 200 (Req 2.1)."""
        resp = client.get("/api/v1/alerts?severity=medium")
        assert resp.status_code == 200

    def test_invalid_severity_returns_422(self, client):
        """GET /alerts?severity=unknown must return 422 (Req 2.2)."""
        resp = client.get("/api/v1/alerts?severity=unknown")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_invalid_severity_low_returns_422(self, client):
        """GET /alerts?severity=low is not a valid severity level."""
        resp = client.get("/api/v1/alerts?severity=low")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_alerts_response_contains_severity_field(self, client):
        """Alert responses include a severity field derived from composite_score."""
        alert = _make_alert(composite_score=0.95)
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [alert]
        mock_result.scalar.return_value = 1
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["alerts"]) == 1
        assert body["alerts"][0]["severity"] == "critical"

    def test_alert_severity_high_for_score_075_to_089(self, client):
        """Alert with composite_score=0.80 should have severity='high'."""
        alert = _make_alert(composite_score=0.80)
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [alert]
        mock_result.scalar.return_value = 1
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200
        assert resp.json()["alerts"][0]["severity"] == "high"

    def test_alert_severity_medium_for_score_065_to_074(self, client):
        """Alert with composite_score=0.70 should have severity='medium'."""
        alert = _make_alert(composite_score=0.70)
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [alert]
        mock_result.scalar.return_value = 1
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200
        assert resp.json()["alerts"][0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# Pagination – /api/v1/incidents  (Req 15.1, 15.2)
# ---------------------------------------------------------------------------

class TestIncidentPagination:
    """Requirement 15.1 – limit/offset validation on the incidents endpoint."""

    def test_default_pagination_returns_200(self, client):
        resp = client.get("/api/v1/incidents")
        assert resp.status_code == 200
        body = resp.json()
        assert body["limit"] == 50
        assert body["offset"] == 0
        assert "incidents" in body
        assert "total" in body

    def test_explicit_pagination_echoed(self, client):
        resp = client.get("/api/v1/incidents?limit=25&offset=10")
        assert resp.status_code == 200
        body = resp.json()
        assert body["limit"] == 25
        assert body["offset"] == 10

    def test_limit_above_500_returns_422(self, client):
        resp = client.get("/api/v1/incidents?limit=600")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_negative_offset_returns_422(self, client):
        resp = client.get("/api/v1/incidents?offset=-5")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_non_integer_limit_returns_422(self, client):
        resp = client.get("/api/v1/incidents?limit=bad")
        assert resp.status_code == 422
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# State filtering – /api/v1/incidents  (Req 2.3, 2.4)
# ---------------------------------------------------------------------------

class TestIncidentStateFilter:
    """Requirement 2.3, 2.4 – state filter on the incidents endpoint."""

    def test_valid_state_detected_returns_200(self, client):
        resp = client.get("/api/v1/incidents?state=detected")
        assert resp.status_code == 200

    def test_valid_state_analyzing_returns_200(self, client):
        resp = client.get("/api/v1/incidents?state=analyzing")
        assert resp.status_code == 200

    def test_valid_state_mitigating_returns_200(self, client):
        resp = client.get("/api/v1/incidents?state=mitigating")
        assert resp.status_code == 200

    def test_valid_state_resolved_returns_200(self, client):
        resp = client.get("/api/v1/incidents?state=resolved")
        assert resp.status_code == 200

    def test_valid_state_closed_returns_200(self, client):
        resp = client.get("/api/v1/incidents?state=closed")
        assert resp.status_code == 200

    def test_invalid_state_returns_422(self, client):
        """GET /incidents?state=unknown must return 422 (Req 2.4)."""
        resp = client.get("/api/v1/incidents?state=unknown")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_invalid_state_open_returns_422(self, client):
        """'open' is not a valid state value."""
        resp = client.get("/api/v1/incidents?state=open")
        assert resp.status_code == 422
        assert "detail" in resp.json()


# ---------------------------------------------------------------------------
# Incident acknowledgment state transitions  (Req 2.5, 2.6)
# ---------------------------------------------------------------------------

class TestIncidentDetail:
    """Incident detail endpoint should return summary and related alerts."""

    def test_get_incident_detail_returns_summary_and_related_alerts(self, client):
        incident = _make_incident(state="detected")
        alert = _make_alert(composite_score=0.92)
        alert.incident_id = incident.id

        incident_result = MagicMock()
        incident_result.scalar_one_or_none.return_value = incident

        alert_result = MagicMock()
        alert_result.scalars.return_value.all.return_value = [alert]

        client.mock_session.execute = AsyncMock(side_effect=[incident_result, alert_result])

        resp = client.get(f"/api/v1/incidents/{incident.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == incident.id
        assert body["alert_count"] == 1
        assert body["related_alerts"][0]["id"] == alert.id
        assert "summary" in body


class TestAcknowledgeIncident:
    """Requirements 2.5, 2.6 – acknowledge endpoint state transitions."""

    _body = {"acknowledged_by": "analyst1", "notes": "Reviewed and resolved."}

    def test_acknowledge_detected_incident_returns_200(self, client):
        """POST acknowledge on a 'detected' incident returns 200 with state=resolved."""
        incident = _make_incident(state="detected")
        incident.response_plan = {"event_id": str(uuid.uuid4())}

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = incident
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{incident.id}/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["state"] == "resolved"
        assert body["response_plan"]["event_id"] == incident.response_plan["event_id"]
        assert body["response_plan"]["acknowledged_by"] == self._body["acknowledged_by"]
        assert "acknowledged_at" in body["response_plan"]

    def test_acknowledge_analyzing_incident_returns_200(self, client):
        """POST acknowledge on an 'analyzing' incident returns 200 with state=resolved."""
        incident = _make_incident(state="analyzing")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = incident
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{incident.id}/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 200
        assert resp.json()["state"] == "resolved"

    def test_acknowledge_mitigating_incident_returns_200(self, client):
        """POST acknowledge on a 'mitigating' incident returns 200 with state=resolved."""
        incident = _make_incident(state="mitigating")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = incident
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{incident.id}/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 200
        assert resp.json()["state"] == "resolved"

    def test_acknowledge_resolved_incident_returns_200(self, client):
        """POST acknowledge on an already 'resolved' incident returns 200 (idempotent)."""
        incident = _make_incident(state="resolved")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = incident
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{incident.id}/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 200

    def test_acknowledge_not_found_returns_404(self, client):
        """POST acknowledge on a missing incident returns 404 (Req 2.6)."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{uuid.uuid4()}/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 404
        body = resp.json()
        assert "detail" in body
        assert body["detail"] == "Incident not found"

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
        body = resp.json()
        assert "detail" in body
        assert body["detail"] == "Incident already closed"

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
        resp = client.post(f"/api/v1/incidents/{uuid.uuid4()}/acknowledge")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_acknowledge_sets_resolved_at_timestamp(self, client):
        """POST acknowledge sets resolved_at on the incident."""
        incident = _make_incident(state="detected")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = incident
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{incident.id}/acknowledge",
            json=self._body,
        )
        assert resp.status_code == 200
        # The route sets resolved_at; verify the mock was updated
        assert incident.resolved_at is not None

    def test_acknowledge_records_acknowledged_by(self, client):
        """POST acknowledge stores acknowledged_by in response_plan."""
        incident = _make_incident(state="detected")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = incident
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(
            f"/api/v1/incidents/{incident.id}/acknowledge",
            json={"acknowledged_by": "analyst_bob", "notes": "All clear."},
        )
        assert resp.status_code == 200
        assert incident.response_plan.get("acknowledged_by") == "analyst_bob"


# ---------------------------------------------------------------------------
# Devices endpoint – pagination and filtering  (Req 3.3)
# ---------------------------------------------------------------------------

class TestAuditLogsAccessControl:
    """Audit log viewing should be restricted to admins only."""

    def test_analyst_cannot_access_audit_logs(self):
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")

        async def _override_session():
            yield _make_mock_session()

        app.dependency_overrides[get_current_user] = lambda: TokenData(username="analyst", role="analyst")
        app.dependency_overrides[get_session] = _override_session

        with TestClient(app) as c:
            resp = c.get("/api/v1/audit-logs")

        assert resp.status_code == 403
        assert resp.json()["detail"] == "Insufficient permissions"

    def test_admin_can_access_audit_logs(self):
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")

        async def _override_session():
            yield _make_mock_session()

        app.dependency_overrides[get_current_user] = lambda: TokenData(username="admin", role="admin")
        app.dependency_overrides[get_session] = _override_session

        with TestClient(app) as c:
            resp = c.get("/api/v1/audit-logs")

        assert resp.status_code == 200
        body = resp.json()
        assert body["limit"] == 50
        assert body["offset"] == 0
        assert "audit_logs" in body


class TestDevicesEndpoint:
    """Requirement 3.3 – devices endpoint pagination and isolation filter."""

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

    def test_devices_negative_offset_returns_422(self, client):
        resp = client.get("/api/v1/devices?offset=-1")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_devices_filter_isolated_true_returns_200(self, client):
        """GET /devices?is_isolated=true returns 200."""
        resp = client.get("/api/v1/devices?is_isolated=true")
        assert resp.status_code == 200

    def test_devices_filter_isolated_false_returns_200(self, client):
        """GET /devices?is_isolated=false returns 200."""
        resp = client.get("/api/v1/devices?is_isolated=false")
        assert resp.status_code == 200

    def test_devices_response_contains_required_fields(self, client):
        """Device response includes all required fields."""
        device = _make_device(is_isolated=True)
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [device]
        mock_result.scalar.return_value = 1
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.get("/api/v1/devices")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["devices"]) == 1
        dev = body["devices"][0]
        assert "device_id" in dev
        assert "ip_address" in dev
        assert "is_isolated" in dev
        assert dev["is_isolated"] is True

    def test_isolate_device_sets_isolated_true(self, client):
        """POST /devices/{id}/isolate should mark the device as isolated."""
        device = _make_device(is_isolated=False)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = device
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(f"/api/v1/devices/{device.device_id}/isolate")
        assert resp.status_code == 200
        assert resp.json()["is_isolated"] is True
        assert device.is_isolated is True

    def test_release_device_sets_isolated_false(self, client):
        """POST /devices/{id}/release should mark the device as released."""
        device = _make_device(is_isolated=True)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = device
        client.mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.post(f"/api/v1/devices/{device.device_id}/release")
        assert resp.status_code == 200
        assert resp.json()["is_isolated"] is False
        assert device.is_isolated is False


# ---------------------------------------------------------------------------
# Config validation – PUT /api/v1/config  (Req 3.4, 3.5, 15.1, 15.2)
# ---------------------------------------------------------------------------

class TestConfigValidation:
    """Requirements 3.4, 3.5 – config update validation against VALIDATION_RULES."""

    def _mock_config(self):
        """Return a default SystemConfig instance."""
        from backend.utils.config_loader import SystemConfig
        return SystemConfig()

    # --- composite_threshold ---

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

    def test_composite_threshold_zero_returns_422(self, client):
        """PUT /config with composite_threshold == 0.0 must return 422."""
        resp = client.put("/api/v1/config", json={"composite_threshold": 0.0})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_composite_threshold_negative_returns_422(self, client):
        """PUT /config with composite_threshold < 0 must return 422."""
        resp = client.put("/api/v1/config", json={"composite_threshold": -0.1})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    # --- detection_threshold ---

    def test_detection_threshold_zero_returns_422(self, client):
        """PUT /config with detection_threshold == 0.0 must return 422."""
        resp = client.put("/api/v1/config", json={"detection_threshold": 0.0})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_detection_threshold_above_1_returns_422(self, client):
        """PUT /config with detection_threshold > 1.0 must return 422."""
        resp = client.put("/api/v1/config", json={"detection_threshold": 1.1})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    # --- anomaly_threshold ---

    def test_anomaly_threshold_zero_returns_422(self, client):
        """PUT /config with anomaly_threshold == 0.0 must return 422."""
        resp = client.put("/api/v1/config", json={"anomaly_threshold": 0.0})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    # --- log_retention_days ---

    def test_log_retention_days_too_large_returns_422(self, client):
        """PUT /config with log_retention_days > 3650 must return 422."""
        resp = client.put("/api/v1/config", json={"log_retention_days": 9999})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_log_retention_days_zero_returns_422(self, client):
        """PUT /config with log_retention_days == 0 must return 422."""
        resp = client.put("/api/v1/config", json={"log_retention_days": 0})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    # --- backup_retention_days ---

    def test_backup_retention_days_too_large_returns_422(self, client):
        """PUT /config with backup_retention_days > 365 must return 422."""
        resp = client.put("/api/v1/config", json={"backup_retention_days": 400})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    # --- threat_intel_update_interval_hours ---

    def test_threat_intel_interval_too_large_returns_422(self, client):
        """PUT /config with threat_intel_update_interval_hours > 168 must return 422."""
        resp = client.put(
            "/api/v1/config",
            json={"threat_intel_update_interval_hours": 200},
        )
        assert resp.status_code == 422
        assert "detail" in resp.json()

    # --- IP address validation ---

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

    def test_valid_config_update_returns_config_response(self, client):
        """PUT /config returns a ConfigResponse with all expected fields."""
        with patch("backend.api.routes.load_config", return_value=self._mock_config()), \
             patch("backend.utils.config_loader._validate"):
            resp = client.put(
                "/api/v1/config",
                json={"composite_threshold": 0.80},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert "detection_threshold" in body
        assert "composite_threshold" in body
        assert "whitelist_ips" in body
        assert "version" in body


# ---------------------------------------------------------------------------
# Metrics endpoint – GET /api/v1/metrics  (Req 3.3)
# ---------------------------------------------------------------------------

class TestMetricsEndpoint:
    """Requirement 3.3 – metrics endpoint returns structured data."""

    def test_metrics_returns_200(self, client):
        """GET /metrics returns 200 with expected top-level keys."""
        with patch("backend.agents.queues.get_queues") as mock_get_queues:
            mock_q = MagicMock()
            for attr in (
                "detection_queue", "anomaly_queue", "risk_queue",
                "orchestrator_queue", "prevention_queue", "healing_queue",
                "logging_queue",
            ):
                getattr(mock_q, attr).qsize.return_value = 0
            mock_get_queues.return_value = mock_q

            resp = client.get("/api/v1/metrics")

        assert resp.status_code == 200
        body = resp.json()
        assert "queue_depths" in body
        assert "ml_latency_ms" in body
        assert "total_events_processed" in body
        assert "total_mitigations_applied" in body
        assert "active_incidents" in body
        assert "packet_drops" in body
        assert "timestamp" in body

    def test_metrics_queue_depths_has_all_queues(self, client):
        """GET /metrics queue_depths contains all seven agent queues."""
        with patch("backend.agents.queues.get_queues") as mock_get_queues:
            mock_q = MagicMock()
            for attr in (
                "detection_queue", "anomaly_queue", "risk_queue",
                "orchestrator_queue", "prevention_queue", "healing_queue",
                "logging_queue",
            ):
                getattr(mock_q, attr).qsize.return_value = 3
            mock_get_queues.return_value = mock_q

            resp = client.get("/api/v1/metrics")

        assert resp.status_code == 200
        depths = resp.json()["queue_depths"]
        for key in ("detection", "anomaly", "risk", "orchestrator", "prevention", "healing", "logging"):
            assert key in depths

    def test_metrics_ml_latency_has_all_percentiles(self, client):
        """GET /metrics ml_latency_ms contains supervised and IF percentiles."""
        with patch("backend.agents.queues.get_queues") as mock_get_queues:
            mock_q = MagicMock()
            for attr in (
                "detection_queue", "anomaly_queue", "risk_queue",
                "orchestrator_queue", "prevention_queue", "healing_queue",
                "logging_queue",
            ):
                getattr(mock_q, attr).qsize.return_value = 0
            mock_get_queues.return_value = mock_q

            resp = client.get("/api/v1/metrics")

        latency = resp.json()["ml_latency_ms"]
        for key in ("lightgbm_p50", "lightgbm_p95", "lightgbm_p99", "if_p50", "if_p95", "if_p99"):
            assert key in latency


# ---------------------------------------------------------------------------
# Error response contract  (Req 15.1, 15.2, 15.3)
# ---------------------------------------------------------------------------

class TestErrorResponseContract:
    """All error responses must contain a 'detail' field (Req 15.1–15.3)."""

    def test_422_has_detail_field_on_alerts(self, client):
        resp = client.get("/api/v1/alerts?limit=abc")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_422_has_detail_field_on_incidents(self, client):
        resp = client.get("/api/v1/incidents?limit=abc")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_422_has_detail_field_on_devices(self, client):
        resp = client.get("/api/v1/devices?limit=abc")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_422_has_detail_field_on_config(self, client):
        resp = client.put("/api/v1/config", json={"composite_threshold": 99.0})
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_404_has_detail_field(self, client):
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

    def test_422_invalid_severity_has_detail_field(self, client):
        resp = client.get("/api/v1/alerts?severity=invalid")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_422_invalid_state_has_detail_field(self, client):
        resp = client.get("/api/v1/incidents?state=invalid")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_422_invalid_uuid_has_detail_field(self, client):
        resp = client.post(
            "/api/v1/incidents/not-a-uuid/acknowledge",
            json={"acknowledged_by": "admin"},
        )
        assert resp.status_code == 422
        assert "detail" in resp.json()
