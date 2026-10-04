from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.auth import AuthService
from backend.api.routes import router


class DummyFlow:
    def __init__(self, flow_id: str, timestamp: datetime) -> None:
        self.flow_id = flow_id
        self.timestamp = timestamp
        self.src_ip = "10.0.0.1"
        self.dst_ip = "10.0.0.2"
        self.src_port = 1234
        self.dst_port = 80
        self.protocol = "tcp"
        self.packet_rate = 10.5
        self.byte_rate = 1024.0
        self.flow_duration = 1.23
        self.tcp_flags = "SYN"
        self.connection_errors = 0
        self.is_known_iot_port = False


@pytest.fixture
def app() -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    return app


def test_ws_live_traffic_sends_initial_snapshot(app: FastAPI) -> None:
    traffic_agent = MagicMock()
    traffic_agent.get_recent_flows.return_value = [
        DummyFlow("flow-1", datetime.now(timezone.utc)),
        DummyFlow("flow-2", datetime.now(timezone.utc)),
    ]
    app.state.agents = {"traffic": traffic_agent}

    with TestClient(app) as client:
        token = AuthService.create_access_token("analyst", "analyst")
        with client.websocket_connect(
            f"/api/v1/ws/live-traffic?token={token}"
        ) as websocket:
            msg = websocket.receive_json()
            assert msg["type"] == "snapshot"
            assert isinstance(msg["payload"], list)
            assert len(msg["payload"]) == 2
            assert msg["payload"][0]["flow_id"] == "flow-1"
            assert isinstance(msg["payload"][0]["timestamp"], str)
            traffic_agent.get_recent_flows.assert_called_once_with(limit=50)


@pytest.mark.parametrize("url,headers", [
    ("/api/v1/ws/live-traffic", None),
    ("/api/v1/ws/live-traffic?token=invalid", None),
    ("/api/v1/ws/live-traffic", [("Authorization", "Bearer invalid")]),
])
def test_ws_live_traffic_rejects_invalid_token(
    app: FastAPI, url: str, headers: list[tuple[str, str]] | None
) -> None:
    with TestClient(app) as client:
        with pytest.raises(Exception):
            client.websocket_connect(url, headers=headers)


def test_ws_live_traffic_accepts_query_token(app: FastAPI) -> None:
    traffic_agent = MagicMock()
    traffic_agent.get_recent_flows.return_value = [
        DummyFlow("flow-1", datetime.now(timezone.utc)),
    ]
    app.state.agents = {"traffic": traffic_agent}
    token = AuthService.create_access_token("analyst", "analyst")
    with TestClient(app) as client:
        with client.websocket_connect(
            f"/api/v1/ws/live-traffic?token={token}"
        ) as websocket:
            msg = websocket.receive_json()
            assert msg["type"] == "snapshot"

