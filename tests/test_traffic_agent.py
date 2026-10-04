from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from backend.agents import traffic_agent
from backend.agents.traffic_agent import TrafficAgent
from backend.models.messages import FeatureVector


def test_resolve_log_path_falls_back_to_existing_candidate(tmp_path: Path, monkeypatch) -> None:
    fallback_log = tmp_path / "conn.log"
    fallback_log.write_text("#separator \t\n#fields ts uid\n", encoding="utf-8")

    monkeypatch.setenv("ZEEK_LOG_PATH", "/tmp/does-not-exist/conn.log")

    resolved = traffic_agent.resolve_log_path(
        "/tmp/does-not-exist/conn.log",
        [str(fallback_log)],
    )

    assert resolved == str(fallback_log)


def test_resolve_log_path_expands_zeek_log_directory(tmp_path: Path) -> None:
    current_dir = tmp_path / "current"
    current_dir.mkdir()
    conn_log = current_dir / "conn.log"
    conn_log.write_text("#separator \\t\n#fields ts uid\n", encoding="utf-8")

    resolved = traffic_agent.resolve_log_path(str(tmp_path))

    assert resolved == str(conn_log)


def test_publish_adds_flow_to_recent_history(monkeypatch) -> None:
    agent = TrafficAgent()

    async def fake_safe_put(*args, **kwargs):
        return True

    monkeypatch.setattr("backend.agents.traffic_agent.safe_put", fake_safe_put)
    monkeypatch.setattr(
        "backend.agents.traffic_agent.get_queues",
        lambda: SimpleNamespace(
            detection_queue=SimpleNamespace(),
            anomaly_queue=SimpleNamespace(),
        ),
    )

    fv = FeatureVector(
        flow_id="flow-1",
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        packet_rate=10.0,
        byte_rate=1000.0,
        flow_duration=1.0,
        tcp_flags="S",
        connection_errors=0,
        port_entropy=1.2,
        is_known_iot_port=False,
    )

    import asyncio

    asyncio.run(agent._publish(fv))

    assert agent.get_recent_flows(limit=10) == [fv]
