from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

from backend.agents.response_agent import ResponseAgent
from backend.models.messages import MitigationCommand


def test_rate_limit_passes_command_ttl_to_firewall(monkeypatch):
    agent = ResponseAgent()
    rate_limit = AsyncMock(return_value="rule-123")
    monkeypatch.setattr(agent, "is_whitelisted", lambda _ip: False)
    monkeypatch.setattr(agent, "rate_limit", rate_limit)
    monkeypatch.setattr(agent, "_log_action", AsyncMock())
    monkeypatch.setattr(agent, "_persist_mitigation", AsyncMock())
    monkeypatch.setattr("backend.agents.response_agent.increment_mitigations", lambda _action: None)
    monkeypatch.setattr("backend.agents.response_agent.increment_events_processed", lambda _agent: None)

    command = MitigationCommand(
        action="rate_limit",
        target_ip="192.0.2.15",
        ttl_seconds=321,
    )

    result = asyncio.run(agent._execute_mitigation(command))

    assert result == "rule-123"
    rate_limit.assert_awaited_once_with("192.0.2.15", ttl_seconds=321)