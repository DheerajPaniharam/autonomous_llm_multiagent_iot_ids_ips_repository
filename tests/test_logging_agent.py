from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from backend.agents.observability_agent import ObservabilityAgent
from backend.models.messages import LogEntry


@pytest.fixture
def sample_entry() -> LogEntry:
    return LogEntry(
        level="info",
        source_agent="test_agent",
        event_type="test_event",
        payload={"foo": "bar"},
        timestamp=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
@patch("backend.agents.observability_agent.write_log_entry", new_callable=AsyncMock)
@patch("backend.agents.observability_agent.write_to_log_file", new_callable=AsyncMock)
async def test_log_event_success(mock_send: AsyncMock, mock_write: AsyncMock, sample_entry: LogEntry) -> None:
    agent = ObservabilityAgent()
    mock_send.return_value = True

    await agent.log_event(sample_entry)

    mock_write.assert_awaited_once_with(sample_entry)
    mock_send.assert_awaited_once_with(sample_entry)
    assert len(agent._buffer) == 0
    assert len(agent._file_buffer) == 0


@pytest.mark.asyncio
@patch("backend.agents.observability_agent.write_log_entry", new_callable=AsyncMock)
@patch("backend.agents.observability_agent.write_to_log_file", new_callable=AsyncMock)
async def test_log_event_db_failure(mock_send: AsyncMock, mock_write: AsyncMock, sample_entry: LogEntry) -> None:
    agent = ObservabilityAgent()
    mock_write.side_effect = RuntimeError("DB down")
    mock_send.return_value = True

    await agent.log_event(sample_entry)

    mock_write.assert_awaited_once_with(sample_entry)
    assert len(agent._buffer) == 1
    mock_send.assert_awaited_once_with(sample_entry)
    assert len(agent._file_buffer) == 0


@pytest.mark.asyncio
@patch("backend.agents.observability_agent.write_log_entry", new_callable=AsyncMock)
@patch("backend.agents.observability_agent.write_to_log_file", new_callable=AsyncMock)
async def test_log_event_file_failure(mock_send: AsyncMock, mock_write: AsyncMock, sample_entry: LogEntry) -> None:
    agent = ObservabilityAgent()
    mock_send.side_effect = RuntimeError("Disk error")

    await agent.log_event(sample_entry)

    mock_write.assert_awaited_once_with(sample_entry)
    mock_send.assert_awaited_once_with(sample_entry)
    assert len(agent._buffer) == 0
    assert len(agent._file_buffer) == 1


@pytest.mark.asyncio
@patch("backend.agents.observability_agent.write_log_entry", new_callable=AsyncMock)
@patch("backend.agents.observability_agent.write_to_log_file", new_callable=AsyncMock)
async def test_flush_buffer_db_only(mock_send: AsyncMock, mock_write: AsyncMock, sample_entry: LogEntry) -> None:
    agent = ObservabilityAgent()
    agent._buffer.append(sample_entry)
    mock_send.return_value = True

    await agent._flush_buffer()

    mock_write.assert_awaited_once_with(sample_entry)
    mock_send.assert_awaited_once_with(sample_entry)
    assert len(agent._buffer) == 0
    assert len(agent._file_buffer) == 0


@pytest.mark.asyncio
@patch("backend.agents.observability_agent.write_log_entry", new_callable=AsyncMock)
@patch("backend.agents.observability_agent.write_to_log_file", new_callable=AsyncMock)
async def test_flush_buffer_file_only(mock_send: AsyncMock, mock_write: AsyncMock, sample_entry: LogEntry) -> None:
    agent = ObservabilityAgent()
    agent._file_buffer.append(sample_entry)
    mock_send.return_value = True

    await agent._flush_buffer()

    mock_write.assert_not_called()
    mock_send.assert_awaited_once_with(sample_entry)
    assert len(agent._buffer) == 0
    assert len(agent._file_buffer) == 0


@pytest.mark.asyncio
@patch("backend.agents.observability_agent.write_log_entry", new_callable=AsyncMock)
@patch("backend.agents.observability_agent.write_to_log_file", new_callable=AsyncMock)
async def test_flush_buffer_both_fail(mock_send: AsyncMock, mock_write: AsyncMock, sample_entry: LogEntry) -> None:
    agent = ObservabilityAgent()
    agent._buffer.append(sample_entry)
    agent._file_buffer.append(sample_entry)
    
    mock_write.side_effect = RuntimeError("DB down")
    mock_send.side_effect = RuntimeError("Disk error")

    await agent._flush_buffer()

    assert len(agent._buffer) == 1
    assert len(agent._file_buffer) == 1
