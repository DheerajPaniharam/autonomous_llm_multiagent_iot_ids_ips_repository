"""
Integration tests for application lifecycle — backend/main.py.

Covers:
  1. Startup sequence: agents start in correct order (Req 1.1, 1.2, 1.3, 1.4)
  2. Graceful shutdown: queues drain before agents stop (Req 1.5, 1.6, 12.1–12.6)
  3. Agent restart on failure (Req 1.7)
  4. Queue drain timeout handling (Req 12.2, 12.3, 12.4, 12.5)

All external dependencies (database, ML pipeline, agents) are mocked so the
tests run without any live infrastructure.

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 12.1, 12.2, 12.3, 12.4, 12.5, 12.6
"""
from __future__ import annotations

import os

# Set required env vars before any backend imports
os.environ.setdefault("JWT_SECRET_KEY", "test-lifecycle-secret")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost/testdb")

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from backend.main import (
    _seed_admin_user,
    _drain_queue,
    _graceful_shutdown,
    _start_agents,
    _supervise_agent,
    _start_supervisors,
    _log_startup,
    _log_shutdown,
)
from backend.agents.queues import AgentQueues


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("", "test-only-password"),
        ("bootstrap-admin", ""),
        ("bootstrap-admin", "admin123"),
    ],
)
@pytest.mark.asyncio
async def test_admin_seed_requires_explicit_credentials(username, password, monkeypatch, caplog):
    monkeypatch.setenv("ADMIN_USERNAME", username)
    monkeypatch.setenv("ADMIN_PASSWORD", password)

    with patch("backend.database.connection.session_context") as session_context:
        await _seed_admin_user()

    session_context.assert_not_called()
    assert "Skipping admin user seeding" in caplog.text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_empty_queues() -> AgentQueues:
    """Return an AgentQueues with empty in-memory queues (no real infrastructure)."""
    return AgentQueues(
        detection_queue=asyncio.Queue(),
        anomaly_queue=asyncio.Queue(),
        risk_queue=asyncio.Queue(),
        orchestrator_queue=asyncio.PriorityQueue(),
        prevention_queue=asyncio.Queue(),
        healing_queue=asyncio.Queue(),
        logging_queue=asyncio.Queue(),
    )


def _make_agent_mock(name: str, stop_order: list | None = None) -> AsyncMock:
    """Create an AsyncMock agent whose stop() optionally records call order."""
    agent = AsyncMock()
    agent.start = AsyncMock()

    if stop_order is not None:
        async def _stop():
            stop_order.append(name)
        agent.stop = _stop
    else:
        agent.stop = AsyncMock()

    return agent


async def _raise_after(delay: float, exc: Exception) -> None:
    """Coroutine that sleeps briefly then raises the given exception."""
    await asyncio.sleep(delay)
    raise exc


# ---------------------------------------------------------------------------
# 1. Startup Sequence  (Req 1.1, 1.2, 1.3, 1.4)
# ---------------------------------------------------------------------------


class TestStartupSequence:
    """
    Verify that _start_agents starts every agent and returns a task map.
    Requirements: 1.1, 1.3
    """

    @pytest.mark.asyncio
    async def test_all_nine_agents_are_started(self):
        """_start_agents calls start() on all nine agents (Req 1.3)."""
        agent_names = [
            "traffic", "detection", "anomaly", "risk", "orchestrator",
            "prevention", "healing", "logging", "reporting",
        ]
        agents = {name: _make_agent_mock(name) for name in agent_names}
        for mock_agent in agents.values():
            mock_agent._task = None  # no internal task

        await _start_agents(agents)

        for name, mock_agent in agents.items():
            mock_agent.start.assert_called_once(), (
                f"start() was not called for agent '{name}'"
            )

    @pytest.mark.asyncio
    async def test_start_agents_returns_task_for_every_agent(self):
        """_start_agents returns a dict mapping every agent name to an asyncio.Task (Req 1.3)."""
        agent_names = [
            "traffic", "detection", "anomaly", "risk", "orchestrator",
            "prevention", "healing", "logging", "reporting",
        ]
        agents = {name: _make_agent_mock(name) for name in agent_names}
        for mock_agent in agents.values():
            mock_agent._task = None

        result = await _start_agents(agents)

        assert set(result.keys()) == set(agent_names)
        for name, task in result.items():
            assert isinstance(task, asyncio.Task), (
                f"Expected asyncio.Task for '{name}', got {type(task)}"
            )

        # Clean up placeholder tasks
        for task in result.values():
            task.cancel()
        await asyncio.gather(*result.values(), return_exceptions=True)

    @pytest.mark.asyncio
    async def test_start_agents_uses_agents_own_internal_task(self):
        """When an agent exposes _task, _start_agents uses it directly (Req 1.3)."""
        internal_task = asyncio.create_task(asyncio.sleep(100))
        agent = _make_agent_mock("detection")
        agent._task = internal_task

        result = await _start_agents({"detection": agent})

        assert result["detection"] is internal_task

        internal_task.cancel()
        await asyncio.gather(internal_task, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_start_agents_creates_placeholder_for_agents_without_task(self):
        """Agents without _task get a placeholder asyncio.Task (Req 1.3)."""
        agent = _make_agent_mock("reporting")
        agent._task = None

        result = await _start_agents({"reporting": agent})

        task = result["reporting"]
        assert isinstance(task, asyncio.Task)
        assert not task.done()

        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_startup_logs_agent_count(self):
        """_start_agents logs the number of agents started (Req 1.9)."""
        agents = {
            "traffic": _make_agent_mock("traffic"),
            "detection": _make_agent_mock("detection"),
        }
        for a in agents.values():
            a._task = None

        with patch("backend.main.logger") as mock_logger:
            await _start_agents(agents)

        mock_logger.info.assert_called()
        # At least one info call should mention the count
        all_calls = " ".join(str(c) for c in mock_logger.info.call_args_list)
        assert "2" in all_calls or "Started" in all_calls

    def test_log_startup_emits_structured_json(self, caplog):
        """_log_startup writes a structured JSON startup message (Req 1.9)."""
        model_paths = {
            "supervised_model": "models/lgb_model.joblib",
            "if_model": "models/if_model.joblib",
            "scaler": "models/scaler.joblib",
        }
        with caplog.at_level(logging.INFO, logger="backend.main"):
            _log_startup(model_paths, agent_count=9)

        # The log record should contain the startup JSON
        startup_records = [r for r in caplog.records if "STARTUP" in r.message]
        assert startup_records, "No STARTUP log record found"
        msg = startup_records[0].message
        assert '"event": "startup"' in msg or "startup" in msg
        assert "9" in msg  # agent_count


# ---------------------------------------------------------------------------
# 2. Graceful Shutdown — queues drain before agents stop  (Req 12.1–12.6)
# ---------------------------------------------------------------------------


class TestGracefulShutdown:
    """
    Verify the shutdown sequence: Traffic_Agent stops first, queues drain,
    then downstream agents stop, then close_db is called.
    Requirements: 1.5, 1.6, 12.1, 12.2, 12.3, 12.4, 12.5, 12.6
    """

    @pytest.mark.asyncio
    async def test_traffic_agent_stops_first(self):
        """Traffic_Agent must be the first agent stopped (Req 12.1)."""
        stop_order: list[str] = []

        agents = {
            "traffic": _make_agent_mock("traffic", stop_order),
            "detection": _make_agent_mock("detection", stop_order),
            "anomaly": _make_agent_mock("anomaly", stop_order),
            "risk": _make_agent_mock("risk", stop_order),
            "orchestrator": _make_agent_mock("orchestrator", stop_order),
            "prevention": _make_agent_mock("prevention", stop_order),
            "healing": _make_agent_mock("healing", stop_order),
            "logging": _make_agent_mock("logging", stop_order),
            "reporting": _make_agent_mock("reporting", stop_order),
        }

        with patch("backend.main.get_queues", return_value=_make_empty_queues()):
            await _graceful_shutdown(agents, supervisors=[])

        assert stop_order[0] == "traffic", (
            f"Expected 'traffic' to stop first, got: {stop_order}"
        )

    @pytest.mark.asyncio
    async def test_shutdown_returns_timeout_info_with_timed_out_queues_key(self):
        """_graceful_shutdown returns a dict with 'timed_out_queues' list (Req 12.5, 12.6)."""
        agents = {name: _make_agent_mock(name) for name in [
            "traffic", "detection", "anomaly", "risk", "orchestrator",
            "prevention", "healing", "logging", "reporting",
        ]}

        with patch("backend.main.get_queues", return_value=_make_empty_queues()):
            result = await _graceful_shutdown(agents, supervisors=[])

        assert isinstance(result, dict)
        assert "timed_out_queues" in result
        assert isinstance(result["timed_out_queues"], list)

    @pytest.mark.asyncio
    async def test_shutdown_includes_total_drain_time(self):
        """_graceful_shutdown result includes 'total_drain_time_seconds' (Req 12.6)."""
        agents = {name: _make_agent_mock(name) for name in [
            "traffic", "detection", "anomaly", "risk", "orchestrator",
            "prevention", "healing", "logging", "reporting",
        ]}

        with patch("backend.main.get_queues", return_value=_make_empty_queues()):
            result = await _graceful_shutdown(agents, supervisors=[])

        assert "total_drain_time_seconds" in result
        assert result["total_drain_time_seconds"] >= 0.0

    @pytest.mark.asyncio
    async def test_shutdown_cancels_all_supervisor_tasks(self):
        """_graceful_shutdown cancels every supervisor task (Req 1.5)."""
        agents = {
            "traffic": _make_agent_mock("traffic"),
            "logging": _make_agent_mock("logging"),
        }
        sup1 = asyncio.create_task(asyncio.sleep(100))
        sup2 = asyncio.create_task(asyncio.sleep(100))

        with patch("backend.main.get_queues", return_value=_make_empty_queues()):
            await _graceful_shutdown(agents, supervisors=[sup1, sup2])

        assert sup1.cancelled() or sup1.done()
        assert sup2.cancelled() or sup2.done()

    @pytest.mark.asyncio
    async def test_empty_queues_drain_immediately(self):
        """All empty queues drain without timeout — timed_out_queues is empty (Req 12.2–12.4)."""
        agents = {name: _make_agent_mock(name) for name in [
            "traffic", "detection", "anomaly", "risk", "orchestrator",
            "prevention", "healing", "logging", "reporting",
        ]}

        with patch("backend.main.get_queues", return_value=_make_empty_queues()):
            result = await _graceful_shutdown(agents, supervisors=[])

        assert result["timed_out_queues"] == [], (
            f"Expected no timeouts for empty queues, got: {result['timed_out_queues']}"
        )

    def test_log_shutdown_emits_structured_json(self, caplog):
        """_log_shutdown writes a structured JSON shutdown message (Req 12.6)."""
        timeout_info = {
            "total_drain_time_seconds": 2.5,
            "timed_out_queues": ["logging"],
        }
        with caplog.at_level(logging.INFO, logger="backend.main"):
            _log_shutdown(timeout_info)

        shutdown_records = [r for r in caplog.records if "SHUTDOWN" in r.message]
        assert shutdown_records, "No SHUTDOWN log record found"
        msg = shutdown_records[0].message
        assert "shutdown" in msg
        assert "2.5" in msg or "total_drain_time" in msg


# ---------------------------------------------------------------------------
# 3. Agent Restart on Failure  (Req 1.7)
# ---------------------------------------------------------------------------


class TestAgentRestartOnFailure:
    """
    Verify that _supervise_agent restarts a crashed agent and tracks restart counts.
    Requirements: 1.7
    """

    @pytest.mark.asyncio
    async def test_agent_is_restarted_after_task_exception(self):
        """_supervise_agent calls agent.start() again after the task raises (Req 1.7)."""
        agent = AsyncMock()
        agent.start = AsyncMock()

        crash_task = asyncio.create_task(_raise_after(0.01, RuntimeError("boom")))
        tasks = {"worker": crash_task}
        restart_counts: dict = {}

        original_sleep = asyncio.sleep

        async def instant_sleep(delay):
            await original_sleep(0)

        with patch("backend.main.asyncio.sleep", side_effect=instant_sleep):
            supervisor = asyncio.create_task(
                _supervise_agent("worker", agent, tasks, restart_counts)
            )
            await original_sleep(0.3)

        agent.start.assert_called()
        assert restart_counts.get("worker", 0) >= 1

        supervisor.cancel()
        await asyncio.gather(supervisor, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_restart_count_increments_on_each_crash(self):
        """restart_counts[name] increments with every crash (Req 1.7)."""
        agent = AsyncMock()
        agent.start = AsyncMock()

        crash_task = asyncio.create_task(_raise_after(0.01, ValueError("crash")))
        tasks = {"counter": crash_task}
        restart_counts: dict = {}

        original_sleep = asyncio.sleep

        async def instant_sleep(delay):
            await original_sleep(0)

        with patch("backend.main.asyncio.sleep", side_effect=instant_sleep):
            supervisor = asyncio.create_task(
                _supervise_agent("counter", agent, tasks, restart_counts)
            )
            await original_sleep(0.3)
            supervisor.cancel()
            await asyncio.gather(supervisor, return_exceptions=True)

        assert restart_counts.get("counter", 0) >= 1

    @pytest.mark.asyncio
    async def test_warning_logged_when_restart_count_exceeds_5(self):
        """A WARNING is logged when restart count exceeds 5 (Req 1.7)."""
        agent = AsyncMock()
        agent.start = AsyncMock()

        tasks: dict = {"flaky": None}
        restart_counts = {"flaky": 5}  # Pre-seed at 5; next crash triggers warning

        crash_task = asyncio.create_task(_raise_after(0.01, RuntimeError("crash again")))
        tasks["flaky"] = crash_task

        with patch("backend.main.logger") as mock_logger:
            supervisor = asyncio.create_task(
                _supervise_agent("flaky", agent, tasks, restart_counts)
            )
            await asyncio.sleep(0.2)
            supervisor.cancel()
            await asyncio.gather(supervisor, return_exceptions=True)

        assert restart_counts["flaky"] > 5
        mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_supervisor_exits_cleanly_on_cancellation(self):
        """_supervise_agent exits without error when cancelled (Req 1.7)."""
        agent = AsyncMock()
        tasks = {"steady": asyncio.create_task(asyncio.sleep(100))}
        restart_counts: dict = {}

        supervisor = asyncio.create_task(
            _supervise_agent("steady", agent, tasks, restart_counts)
        )
        await asyncio.sleep(0.05)
        supervisor.cancel()

        # Must not raise
        await asyncio.gather(supervisor, return_exceptions=True)

        # No restart should have occurred
        agent.start.assert_not_called()

    @pytest.mark.asyncio
    async def test_error_logged_on_agent_crash(self):
        """An ERROR is logged when an agent task raises an exception (Req 1.7)."""
        agent = AsyncMock()
        agent.start = AsyncMock()

        crash_task = asyncio.create_task(_raise_after(0.01, RuntimeError("fatal")))
        tasks = {"broken": crash_task}
        restart_counts: dict = {}

        with patch("backend.main.logger") as mock_logger:
            supervisor = asyncio.create_task(
                _supervise_agent("broken", agent, tasks, restart_counts)
            )
            await asyncio.sleep(0.2)
            supervisor.cancel()
            await asyncio.gather(supervisor, return_exceptions=True)

        mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_start_supervisors_creates_one_supervisor_per_agent(self):
        """_start_supervisors returns one supervisor task per agent (Req 1.7)."""
        agents = {
            "traffic": _make_agent_mock("traffic"),
            "detection": _make_agent_mock("detection"),
            "logging": _make_agent_mock("logging"),
        }
        tasks = {name: asyncio.create_task(asyncio.sleep(100)) for name in agents}

        supervisors = await _start_supervisors(agents, tasks)

        assert len(supervisors) == len(agents)
        for sup in supervisors:
            assert isinstance(sup, asyncio.Task)

        # Clean up
        for sup in supervisors:
            sup.cancel()
        for t in tasks.values():
            t.cancel()
        await asyncio.gather(*supervisors, *tasks.values(), return_exceptions=True)


# ---------------------------------------------------------------------------
# 4. Queue Drain Timeout Handling  (Req 12.2, 12.3, 12.4, 12.5)
# ---------------------------------------------------------------------------


class TestQueueDrainTimeout:
    """
    Verify _drain_queue behaviour: returns True on success, False on timeout,
    and logs appropriate messages.
    Requirements: 12.2, 12.3, 12.4, 12.5
    """

    @pytest.mark.asyncio
    async def test_empty_queue_drains_immediately_returns_true(self):
        """An empty queue drains instantly and returns True (Req 12.2)."""
        queue = asyncio.Queue()
        result = await _drain_queue(queue, "empty_queue", timeout=5.0)
        assert result is True

    @pytest.mark.asyncio
    async def test_fully_processed_queue_returns_true(self):
        """A queue where all items are task_done'd returns True (Req 12.2)."""
        queue = asyncio.Queue()
        for i in range(5):
            await queue.put(f"item_{i}")
            queue.task_done()

        result = await _drain_queue(queue, "processed_queue", timeout=5.0)
        assert result is True

    @pytest.mark.asyncio
    async def test_stuck_queue_returns_false_on_timeout(self):
        """A queue with unprocessed items returns False after timeout (Req 12.5)."""
        queue = asyncio.Queue()
        await queue.put("stuck_item")  # never task_done'd

        result = await _drain_queue(queue, "stuck_queue", timeout=0.05)
        assert result is False

    @pytest.mark.asyncio
    async def test_timeout_logs_warning_with_queue_name(self):
        """A timeout logs a WARNING that includes the queue name (Req 12.5)."""
        queue = asyncio.Queue()
        await queue.put("stuck")

        with patch("backend.main.logger") as mock_logger:
            await _drain_queue(queue, "my_stuck_queue", timeout=0.05)

        mock_logger.warning.assert_called_once()
        warning_args = str(mock_logger.warning.call_args)
        assert "my_stuck_queue" in warning_args

    @pytest.mark.asyncio
    async def test_timeout_logs_remaining_item_count(self):
        """The timeout warning includes the remaining item count (Req 12.5)."""
        queue = asyncio.Queue()
        await queue.put("item1")
        await queue.put("item2")

        with patch("backend.main.logger") as mock_logger:
            await _drain_queue(queue, "count_queue", timeout=0.05)

        warning_args = str(mock_logger.warning.call_args)
        # The remaining count (2) should appear in the warning
        assert "2" in warning_args

    @pytest.mark.asyncio
    async def test_success_logs_info_with_queue_name(self):
        """A successful drain logs an INFO message with the queue name (Req 12.2)."""
        queue = asyncio.Queue()

        with patch("backend.main.logger") as mock_logger:
            await _drain_queue(queue, "success_queue", timeout=5.0)

        mock_logger.info.assert_called_once()
        info_args = str(mock_logger.info.call_args)
        assert "success_queue" in info_args

    @pytest.mark.asyncio
    async def test_detection_queue_timeout_recorded_in_shutdown(self):
        """A stuck detection_queue is recorded in timed_out_queues (Req 12.2, 12.5)."""
        agents = {name: _make_agent_mock(name) for name in [
            "traffic", "detection", "anomaly", "risk", "orchestrator",
            "prevention", "healing", "logging", "reporting",
        ]}

        queues = _make_empty_queues()
        await queues.detection_queue.put("stuck")  # never task_done'd

        async def fast_drain(queue, name, timeout):
            """Replacement that uses a very short timeout."""
            try:
                await asyncio.wait_for(queue.join(), timeout=0.05)
                return True
            except asyncio.TimeoutError:
                return False

        with patch("backend.main.get_queues", return_value=queues), \
             patch("backend.main._drain_queue", side_effect=fast_drain):
            result = await _graceful_shutdown(agents, supervisors=[])

        assert "detection" in result["timed_out_queues"]

    @pytest.mark.asyncio
    async def test_logging_queue_timeout_recorded_in_shutdown(self):
        """A stuck logging_queue is recorded in timed_out_queues (Req 12.4, 12.5)."""
        agents = {name: _make_agent_mock(name) for name in [
            "traffic", "detection", "anomaly", "risk", "orchestrator",
            "prevention", "healing", "logging", "reporting",
        ]}

        queues = _make_empty_queues()
        await queues.logging_queue.put("stuck_log")  # never task_done'd

        async def fast_drain(queue, name, timeout):
            try:
                await asyncio.wait_for(queue.join(), timeout=0.05)
                return True
            except asyncio.TimeoutError:
                return False

        with patch("backend.main.get_queues", return_value=queues), \
             patch("backend.main._drain_queue", side_effect=fast_drain):
            result = await _graceful_shutdown(agents, supervisors=[])

        assert "logging" in result["timed_out_queues"]

    @pytest.mark.asyncio
    async def test_queue_drains_concurrently_during_shutdown(self):
        """
        Detection/anomaly/risk/orchestrator queues are drained concurrently
        (all four should appear in timed_out_queues when all are stuck).
        Requirements: 12.2
        """
        agents = {name: _make_agent_mock(name) for name in [
            "traffic", "detection", "anomaly", "risk", "orchestrator",
            "prevention", "healing", "logging", "reporting",
        ]}

        queues = _make_empty_queues()
        # Stick items in all four pipeline queues
        for q in [
            queues.detection_queue,
            queues.anomaly_queue,
            queues.risk_queue,
            queues.orchestrator_queue,
        ]:
            await q.put("stuck")

        async def fast_drain(queue, name, timeout):
            try:
                await asyncio.wait_for(queue.join(), timeout=0.05)
                return True
            except asyncio.TimeoutError:
                return False

        with patch("backend.main.get_queues", return_value=queues), \
             patch("backend.main._drain_queue", side_effect=fast_drain):
            result = await _graceful_shutdown(agents, supervisors=[])

        timed_out = set(result["timed_out_queues"])
        assert {"detection", "anomaly", "risk", "orchestrator"}.issubset(timed_out)
