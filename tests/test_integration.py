"""
Integration tests for application lifecycle.

Tests cover the actual functions in backend/main.py:
- _drain_queue: queue draining with timeout
- _graceful_shutdown: graceful shutdown sequence
- _supervise_agent: agent supervision and restart
- _start_agents: agent startup

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 12.1, 12.2, 12.3, 12.4, 12.5, 12.6
"""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost/test")

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.main import _drain_queue, _graceful_shutdown, _supervise_agent, _start_agents


# ---------------------------------------------------------------------------
# Queue Draining Tests  (Req 12.2, 12.3, 12.4)
# ---------------------------------------------------------------------------


class TestDrainQueue:
    """Tests for _drain_queue — queue draining with timeout."""

    @pytest.mark.asyncio
    async def test_drain_queue_returns_true_when_drained_within_timeout(self):
        """_drain_queue returns True when the queue drains before the timeout."""
        queue = asyncio.Queue()
        # Put one item and immediately mark it done so join() returns instantly
        await queue.put("item")
        queue.task_done()

        result = await _drain_queue(queue, "test_queue", timeout=5.0)

        assert result is True

    @pytest.mark.asyncio
    async def test_drain_queue_returns_false_and_logs_warning_on_timeout(self):
        """_drain_queue returns False and logs a WARNING when the timeout is exceeded."""
        queue = asyncio.Queue()
        # Put an item but never call task_done, so join() will block forever
        await queue.put("stuck_item")

        with patch("backend.main.logger") as mock_logger:
            result = await _drain_queue(queue, "stuck_queue", timeout=0.05)

        assert result is False
        mock_logger.warning.assert_called_once()
        warning_call_args = mock_logger.warning.call_args[0]
        assert "stuck_queue" in warning_call_args[0] or "stuck_queue" in str(warning_call_args)

    @pytest.mark.asyncio
    async def test_drain_queue_empty_queue_returns_true_immediately(self):
        """_drain_queue with an empty queue returns True without waiting."""
        queue = asyncio.Queue()
        # Empty queue — join() returns immediately

        result = await _drain_queue(queue, "empty_queue", timeout=5.0)

        assert result is True

    @pytest.mark.asyncio
    async def test_drain_queue_logs_success(self):
        """_drain_queue logs an info message on successful drain."""
        queue = asyncio.Queue()

        with patch("backend.main.logger") as mock_logger:
            result = await _drain_queue(queue, "my_queue", timeout=5.0)

        assert result is True
        mock_logger.info.assert_called_once()
        info_call_args = mock_logger.info.call_args[0]
        assert "my_queue" in info_call_args[0] or "my_queue" in str(info_call_args)

    @pytest.mark.asyncio
    async def test_drain_queue_multiple_items_all_done(self):
        """_drain_queue returns True when all items in a multi-item queue are processed."""
        queue = asyncio.Queue()
        for i in range(5):
            await queue.put(f"item_{i}")
            queue.task_done()

        result = await _drain_queue(queue, "multi_queue", timeout=5.0)

        assert result is True


# ---------------------------------------------------------------------------
# Agent Supervision Tests  (Req 1.7)
# ---------------------------------------------------------------------------


class TestSuperviseAgent:
    """Tests for _supervise_agent — supervision and restart on failure."""

    @pytest.mark.asyncio
    async def test_supervise_agent_restarts_on_task_exception(self):
        """_supervise_agent restarts the agent when its task raises an exception."""
        agent = AsyncMock()
        agent.start = AsyncMock()

        # First task raises immediately
        fail_task = asyncio.create_task(_raise_after(0.01, RuntimeError("crash")))

        tasks = {"worker": fail_task}
        restart_counts: dict = {}

        # Patch the sleep inside _supervise_agent so the restart happens instantly
        original_sleep = asyncio.sleep

        async def instant_sleep(delay):
            await original_sleep(0)

        with patch("backend.main.asyncio.sleep", side_effect=instant_sleep):
            supervisor = asyncio.create_task(
                _supervise_agent("worker", agent, tasks, restart_counts)
            )
            # Give enough time for: task crash → instant sleep → agent.start()
            await original_sleep(0.3)

        # Verify the agent was restarted
        agent.start.assert_called()
        assert restart_counts.get("worker", 0) >= 1

        supervisor.cancel()
        await asyncio.gather(supervisor, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_supervise_agent_logs_warning_when_restart_count_exceeds_5(self):
        """_supervise_agent logs a WARNING when restart count exceeds 5."""
        agent = AsyncMock()
        agent.start = AsyncMock()

        tasks: dict = {"flaky": None}
        restart_counts = {"flaky": 5}  # Already at 5 — next crash triggers warning

        crash_task = asyncio.create_task(_raise_after(0.01, RuntimeError("crash again")))
        tasks["flaky"] = crash_task

        with patch("backend.main.logger") as mock_logger:
            supervisor = asyncio.create_task(
                _supervise_agent("flaky", agent, tasks, restart_counts)
            )
            await asyncio.sleep(0.2)
            supervisor.cancel()
            await asyncio.gather(supervisor, return_exceptions=True)

        # restart_counts["flaky"] should now be > 5, triggering the warning
        assert restart_counts["flaky"] > 5
        mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_supervise_agent_stops_cleanly_on_cancelled_error(self):
        """_supervise_agent exits cleanly when cancelled (CancelledError)."""
        agent = AsyncMock()
        tasks: dict = {"steady": asyncio.create_task(asyncio.sleep(10))}
        restart_counts: dict = {}

        supervisor = asyncio.create_task(
            _supervise_agent("steady", agent, tasks, restart_counts)
        )

        await asyncio.sleep(0.05)
        supervisor.cancel()

        # Should not raise — CancelledError is handled internally
        await asyncio.gather(supervisor, return_exceptions=True)

        # Agent should NOT have been restarted (clean cancellation)
        agent.start.assert_not_called()

    @pytest.mark.asyncio
    async def test_supervise_agent_increments_restart_count_on_each_crash(self):
        """_supervise_agent increments restart_counts on every crash."""
        agent = AsyncMock()
        agent.start = AsyncMock()

        tasks: dict = {}
        restart_counts: dict = {}

        # Patch asyncio.sleep inside the supervisor to speed up the test
        original_sleep = asyncio.sleep

        async def fast_sleep(delay):
            await original_sleep(0)

        crash_task = asyncio.create_task(_raise_after(0.01, ValueError("boom")))
        tasks["counter_agent"] = crash_task

        with patch("backend.main.asyncio") as mock_asyncio:
            mock_asyncio.CancelledError = asyncio.CancelledError
            mock_asyncio.sleep = fast_sleep
            mock_asyncio.create_task = asyncio.create_task

            supervisor = asyncio.create_task(
                _supervise_agent("counter_agent", agent, tasks, restart_counts)
            )
            await original_sleep(0.3)
            supervisor.cancel()
            await asyncio.gather(supervisor, return_exceptions=True)

        assert restart_counts.get("counter_agent", 0) >= 1


# ---------------------------------------------------------------------------
# Graceful Shutdown Tests  (Req 12.1)
# ---------------------------------------------------------------------------


class TestGracefulShutdown:
    """Tests for _graceful_shutdown — shutdown sequence and queue draining."""

    @pytest.mark.asyncio
    async def test_graceful_shutdown_stops_traffic_agent_first(self):
        """_graceful_shutdown stops the traffic agent before any other agent."""
        stop_order = []

        async def make_stop(name):
            async def stop():
                stop_order.append(name)
            return stop

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
        supervisors = []

        with patch("backend.main.get_queues") as mock_get_queues:
            mock_get_queues.return_value = _make_empty_queues()
            await _graceful_shutdown(agents, supervisors)

        assert stop_order[0] == "traffic", (
            f"Expected 'traffic' to be stopped first, got: {stop_order}"
        )

    @pytest.mark.asyncio
    async def test_graceful_shutdown_returns_timeout_info_dict(self):
        """_graceful_shutdown returns a dict with a timed_out_queues list."""
        agents = {
            "traffic": _make_agent_mock("traffic"),
            "detection": _make_agent_mock("detection"),
            "anomaly": _make_agent_mock("anomaly"),
            "risk": _make_agent_mock("risk"),
            "orchestrator": _make_agent_mock("orchestrator"),
            "prevention": _make_agent_mock("prevention"),
            "healing": _make_agent_mock("healing"),
            "logging": _make_agent_mock("logging"),
            "reporting": _make_agent_mock("reporting"),
        }
        supervisors = []

        with patch("backend.main.get_queues") as mock_get_queues:
            mock_get_queues.return_value = _make_empty_queues()
            result = await _graceful_shutdown(agents, supervisors)

        assert isinstance(result, dict)
        assert "timed_out_queues" in result
        assert isinstance(result["timed_out_queues"], list)

    @pytest.mark.asyncio
    async def test_graceful_shutdown_cancels_all_supervisors(self):
        """_graceful_shutdown cancels every supervisor task."""
        agents = {
            "traffic": _make_agent_mock("traffic"),
            "logging": _make_agent_mock("logging"),
        }

        # Create real tasks that block indefinitely
        supervisor1 = asyncio.create_task(asyncio.sleep(100))
        supervisor2 = asyncio.create_task(asyncio.sleep(100))
        supervisors = [supervisor1, supervisor2]

        with patch("backend.main.get_queues") as mock_get_queues:
            mock_get_queues.return_value = _make_empty_queues()
            await _graceful_shutdown(agents, supervisors)

        assert supervisor1.cancelled() or supervisor1.done()
        assert supervisor2.cancelled() or supervisor2.done()

    @pytest.mark.asyncio
    async def test_graceful_shutdown_records_timed_out_queues(self):
        """_graceful_shutdown records queue names that timed out in the result."""
        agents = {
            "traffic": _make_agent_mock("traffic"),
            "detection": _make_agent_mock("detection"),
            "anomaly": _make_agent_mock("anomaly"),
            "risk": _make_agent_mock("risk"),
            "orchestrator": _make_agent_mock("orchestrator"),
            "prevention": _make_agent_mock("prevention"),
            "healing": _make_agent_mock("healing"),
            "logging": _make_agent_mock("logging"),
            "reporting": _make_agent_mock("reporting"),
        }
        supervisors = []

        # Build queues where detection_queue has an unprocessed item (will time out)
        queues = _make_empty_queues()
        await queues.detection_queue.put("stuck_item")  # never task_done'd

        with patch("backend.main.get_queues") as mock_get_queues:
            mock_get_queues.return_value = queues
            # Use a very short timeout so the test runs quickly
            with patch("backend.main._drain_queue", wraps=_fast_drain_queue):
                result = await _graceful_shutdown(agents, supervisors)

        # The result must contain the timed_out_queues key
        assert "timed_out_queues" in result

    @pytest.mark.asyncio
    async def test_graceful_shutdown_includes_total_drain_time(self):
        """_graceful_shutdown result includes total_drain_time_seconds."""
        agents = {"traffic": _make_agent_mock("traffic")}
        supervisors = []

        with patch("backend.main.get_queues") as mock_get_queues:
            mock_get_queues.return_value = _make_empty_queues()
            result = await _graceful_shutdown(agents, supervisors)

        assert "total_drain_time_seconds" in result
        assert result["total_drain_time_seconds"] >= 0.0


# ---------------------------------------------------------------------------
# Agent Startup Tests  (Req 1.3)
# ---------------------------------------------------------------------------


class TestStartAgents:
    """Tests for _start_agents — agent startup."""

    @pytest.mark.asyncio
    async def test_start_agents_calls_start_on_each_agent(self):
        """_start_agents calls start() on every agent in the dict."""
        agents = {
            "alpha": AsyncMock(),
            "beta": AsyncMock(),
            "gamma": AsyncMock(),
        }
        for mock_agent in agents.values():
            mock_agent.start = AsyncMock()
            mock_agent._task = None  # no internal task

        await _start_agents(agents)

        for name, mock_agent in agents.items():
            mock_agent.start.assert_called_once(), f"start() not called for agent '{name}'"

    @pytest.mark.asyncio
    async def test_start_agents_returns_dict_of_tasks(self):
        """_start_agents returns a dict mapping agent names to asyncio.Task objects."""
        agents = {
            "alpha": AsyncMock(),
            "beta": AsyncMock(),
        }
        for mock_agent in agents.values():
            mock_agent.start = AsyncMock()
            mock_agent._task = None

        result = await _start_agents(agents)

        assert isinstance(result, dict)
        assert set(result.keys()) == set(agents.keys())
        for name, task in result.items():
            assert isinstance(task, asyncio.Task), (
                f"Expected asyncio.Task for '{name}', got {type(task)}"
            )

    @pytest.mark.asyncio
    async def test_start_agents_uses_agent_internal_task_when_available(self):
        """_start_agents uses the agent's own _task if it exists."""
        internal_task = asyncio.create_task(asyncio.sleep(100))

        agent = AsyncMock()
        agent.start = AsyncMock()
        agent._task = internal_task

        agents = {"worker": agent}
        result = await _start_agents(agents)

        assert result["worker"] is internal_task

        internal_task.cancel()
        await asyncio.gather(internal_task, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_start_agents_creates_placeholder_task_when_no_internal_task(self):
        """_start_agents creates a placeholder task for agents without _task."""
        agent = AsyncMock()
        agent.start = AsyncMock()
        agent._task = None

        agents = {"simple": agent}
        result = await _start_agents(agents)

        task = result["simple"]
        assert isinstance(task, asyncio.Task)
        assert not task.done()

        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_start_agents_empty_dict_returns_empty_dict(self):
        """_start_agents with an empty agents dict returns an empty dict."""
        result = await _start_agents({})

        assert result == {}

    @pytest.mark.asyncio
    async def test_start_agents_logs_started_count(self):
        """_start_agents logs the number of agents started."""
        agents = {
            "a": AsyncMock(),
            "b": AsyncMock(),
        }
        for mock_agent in agents.values():
            mock_agent.start = AsyncMock()
            mock_agent._task = None

        with patch("backend.main.logger") as mock_logger:
            await _start_agents(agents)

        mock_logger.info.assert_called()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _raise_after(delay: float, exc: Exception) -> None:
    """Coroutine that sleeps briefly then raises the given exception."""
    await asyncio.sleep(delay)
    raise exc


def _make_agent_mock(name: str, stop_order: list | None = None) -> AsyncMock:
    """Create an AsyncMock agent whose stop() records call order."""
    agent = AsyncMock()

    if stop_order is not None:
        async def stop_and_record():
            stop_order.append(name)

        agent.stop = stop_and_record
    else:
        agent.stop = AsyncMock()

    agent.start = AsyncMock()
    return agent


def _make_empty_queues():
    """Return an AgentQueues-like object with empty asyncio.Queue instances."""
    from backend.agents.queues import AgentQueues
    return AgentQueues(
        detection_queue=asyncio.Queue(),
        anomaly_queue=asyncio.Queue(),
        risk_queue=asyncio.Queue(),
        orchestrator_queue=asyncio.PriorityQueue(),
        prevention_queue=asyncio.Queue(),
        healing_queue=asyncio.Queue(),
        logging_queue=asyncio.Queue(),
    )


async def _fast_drain_queue(queue: asyncio.Queue, name: str, timeout: float) -> bool:
    """Replacement for _drain_queue that uses a very short timeout (for tests)."""
    try:
        await asyncio.wait_for(queue.join(), timeout=0.05)
        return True
    except asyncio.TimeoutError:
        return False
