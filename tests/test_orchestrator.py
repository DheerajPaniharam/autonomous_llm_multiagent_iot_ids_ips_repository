"""
Integration tests for LLMOrchestrator.
Tests incident creation, conflict resolution, fallback behavior, and campaign correlation.
"""
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
import pytest

from backend.agents.orchestrator import LLMOrchestrator, rule_based_fallback
from backend.agents.queues import get_queues, AgentQueues, safe_put
from backend.models.messages import (
    AttackEvent, FeatureVector, MitigationCommand, LogEntry, IncidentState
)


@pytest.fixture
def queues():
    """Create fresh queues for each test."""
    # Reset the global queues singleton
    import backend.agents.queues as queues_module
    queues_module._queues = None
    return get_queues()


@pytest.fixture
def orchestrator():
    """Create a fresh LLMOrchestrator instance."""
    return LLMOrchestrator()


@pytest.fixture
def sample_feature_vector():
    """Create a sample FeatureVector for testing."""
    return FeatureVector(
        flow_id="test_flow_123",
        timestamp=datetime.utcnow(),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.50",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        packet_rate=100.0,
        byte_rate=50000.0,
        flow_duration=5.0,
        tcp_flags="PA",
        connection_errors=0,
        port_entropy=0.5,
        is_known_iot_port=False,
    )


def create_attack_event(
    composite_score: float,
    attack_type: str = "port_scan",
    feature_vector: FeatureVector = None,
) -> AttackEvent:
    """Helper to create AttackEvent with specified score."""
    if feature_vector is None:
        feature_vector = FeatureVector(
            flow_id=f"flow_{composite_score}",
            timestamp=datetime.utcnow(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.50",
            src_port=54321,
            dst_port=80,
            protocol="TCP",
            packet_rate=100.0,
            byte_rate=50000.0,
            flow_duration=5.0,
            tcp_flags="PA",
            connection_errors=0,
            port_entropy=0.5,
            is_known_iot_port=False,
        )
    
    return AttackEvent(
        flow_id=feature_vector.flow_id,
        feature_vector=feature_vector,
        lightgbm_score=composite_score * 0.6,
        if_score=composite_score * 0.4,
        composite_score=composite_score,
        attack_type=attack_type,
        timestamp=datetime.utcnow(),
    )


# ---------------------------------------------------------------------------
# Test: Requirement 10.1 - High severity incident creation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_high_severity_creates_critical_incident(orchestrator, queues):
    """
    WHEN the LLMOrchestrator receives an AttackEvent with composite_score >= 0.9,
    THEN it SHALL create an Incident record with severity="critical" and state="detected".
    Validates: Requirements 10.1
    """
    # Create high-severity attack event
    event = create_attack_event(composite_score=0.95, attack_type="ddos")
    
    # Mock LLM to return None (force fallback)
    with patch("backend.agents.orchestrator.analyze_threat", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = None
        
        # Handle the event
        await orchestrator.handle_attack_event(event)
    
    # Verify incident was created
    assert len(orchestrator._incidents) == 1
    incident = list(orchestrator._incidents.values())[0]
    assert incident.severity == "critical"
    assert incident.state == IncidentState.DETECTED
    assert incident.attack_type == "ddos"
    assert incident.detected_at is not None


# ---------------------------------------------------------------------------
# Test: Requirement 10.2 - Low score does not create incident
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_low_score_no_incident(orchestrator, queues):
    """
    WHEN the LLMOrchestrator receives an AttackEvent with composite_score < 0.65,
    THEN it SHALL not create an Incident record.
    Validates: Requirements 10.2
    """
    # Create low-severity attack event
    event = create_attack_event(composite_score=0.60, attack_type="suspicious")
    
    # Mock LLM to return None
    with patch("backend.agents.orchestrator.analyze_threat", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = None
        
        # Handle the event
        await orchestrator.handle_attack_event(event)
    
    # Verify no incident was created
    assert len(orchestrator._incidents) == 0


# ---------------------------------------------------------------------------
# Test: Requirement 10.3 - Conflict resolution by priority
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_conflict_resolution_by_priority(orchestrator):
    """
    WHEN the LLMOrchestrator receives two MitigationCommands for the same target_ip,
    THEN it SHALL resolve the conflict by keeping only the command with the lower
    priority number (higher urgency).
    Validates: Requirements 10.3
    """
    # Create two commands for the same IP with different priorities
    cmd1 = MitigationCommand(
        event_id="event1",
        action="block_ip",
        target_ip="192.168.1.100",
        ttl_seconds=3600,
        priority=2,  # Lower urgency
    )
    
    cmd2 = MitigationCommand(
        event_id="event2",
        action="rate_limit",
        target_ip="192.168.1.100",
        ttl_seconds=1800,
        priority=1,  # Higher urgency (lower number)
    )
    
    # Resolve conflicts
    resolved = await orchestrator._resolve_conflicts([cmd1, cmd2])
    
    # Verify only the higher priority command remains
    assert len(resolved) == 1
    assert resolved[0].priority == 1
    assert resolved[0].event_id == "event2"


# ---------------------------------------------------------------------------
# Test: Requirement 10.4 - LLM timeout triggers fallback
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_llm_timeout_triggers_fallback(orchestrator, queues):
    """
    WHEN the LLM is unavailable (timeout),
    THEN the LLMOrchestrator SHALL invoke rule_based_fallback and dispatch
    a MitigationCommand based on the composite score alone.
    Validates: Requirements 10.4
    """
    # Create medium-severity attack event
    event = create_attack_event(composite_score=0.85, attack_type="brute_force")
    
    # Mock LLM to return None (simulating timeout)
    with patch("backend.agents.orchestrator.analyze_threat", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = None
        
        # Handle the event
        await orchestrator.handle_attack_event(event)
    
    # Verify mitigation command was dispatched to prevention queue
    assert not queues.prevention_queue.empty()
    cmd = await queues.prevention_queue.get()
    assert isinstance(cmd, MitigationCommand)
    assert cmd.target_ip == "192.168.1.100"
    # Score 0.85 should trigger rate_limit action (>= 0.65, < 0.9)
    assert cmd.action == "rate_limit"


# ---------------------------------------------------------------------------
# Test: Requirement 10.5 - LogEntry emission
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_attack_event_emits_log_entry(orchestrator, queues):
    """
    WHEN the LLMOrchestrator processes an AttackEvent,
    THEN it SHALL emit a LogEntry to the logging_queue with
    event_type="attack_event_processed".
    Validates: Requirements 10.5
    """
    # Create attack event
    event = create_attack_event(composite_score=0.75, attack_type="sql_injection")
    
    # Mock LLM
    with patch("backend.agents.orchestrator.analyze_threat", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = {"action": "block_ip", "confidence": 0.9}
        
        # Handle the event
        await orchestrator.handle_attack_event(event)
    
    # Verify log entry was emitted
    assert not queues.logging_queue.empty()
    log_entry = await queues.logging_queue.get()
    assert isinstance(log_entry, LogEntry)
    assert log_entry.event_type == "attack_event_processed"
    assert log_entry.source_agent == "orchestrator"
    assert log_entry.payload["attack_type"] == "sql_injection"
    assert log_entry.payload["composite_score"] == 0.75


# ---------------------------------------------------------------------------
# Test: Requirement 10.6 - Campaign correlation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_campaign_correlation_warning(orchestrator, queues, caplog):
    """
    WHEN three or more AttackEvents with the same attack_type arrive within 5 seconds,
    THEN the LLMOrchestrator SHALL log a campaign detection warning.
    Validates: Requirements 10.6
    """
    import logging
    caplog.set_level(logging.WARNING)
    
    # Create three events with the same attack type
    events = [
        create_attack_event(composite_score=0.70, attack_type="port_scan"),
        create_attack_event(composite_score=0.72, attack_type="port_scan"),
        create_attack_event(composite_score=0.68, attack_type="port_scan"),
    ]
    
    # Mock LLM
    with patch("backend.agents.orchestrator.analyze_threat", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = None
        
        # Process all three events
        for event in events:
            await orchestrator.handle_attack_event(event)
    
    # Verify campaign warning was logged
    assert any("Campaign detected" in record.message for record in caplog.records)
    assert any("port_scan" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# Test: Rule-based fallback logic
# ---------------------------------------------------------------------------

def test_rule_based_fallback_critical():
    """Test fallback for critical score (>= 0.9)."""
    cmd = rule_based_fallback(0.95)
    assert cmd is not None
    assert cmd.action == "block_ip"
    assert cmd.ttl_seconds == 3600
    assert cmd.priority == 1


def test_rule_based_fallback_medium():
    """Test fallback for medium score (>= 0.65, < 0.9)."""
    cmd = rule_based_fallback(0.75)
    assert cmd is not None
    assert cmd.action == "rate_limit"
    assert cmd.ttl_seconds == 1800
    assert cmd.priority == 2


def test_rule_based_fallback_low():
    """Test fallback for low score (< 0.65)."""
    cmd = rule_based_fallback(0.50)
    assert cmd is None


# ---------------------------------------------------------------------------
# Test: LLM-based mitigation command
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_llm_based_mitigation(orchestrator, queues):
    """
    WHEN the LLM returns a valid action,
    THEN the orchestrator SHALL create a MitigationCommand with that action.
    """
    event = create_attack_event(composite_score=0.88, attack_type="xss")
    
    # Mock LLM to return a specific action
    with patch("backend.agents.orchestrator.analyze_threat", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = {
            "action": "isolate_device",
            "confidence": 0.95,
            "reasoning": "Suspicious device behavior detected"
        }
        
        # Handle the event
        await orchestrator.handle_attack_event(event)
    
    # Verify mitigation command was dispatched
    assert not queues.prevention_queue.empty()
    cmd = await queues.prevention_queue.get()
    assert cmd.action == "isolate_device"
    assert cmd.target_ip == "192.168.1.100"


# ---------------------------------------------------------------------------
# Test: Multiple events with different IPs (no conflict)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_conflict_different_ips(orchestrator):
    """
    WHEN commands target different IPs,
    THEN all commands should be kept (no conflict).
    """
    cmd1 = MitigationCommand(
        event_id="event1",
        action="block_ip",
        target_ip="192.168.1.100",
        ttl_seconds=3600,
        priority=1,
    )
    
    cmd2 = MitigationCommand(
        event_id="event2",
        action="block_ip",
        target_ip="192.168.1.101",
        ttl_seconds=3600,
        priority=1,
    )
    
    resolved = await orchestrator._resolve_conflicts([cmd1, cmd2])
    
    # Both commands should remain
    assert len(resolved) == 2
    assert {cmd.target_ip for cmd in resolved} == {"192.168.1.100", "192.168.1.101"}


# ---------------------------------------------------------------------------
# Test: Campaign correlation with different attack types
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_campaign_different_types(orchestrator, queues, caplog):
    """
    WHEN events have different attack types,
    THEN no campaign warning should be logged.
    """
    import logging
    caplog.set_level(logging.WARNING)
    
    # Create three events with different attack types
    events = [
        create_attack_event(composite_score=0.70, attack_type="port_scan"),
        create_attack_event(composite_score=0.72, attack_type="ddos"),
        create_attack_event(composite_score=0.68, attack_type="brute_force"),
    ]
    
    with patch("backend.agents.orchestrator.analyze_threat", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = None
        
        for event in events:
            await orchestrator.handle_attack_event(event)
    
    # Verify no campaign warning was logged
    campaign_warnings = [r for r in caplog.records if "Campaign detected" in r.message]
    assert len(campaign_warnings) == 0


# ---------------------------------------------------------------------------
# Test: Campaign correlation time window
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_campaign_time_window(orchestrator, queues, caplog):
    """
    WHEN events arrive outside the 5-second window,
    THEN no campaign warning should be logged.
    """
    import logging
    caplog.set_level(logging.WARNING)
    
    # Create events with timestamps outside the window
    old_event = create_attack_event(composite_score=0.70, attack_type="port_scan")
    old_event.timestamp = datetime.utcnow() - timedelta(seconds=10)
    
    new_events = [
        create_attack_event(composite_score=0.72, attack_type="port_scan"),
        create_attack_event(composite_score=0.68, attack_type="port_scan"),
    ]
    
    with patch("backend.agents.orchestrator.analyze_threat", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = None
        
        # Process old event first
        await orchestrator.handle_attack_event(old_event)
        
        # Process new events
        for event in new_events:
            await orchestrator.handle_attack_event(event)
    
    # Should not trigger campaign warning (only 2 events in window)
    campaign_warnings = [r for r in caplog.records if "Campaign detected" in r.message]
    assert len(campaign_warnings) == 0


# ---------------------------------------------------------------------------
# Test: Priority queue ordering for equal-priority events
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_equal_priority_attack_events_can_be_enqueued(queues):
    """Equal-priority AttackEvents must not crash the orchestrator PriorityQueue."""
    event1 = create_attack_event(composite_score=0.80, attack_type="test")
    event2 = create_attack_event(composite_score=0.80, attack_type="test")

    first = await safe_put(queues.orchestrator_queue, (1, event1))
    second = await safe_put(queues.orchestrator_queue, (1, event2))

    assert first is True
    assert second is True


# ---------------------------------------------------------------------------
# Test: Orchestrator start/stop lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_orchestrator_lifecycle(orchestrator, queues):
    """
    Test that orchestrator can start and stop cleanly.
    """
    # Start orchestrator
    await orchestrator.start()
    assert orchestrator._running is True
    assert orchestrator._task is not None
    
    # Put an event in the queue
    event = create_attack_event(composite_score=0.80, attack_type="test")
    with patch(
        "backend.agents.orchestrator.analyze_threat", new_callable=AsyncMock
    ) as mock_llm:
        mock_llm.return_value = None
        await queues.orchestrator_queue.put((1, event))

        # Give it time to process
        await asyncio.sleep(0.1)

        # Stop flushes any event still pending aggregation.
        await orchestrator.stop()
    assert orchestrator._running is False
    assert orchestrator._processed >= 1


# ---------------------------------------------------------------------------
# Test: Metrics increment
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_metrics_increment(orchestrator, queues):
    """
    Verify that processing an event increments the metrics counter.
    """
    with patch("backend.agents.orchestrator.increment_events_processed") as mock_metric:
        event = create_attack_event(composite_score=0.75, attack_type="test")
        
        with patch("backend.agents.orchestrator.analyze_threat", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = None
            await orchestrator.handle_attack_event(event)
        
        # Verify metric was incremented
        mock_metric.assert_any_call("orchestrator")



# ---------------------------------------------------------------------------
# Property 11: Every above-threshold event triggers mitigation
# Validates: Requirements 10.7
# ---------------------------------------------------------------------------

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st


class TestMitigationDispatchProperty:
    """
    **Validates: Requirements 10.7**

    Property 11: Every AttackEvent with composite_score >= 0.65 MUST result in
    at least one MitigationCommand being dispatched to the prevention_queue.
    """

    @given(composite_score=st.floats(min_value=0.65, max_value=1.0, allow_nan=False))
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    def test_every_above_threshold_event_triggers_mitigation(self, composite_score):
        """
        **Validates: Requirements 10.7**

        For any composite_score in [0.65, 1.0], handling the AttackEvent must
        dispatch a MitigationCommand to the prevention_queue.
        """
        import backend.agents.queues as queues_module
        from unittest.mock import AsyncMock, patch

        # Reset the global queues singleton so each run starts clean
        queues_module._queues = None
        fresh_queues = queues_module.get_queues()

        orchestrator = LLMOrchestrator()
        event = create_attack_event(composite_score=composite_score, attack_type="port_scan")

        # Mock analyze_threat to return None, forcing the rule-based fallback path
        with patch(
            "backend.agents.orchestrator.analyze_threat", new_callable=AsyncMock
        ) as mock_llm:
            mock_llm.return_value = None
            asyncio.run(orchestrator.handle_attack_event(event))

        # The prevention_queue must contain at least one MitigationCommand
        assert not fresh_queues.prevention_queue.empty(), (
            f"Expected a MitigationCommand in prevention_queue for "
            f"composite_score={composite_score}, but queue was empty."
        )


# ---------------------------------------------------------------------------
# Property 12: Deduplication is idempotent
# Validates: Requirements 10.8
# ---------------------------------------------------------------------------


class TestConflictResolutionIdempotenceProperty:
    """
    **Validates: Requirements 10.8**

    Property 12: When two MitigationCommands share the same target_ip,
    _resolve_conflicts must return exactly one command (the higher-priority one).
    """

    @given(
        target_ip=st.ip_addresses(v=4).map(str),
        priority1=st.integers(min_value=1, max_value=10),
        priority2=st.integers(min_value=1, max_value=10),
        action1=st.sampled_from(["block_ip", "rate_limit", "isolate_device"]),
        action2=st.sampled_from(["block_ip", "rate_limit", "isolate_device"]),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_deduplication_produces_exactly_one_command(
        self, target_ip, priority1, priority2, action1, action2
    ):
        """
        **Validates: Requirements 10.8**

        For any pair of MitigationCommands targeting the same IP, conflict
        resolution must yield exactly one command, keeping the one with the
        lower priority number (higher urgency).
        """
        orchestrator = LLMOrchestrator()

        cmd1 = MitigationCommand(
            event_id="event_prop12_a",
            action=action1,
            target_ip=target_ip,
            ttl_seconds=3600,
            priority=priority1,
        )
        cmd2 = MitigationCommand(
            event_id="event_prop12_b",
            action=action2,
            target_ip=target_ip,
            ttl_seconds=1800,
            priority=priority2,
        )

        resolved = asyncio.run(orchestrator._resolve_conflicts([cmd1, cmd2]))

        # Exactly one command must survive deduplication
        assert len(resolved) == 1, (
            f"Expected exactly 1 command after deduplication for target_ip={target_ip}, "
            f"but got {len(resolved)}."
        )

        # The surviving command must be the one with the lower priority number
        expected_priority = min(priority1, priority2)
        assert resolved[0].priority == expected_priority, (
            f"Expected surviving command to have priority={expected_priority}, "
            f"but got priority={resolved[0].priority}."
        )

        # The surviving command must target the correct IP
        assert resolved[0].target_ip == target_ip
