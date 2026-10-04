"""
Property-based tests for LLMOrchestrator.

**Validates: Requirements 10.7**

Property 11: Every above-threshold event triggers mitigation.
Every AttackEvent with composite_score >= 0.65 MUST result in at least one
MitigationCommand being dispatched to the prevention_queue.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import backend.agents.queues as queues_module
from backend.agents.orchestrator import LLMOrchestrator
from backend.models.messages import AttackEvent, FeatureVector, MitigationCommand


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_feature_vector(src_ip: str = "192.168.1.100") -> FeatureVector:
    """Return a minimal but valid FeatureVector."""
    return FeatureVector(
        flow_id="prop_flow",
        timestamp=datetime.utcnow(),
        src_ip=src_ip,
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        packet_rate=100.0,
        byte_rate=50_000.0,
        flow_duration=5.0,
        tcp_flags="PA",
        connection_errors=0,
        port_entropy=0.5,
        is_known_iot_port=False,
    )


def _make_attack_event(
    composite_score: float,
    attack_type: str = "port_scan",
    src_ip: str = "192.168.1.100",
) -> AttackEvent:
    """Return an AttackEvent with the given composite_score."""
    fv = _make_feature_vector(src_ip=src_ip)
    return AttackEvent(
        flow_id=fv.flow_id,
        feature_vector=fv,
        lightgbm_score=composite_score * 0.6,
        if_score=composite_score * 0.4,
        composite_score=composite_score,
        attack_type=attack_type,
        timestamp=datetime.utcnow(),
    )


# ---------------------------------------------------------------------------
# Property 11: Every above-threshold event triggers mitigation
# Validates: Requirements 10.7
# ---------------------------------------------------------------------------

@given(
    composite_score=st.floats(min_value=0.65, max_value=1.0, allow_nan=False),
    attack_type=st.sampled_from([
        "port_scan", "ddos", "brute_force", "sql_injection",
        "xss", "mitm", "arp_spoofing", "dns_amplification",
    ]),
    src_ip=st.ip_addresses(v=4).map(str),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_every_above_threshold_event_triggers_mitigation(
    composite_score: float,
    attack_type: str,
    src_ip: str,
) -> None:
    """
    **Validates: Requirements 10.7**

    Property 11: For any AttackEvent whose composite_score is in [0.65, 1.0],
    calling handle_attack_event() MUST place at least one MitigationCommand
    on the prevention_queue.

    The LLM is mocked to return None so the deterministic rule_based_fallback
    path is exercised, which guarantees a command for any score >= 0.65.
    """
    # Reset the global queues singleton so each example starts with an empty queue.
    queues_module._queues = None
    fresh_queues = queues_module.get_queues()

    orchestrator = LLMOrchestrator()
    event = _make_attack_event(
        composite_score=composite_score,
        attack_type=attack_type,
        src_ip=src_ip,
    )

    # Mock analyze_threat to return None, forcing the rule-based fallback path.
    with patch(
        "backend.agents.orchestrator.analyze_threat", new_callable=AsyncMock
    ) as mock_llm:
        mock_llm.return_value = None
        asyncio.run(orchestrator.handle_attack_event(event))

    # The prevention_queue MUST contain at least one MitigationCommand.
    assert not fresh_queues.prevention_queue.empty(), (
        f"Expected a MitigationCommand in prevention_queue for "
        f"composite_score={composite_score!r}, attack_type={attack_type!r}, "
        f"src_ip={src_ip!r}, but the queue was empty."
    )

    # Drain the queue and verify the item is a MitigationCommand.
    cmd = fresh_queues.prevention_queue.get_nowait()
    assert isinstance(cmd, MitigationCommand), (
        f"Expected MitigationCommand, got {type(cmd).__name__!r}."
    )

    # The command must target the source IP of the attack event.
    assert cmd.target_ip == src_ip, (
        f"Expected target_ip={src_ip!r}, got {cmd.target_ip!r}."
    )

    # The action must be one of the valid mitigation actions.
    assert cmd.action in ("block_ip", "rate_limit", "isolate_device"), (
        f"Unexpected action {cmd.action!r} for composite_score={composite_score!r}."
    )

    # Score >= 0.9 must produce block_ip with priority 1.
    if composite_score >= 0.9:
        assert cmd.action == "block_ip", (
            f"Score {composite_score!r} >= 0.9 should produce block_ip, "
            f"got {cmd.action!r}."
        )
        assert cmd.priority == 1, (
            f"Score {composite_score!r} >= 0.9 should produce priority=1, "
            f"got {cmd.priority!r}."
        )
    else:
        # 0.65 <= score < 0.9 must produce rate_limit with priority 2.
        assert cmd.action == "rate_limit", (
            f"Score {composite_score!r} in [0.65, 0.9) should produce rate_limit, "
            f"got {cmd.action!r}."
        )
        assert cmd.priority == 2, (
            f"Score {composite_score!r} in [0.65, 0.9) should produce priority=2, "
            f"got {cmd.priority!r}."
        )


# ---------------------------------------------------------------------------
# Property 12: Deduplication is idempotent
# Validates: Requirements 10.8
# ---------------------------------------------------------------------------

@given(
    target_ip=st.ip_addresses(v=4).map(str),
    commands=st.lists(
        st.builds(
            MitigationCommand,
            event_id=st.uuids().map(str),
            action=st.sampled_from(["block_ip", "rate_limit", "isolate_device"]),
            target_ip=st.just("PLACEHOLDER"),  # overridden below
            ttl_seconds=st.integers(min_value=60, max_value=86400),
            priority=st.integers(min_value=1, max_value=3),
        ),
        min_size=2,
        max_size=10,
    ),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_conflict_resolution_deduplication_is_idempotent(
    target_ip: str,
    commands: list[MitigationCommand],
) -> None:
    """
    **Validates: Requirements 10.8**

    Property 12: Deduplication is idempotent.
    Given a list of MitigationCommands that all share the same target_ip,
    calling _resolve_conflicts() MUST return exactly one command for that IP.
    Calling _resolve_conflicts() a second time on the already-resolved list
    MUST return the same single command (idempotence).
    """
    # Override target_ip on every command so they all share the same target.
    for cmd in commands:
        cmd.target_ip = target_ip

    orchestrator = LLMOrchestrator()

    # First resolution pass.
    resolved_once = asyncio.run(orchestrator._resolve_conflicts(commands))

    # Exactly one command per target_ip after first resolution.
    assert len(resolved_once) == 1, (
        f"Expected exactly 1 command after resolving {len(commands)} commands "
        f"for target_ip={target_ip!r}, got {len(resolved_once)}."
    )

    # The surviving command must target the correct IP.
    assert resolved_once[0].target_ip == target_ip, (
        f"Resolved command has wrong target_ip: "
        f"expected {target_ip!r}, got {resolved_once[0].target_ip!r}."
    )

    # The surviving command must be the one with the highest priority (lowest number).
    best_priority = min(cmd.priority for cmd in commands)
    assert resolved_once[0].priority == best_priority, (
        f"Expected priority={best_priority} (highest priority wins), "
        f"got priority={resolved_once[0].priority}."
    )

    # Second resolution pass on the already-resolved list (idempotence check).
    resolved_twice = asyncio.run(orchestrator._resolve_conflicts(resolved_once))

    assert len(resolved_twice) == 1, (
        f"Expected exactly 1 command after second resolution pass, "
        f"got {len(resolved_twice)}."
    )
    assert resolved_twice[0].target_ip == resolved_once[0].target_ip, (
        "target_ip changed between first and second resolution pass."
    )
    assert resolved_twice[0].priority == resolved_once[0].priority, (
        "priority changed between first and second resolution pass."
    )
    assert resolved_twice[0].action == resolved_once[0].action, (
        "action changed between first and second resolution pass."
    )
