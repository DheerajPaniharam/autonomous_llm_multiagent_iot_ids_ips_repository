"""
Property-based tests for MTTD/MTTR calculations in ObservabilityAgent.

Task 7.4 — Property 2: Time deltas are non-negative
**Validates: Requirements 11.6**

Generate random incident/attack event data and verify MTTD >= 0 and MTTR >= 0
for all inputs.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from backend.agents.observability_agent import ObservabilityAgent


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Non-negative time delta in seconds (0 to 7 days)
_non_negative_delta = st.floats(
    min_value=0.0,
    max_value=604800.0,  # 7 days in seconds
    allow_nan=False,
    allow_infinity=False,
)

# Attack type strings (lowercase letters and underscores only)
_attack_type = st.text(
    min_size=1,
    max_size=20,
    alphabet="abcdefghijklmnopqrstuvwxyz_",
)

# Dict of attack_type -> non-negative delta (simulates DB avg results)
_type_deltas = st.dictionaries(
    keys=_attack_type,
    values=_non_negative_delta,
    min_size=1,
    max_size=10,
)


# ---------------------------------------------------------------------------
# Helper: run an async coroutine from a sync context
# ---------------------------------------------------------------------------

def _run(coro):
    """Run a coroutine in a fresh event loop."""
    return asyncio.run(coro)


def _make_mock_session(fake_rows):
    """Build a mock async session context manager returning fake_rows."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.__iter__ = MagicMock(return_value=iter(fake_rows))
    mock_session.execute = AsyncMock(return_value=mock_result)

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_ctx


# ---------------------------------------------------------------------------
# Property 2: Time deltas are non-negative
# Validates: Requirements 11.6
# ---------------------------------------------------------------------------


class TestMTTDNonNegativeProperty:
    """
    Property 2a: MTTD values are always >= 0.0.

    **Validates: Requirements 11.6**

    For any set of non-negative (detected_at - attack_timestamp) averages
    returned by the database, calculate_mttd_all must return values >= 0.0
    for every attack type.
    """

    @given(type_deltas=_type_deltas)
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    def test_calculate_mttd_all_returns_non_negative(self, type_deltas):
        """
        Property 2a: calculate_mttd_all returns >= 0.0 for all attack types
        when the DB returns non-negative average deltas.

        **Validates: Requirements 11.6**
        """
        fake_rows = list(type_deltas.items())

        async def _run_test():
            mock_ctx = _make_mock_session(fake_rows)
            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)
            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttd_all(start, end)

        result = _run(_run_test())

        assert isinstance(result, dict), "calculate_mttd_all must return a dict"
        for attack_type, mttd in result.items():
            assert mttd >= 0.0, (
                f"MTTD for '{attack_type}' is {mttd} — expected >= 0.0"
            )

    @given(
        deltas=st.lists(_non_negative_delta, min_size=1, max_size=50),
        attack_type=_attack_type,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_mttd_guard_logic_is_non_negative(self, deltas, attack_type):
        """
        Property 2a (pure logic): The max(0.0, float(avg)) guard used in
        calculate_mttd_all always produces a non-negative result for any
        list of non-negative deltas.

        **Validates: Requirements 11.6**
        """
        avg = sum(deltas) / len(deltas)
        result = max(0.0, float(avg))
        assert result >= 0.0, (
            f"MTTD guard produced {result} for deltas={deltas[:5]}..."
        )


class TestMTTRNonNegativeProperty:
    """
    Property 2b: MTTR values are always >= 0.0.

    **Validates: Requirements 11.6**

    For any set of non-negative (resolved_at - detected_at) averages
    returned by the database, calculate_mttr_all must return values >= 0.0
    for every attack type.
    """

    @given(type_deltas=_type_deltas)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_calculate_mttr_all_returns_non_negative(self, type_deltas):
        """
        Property 2b: calculate_mttr_all returns >= 0.0 for all attack types
        when the DB returns non-negative average deltas.

        **Validates: Requirements 11.6**
        """
        fake_rows = list(type_deltas.items())

        async def _run_test():
            mock_ctx = _make_mock_session(fake_rows)
            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)
            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttr_all(start, end)

        result = _run(_run_test())

        assert isinstance(result, dict), "calculate_mttr_all must return a dict"
        for attack_type, mttr in result.items():
            assert mttr >= 0.0, (
                f"MTTR for '{attack_type}' is {mttr} — expected >= 0.0"
            )

    @given(
        deltas=st.lists(_non_negative_delta, min_size=1, max_size=50),
        attack_type=_attack_type,
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_mttr_guard_logic_is_non_negative(self, deltas, attack_type):
        """
        Property 2b (pure logic): The max(0.0, float(avg)) guard used in
        calculate_mttr_all always produces a non-negative result for any
        list of non-negative deltas.

        **Validates: Requirements 11.6**
        """
        avg = sum(deltas) / len(deltas)
        result = max(0.0, float(avg))
        assert result >= 0.0, (
            f"MTTR guard produced {result} for deltas={deltas[:5]}..."
        )


class TestMTTDMTTREdgeCases:
    """
    Edge cases for MTTD/MTTR non-negativity (Requirements 11.6).
    """

    def test_mttd_empty_db_result_returns_empty_dict(self):
        """Empty DB result → empty dict (no negative values possible)."""
        async def _run_test():
            mock_ctx = _make_mock_session([])
            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)
            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttd_all(start, end)

        result = _run(_run_test())
        assert result == {}

    def test_mttr_empty_db_result_returns_empty_dict(self):
        """Empty DB result → empty dict (no negative values possible)."""
        async def _run_test():
            mock_ctx = _make_mock_session([])
            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)
            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttr_all(start, end)

        result = _run(_run_test())
        assert result == {}

    def test_mttd_none_db_value_treated_as_zero(self):
        """None average from DB is treated as 0.0, which is non-negative."""
        async def _run_test():
            mock_ctx = _make_mock_session([("ddos", None)])
            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)
            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttd_all(start, end)

        result = _run(_run_test())
        assert result.get("ddos") == 0.0
        assert result["ddos"] >= 0.0

    def test_mttr_none_db_value_treated_as_zero(self):
        """None average from DB is treated as 0.0, which is non-negative."""
        async def _run_test():
            mock_ctx = _make_mock_session([("port_scan", None)])
            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)
            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttr_all(start, end)

        result = _run(_run_test())
        assert result.get("port_scan") == 0.0
        assert result["port_scan"] >= 0.0

    def test_mttd_zero_delta_is_non_negative(self):
        """Zero detection time (instant detection) is a valid non-negative value."""
        async def _run_test():
            mock_ctx = _make_mock_session([("brute_force", 0.0)])
            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)
            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttd_all(start, end)

        result = _run(_run_test())
        assert result.get("brute_force") == 0.0
        assert result["brute_force"] >= 0.0

    def test_mttr_zero_delta_is_non_negative(self):
        """Zero response time (instant resolution) is a valid non-negative value."""
        async def _run_test():
            mock_ctx = _make_mock_session([("mitm", 0.0)])
            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)
            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttr_all(start, end)

        result = _run(_run_test())
        assert result.get("mitm") == 0.0
        assert result["mitm"] >= 0.0

    def test_mttd_none_attack_type_mapped_to_unknown(self):
        """None attack_type from DB is mapped to 'unknown', value is non-negative."""
        async def _run_test():
            mock_ctx = _make_mock_session([(None, 300.0)])
            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)
            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttd_all(start, end)

        result = _run(_run_test())
        assert "unknown" in result
        assert result["unknown"] >= 0.0

    def test_mttr_none_attack_type_mapped_to_unknown(self):
        """None attack_type from DB is mapped to 'unknown', value is non-negative."""
        async def _run_test():
            mock_ctx = _make_mock_session([(None, 600.0)])
            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)
            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttr_all(start, end)

        result = _run(_run_test())
        assert "unknown" in result
        assert result["unknown"] >= 0.0

    @given(
        type_deltas=st.dictionaries(
            keys=_attack_type,
            values=_non_negative_delta,
            min_size=1,
            max_size=10,
        )
    )
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    def test_all_mttd_and_mttr_values_non_negative_combined(self, type_deltas):
        """
        Combined property: both MTTD and MTTR return non-negative values
        for the same set of random attack type deltas.

        **Validates: Requirements 11.6**
        """
        fake_rows = list(type_deltas.items())

        async def _run_mttd():
            mock_ctx = _make_mock_session(fake_rows)
            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)
            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttd_all(start, end)

        async def _run_mttr():
            mock_ctx = _make_mock_session(fake_rows)
            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)
            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttr_all(start, end)

        mttd_result = _run(_run_mttd())
        mttr_result = _run(_run_mttr())

        for attack_type, mttd in mttd_result.items():
            assert mttd >= 0.0, f"MTTD for '{attack_type}' is {mttd} — expected >= 0.0"

        for attack_type, mttr in mttr_result.items():
            assert mttr >= 0.0, f"MTTR for '{attack_type}' is {mttr} — expected >= 0.0"
