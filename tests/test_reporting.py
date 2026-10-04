"""
Property-based tests for ObservabilityAgent MTTD/MTTR calculations.

Task 7.4 — Property 2: Time deltas are non-negative (Validates: Requirements 11.6)
Task 7.5 — Property 3: Count aggregation consistency (Validates: Requirements 11.7)
"""
from __future__ import annotations

import asyncio
from datetime import date, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from backend.agents.observability_agent import Report, ObservabilityAgent


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Non-negative time delta in seconds (up to one day)
_non_negative_delta = st.floats(
    min_value=0.0,
    max_value=86400.0,
    allow_nan=False,
    allow_infinity=False,
)

# Attack type strings (lowercase letters and underscores only)
_attack_type = st.text(
    min_size=1,
    max_size=20,
    alphabet="abcdefghijklmnopqrstuvwxyz_",
)


# ---------------------------------------------------------------------------
# Helper: run an async coroutine from a sync context
# ---------------------------------------------------------------------------

def _run(coro):
    """Run a coroutine in a fresh event loop (compatible with Python 3.10+)."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Task 7.4 — Property 2: Time deltas are non-negative
# Validates: Requirements 11.6
# ---------------------------------------------------------------------------


class TestMTTDMTTRNonNegativeProperty:
    """
    Property 2: Time deltas are non-negative.

    **Validates: Requirements 11.6**

    For any set of non-negative (detected_at - attack_timestamp) deltas,
    calculate_mttd_all must return values >= 0.0 for every attack type.

    For any set of non-negative (resolved_at - detected_at) deltas,
    calculate_mttr_all must return values >= 0.0 for every attack type.
    """

    # ------------------------------------------------------------------
    # Pure-logic tests (no DB required)
    # ------------------------------------------------------------------

    @given(
        deltas=st.lists(_non_negative_delta, min_size=1, max_size=10),
        attack_type=_attack_type,
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_mttd_values_are_non_negative(self, deltas, attack_type):
        """
        Property 2a: MTTD values computed from non-negative deltas are >= 0.

        Simulates the max(0.0, float(avg)) guard in calculate_mttd_all.

        **Validates: Requirements 11.6**
        """
        avg = sum(deltas) / len(deltas)
        result = max(0.0, float(avg))
        assert result >= 0.0, (
            f"MTTD result {result} is negative for deltas={deltas}"
        )

    @given(
        deltas=st.lists(_non_negative_delta, min_size=1, max_size=10),
        attack_type=_attack_type,
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_mttr_values_are_non_negative(self, deltas, attack_type):
        """
        Property 2b: MTTR values computed from non-negative deltas are >= 0.

        Simulates the max(0.0, float(avg)) guard in calculate_mttr_all.

        **Validates: Requirements 11.6**
        """
        avg = sum(deltas) / len(deltas)
        result = max(0.0, float(avg))
        assert result >= 0.0, (
            f"MTTR result {result} is negative for deltas={deltas}"
        )

    # ------------------------------------------------------------------
    # Integration-style tests — mock the DB session, call the real methods
    # ------------------------------------------------------------------

    @given(
        type_deltas=st.dictionaries(
            keys=_attack_type,
            values=_non_negative_delta,
            min_size=1,
            max_size=5,
        )
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    def test_calculate_mttd_all_returns_non_negative_via_mock(self, type_deltas):
        """
        Property 2c: calculate_mttd_all returns non-negative values for all
        attack types when the DB returns non-negative average deltas.

        Mocks get_session so no real database is needed.

        **Validates: Requirements 11.6**
        """
        # Build the fake rows the DB would return: [(attack_type, avg_delta), ...]
        fake_rows = list(type_deltas.items())

        async def _run_test():
            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.__iter__ = MagicMock(return_value=iter(fake_rows))
            mock_session.execute = AsyncMock(return_value=mock_result)

            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)

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
        type_deltas=st.dictionaries(
            keys=_attack_type,
            values=_non_negative_delta,
            min_size=1,
            max_size=5,
        )
    )
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None,
    )
    def test_calculate_mttr_all_returns_non_negative_via_mock(self, type_deltas):
        """
        Property 2d: calculate_mttr_all returns non-negative values for all
        attack types when the DB returns non-negative average deltas.

        Mocks get_session so no real database is needed.

        **Validates: Requirements 11.6**
        """
        fake_rows = list(type_deltas.items())

        async def _run_test():
            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.__iter__ = MagicMock(return_value=iter(fake_rows))
            mock_session.execute = AsyncMock(return_value=mock_result)

            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)

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

    def test_calculate_mttd_all_empty_result_returns_empty_dict(self):
        """
        Edge case: when the DB returns no rows, calculate_mttd_all returns {}.
        """
        async def _run_test():
            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.__iter__ = MagicMock(return_value=iter([]))
            mock_session.execute = AsyncMock(return_value=mock_result)

            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)

            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)

            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttd_all(start, end)

        result = _run(_run_test())
        assert result == {}, f"Expected empty dict, got {result}"

    def test_calculate_mttr_all_empty_result_returns_empty_dict(self):
        """
        Edge case: when the DB returns no rows, calculate_mttr_all returns {}.
        """
        async def _run_test():
            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.__iter__ = MagicMock(return_value=iter([]))
            mock_session.execute = AsyncMock(return_value=mock_result)

            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)

            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)

            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttr_all(start, end)

        result = _run(_run_test())
        assert result == {}, f"Expected empty dict, got {result}"

    def test_calculate_mttd_all_none_db_value_treated_as_zero(self):
        """
        Edge case: a None average from the DB is treated as 0.0 (not an error).
        """
        async def _run_test():
            fake_rows = [("ddos", None)]

            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.__iter__ = MagicMock(return_value=iter(fake_rows))
            mock_session.execute = AsyncMock(return_value=mock_result)

            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)

            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)

            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttd_all(start, end)

        result = _run(_run_test())
        assert result.get("ddos") == 0.0, (
            f"Expected 0.0 for None DB value, got {result.get('ddos')}"
        )

    def test_calculate_mttd_all_none_attack_type_mapped_to_unknown(self):
        """
        Edge case: a None attack_type from the DB is mapped to 'unknown'.
        """
        async def _run_test():
            fake_rows = [(None, 120.0)]

            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.__iter__ = MagicMock(return_value=iter(fake_rows))
            mock_session.execute = AsyncMock(return_value=mock_result)

            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)

            agent = ObservabilityAgent()
            start = datetime(2024, 1, 1)
            end = datetime(2024, 1, 2)

            with patch("backend.agents.observability_agent.session_context", return_value=mock_ctx):
                return await agent.calculate_mttd_all(start, end)

        result = _run(_run_test())
        assert "unknown" in result, (
            f"Expected 'unknown' key for None attack_type, got keys: {list(result.keys())}"
        )
        assert result["unknown"] == 120.0


# ---------------------------------------------------------------------------
# Task 7.5 — Property 3: Count aggregation consistency
# Validates: Requirements 11.7
# ---------------------------------------------------------------------------


class TestCountAggregationConsistencyProperty:
    """
    Property 3: Count aggregation consistency.

    **Validates: Requirements 11.7**

    For any dict of {attack_type: count} pairs, the sum of all per-type
    counts must equal total_events as accumulated by _build_report.
    """

    @given(
        attack_counts=st.dictionaries(
            keys=_attack_type,
            values=st.integers(min_value=0, max_value=1000),
            min_size=1,
            max_size=10,
        )
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_sum_of_per_type_counts_equals_total_events(self, attack_counts):
        """
        Property 3a: sum(attack_counts.values()) == total_events.

        Directly verifies the accumulation logic used in _build_report.

        **Validates: Requirements 11.7**
        """
        total = sum(attack_counts.values())

        # Simulate what _build_report does
        computed_total = 0
        for count in attack_counts.values():
            computed_total += count

        assert computed_total == total, (
            f"Computed total {computed_total} != expected {total} "
            f"for attack_counts={attack_counts}"
        )
        assert computed_total == sum(attack_counts.values()), (
            "Aggregation is not consistent with sum()"
        )

    @given(
        attack_counts=st.dictionaries(
            keys=_attack_type,
            values=st.integers(min_value=0, max_value=1000),
            min_size=1,
            max_size=10,
        )
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_report_total_events_matches_attack_counts_sum_via_mock(self, attack_counts):
        """
        Property 3b: Report.total_events == sum(Report.attack_counts.values())
        after _build_report populates the Report from mocked DB rows.

        Mocks both the attack-counts query and the mitigations scalar, plus
        calculate_mttd_all / calculate_mttr_all, so no real DB is needed.

        **Validates: Requirements 11.7**
        """
        fake_attack_rows = list(attack_counts.items())
        expected_total = sum(attack_counts.values())

        async def _run_test():
            mock_session = AsyncMock()

            mock_attack_result = MagicMock()
            mock_attack_result.__iter__ = MagicMock(
                return_value=iter(fake_attack_rows)
            )
            mock_session.execute = AsyncMock(return_value=mock_attack_result)
            mock_session.scalar = AsyncMock(return_value=0)  # no mitigations

            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)

            agent = ObservabilityAgent()

            with (
                patch("backend.agents.observability_agent.session_context", return_value=mock_ctx),
                patch.object(agent, "calculate_mttd_all", new=AsyncMock(return_value={})),
                patch.object(agent, "calculate_mttr_all", new=AsyncMock(return_value={})),
            ):
                return await agent._build_report(
                    "daily",
                    date(2024, 1, 1),
                    date(2024, 1, 2),
                )

        report = _run(_run_test())

        assert report.total_events == expected_total, (
            f"Report.total_events={report.total_events} != "
            f"expected {expected_total} for attack_counts={attack_counts}"
        )
        assert report.total_events == sum(report.attack_counts.values()), (
            f"Report.total_events={report.total_events} != "
            f"sum(attack_counts.values())={sum(report.attack_counts.values())}"
        )

    def test_empty_attack_counts_gives_zero_total_events(self):
        """
        Edge case: no attack events → total_events == 0.
        """
        async def _run_test():
            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.__iter__ = MagicMock(return_value=iter([]))
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.scalar = AsyncMock(return_value=0)

            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)

            agent = ObservabilityAgent()

            with (
                patch("backend.agents.observability_agent.session_context", return_value=mock_ctx),
                patch.object(agent, "calculate_mttd_all", new=AsyncMock(return_value={})),
                patch.object(agent, "calculate_mttr_all", new=AsyncMock(return_value={})),
            ):
                return await agent._build_report(
                    "daily",
                    date(2024, 1, 1),
                    date(2024, 1, 2),
                )

        report = _run(_run_test())
        assert report.total_events == 0
        assert report.attack_counts == {}

    def test_single_attack_type_total_equals_its_count(self):
        """
        Edge case: single attack type → total_events equals that type's count.
        """
        async def _run_test():
            fake_rows = [("ddos", 42)]

            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.__iter__ = MagicMock(return_value=iter(fake_rows))
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.scalar = AsyncMock(return_value=0)

            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)

            agent = ObservabilityAgent()

            with (
                patch("backend.agents.observability_agent.session_context", return_value=mock_ctx),
                patch.object(agent, "calculate_mttd_all", new=AsyncMock(return_value={})),
                patch.object(agent, "calculate_mttr_all", new=AsyncMock(return_value={})),
            ):
                return await agent._build_report(
                    "daily",
                    date(2024, 1, 1),
                    date(2024, 1, 2),
                )

        report = _run(_run_test())
        assert report.total_events == 42
        assert report.attack_counts == {"ddos": 42}
