"""
Property-based tests for count aggregation consistency in ObservabilityAgent.

Task 7.5 — Property 3: Count aggregation consistency
**Validates: Requirements 11.7**

Generate random attack event lists and verify that the sum of per-type counts
always equals total_events in the report.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from datetime import date, datetime
from unittest.mock import AsyncMock, MagicMock, patch

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from backend.agents.observability_agent import Report, ObservabilityAgent


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Attack type strings (lowercase letters and underscores only)
_attack_type = st.text(
    min_size=1,
    max_size=20,
    alphabet="abcdefghijklmnopqrstuvwxyz_",
)

# A single attack event represented as an attack_type string
_attack_event = _attack_type

# A list of attack events (each event has an attack_type)
_attack_event_list = st.lists(
    _attack_event,
    min_size=0,
    max_size=200,
)

# A dict of {attack_type: count} as the DB would return from GROUP BY
_attack_counts_dict = st.dictionaries(
    keys=_attack_type,
    values=st.integers(min_value=0, max_value=1000),
    min_size=0,
    max_size=20,
)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _run(coro):
    """Run a coroutine in a fresh event loop."""
    return asyncio.run(coro)


def _make_mock_session(attack_rows, mitigation_count: int = 0):
    """
    Build a mock async session context manager that returns attack_rows
    from execute() and mitigation_count from scalar().
    """
    mock_session = AsyncMock()

    mock_result = MagicMock()
    mock_result.__iter__ = MagicMock(return_value=iter(attack_rows))
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.scalar = AsyncMock(return_value=mitigation_count)

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_ctx


# ---------------------------------------------------------------------------
# Property 3: Count aggregation consistency
# Validates: Requirements 11.7
# ---------------------------------------------------------------------------


class TestCountAggregationConsistencyProperty:
    """
    Property 3: Count aggregation consistency.

    **Validates: Requirements 11.7**

    For ALL report periods, the sum of all per-type event counts in
    ``attack_counts`` SHALL equal ``total_events``.

    This is tested at two levels:
    - Pure logic: simulate the accumulation loop directly.
    - Integration: call ``_build_report`` with a mocked DB session and verify
      the returned ``Report`` object satisfies the invariant.
    """

    # ------------------------------------------------------------------
    # Property 3a — pure logic: accumulation loop is consistent with sum()
    # ------------------------------------------------------------------

    @given(attack_counts=_attack_counts_dict)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_accumulation_loop_equals_sum(self, attack_counts):
        """
        Property 3a: Iterating over attack_counts and accumulating a running
        total produces the same result as sum(attack_counts.values()).

        This mirrors the exact loop in ObservabilityAgent._build_report:

            for attack_type, count in rows:
                report.attack_counts[attack_type] = count
                report.total_events += count

        **Validates: Requirements 11.7**
        """
        # Simulate the _build_report accumulation
        computed_total = 0
        stored_counts: dict[str, int] = {}
        for attack_type, count in attack_counts.items():
            stored_counts[attack_type] = count
            computed_total += count

        expected_total = sum(attack_counts.values())

        assert computed_total == expected_total, (
            f"Accumulation loop total {computed_total} != "
            f"sum() total {expected_total} for attack_counts={attack_counts}"
        )
        assert computed_total == sum(stored_counts.values()), (
            f"Stored counts sum {sum(stored_counts.values())} != "
            f"accumulated total {computed_total}"
        )

    # ------------------------------------------------------------------
    # Property 3b — event list: counting events by type is consistent
    # ------------------------------------------------------------------

    @given(events=_attack_event_list)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_per_type_counts_from_event_list_sum_to_total(self, events):
        """
        Property 3b: Given a list of attack events (each with an attack_type),
        grouping by type and summing the per-type counts always equals the
        total number of events.

        This validates the mathematical invariant that underlies Requirement 11.7
        regardless of the specific attack types present.

        **Validates: Requirements 11.7**
        """
        # Count events per type (mirrors what the DB GROUP BY query returns)
        per_type_counts = Counter(events)

        # Sum of per-type counts must equal total events
        total_from_counts = sum(per_type_counts.values())
        assert total_from_counts == len(events), (
            f"sum(per_type_counts) = {total_from_counts} != "
            f"len(events) = {len(events)} for events={events[:10]}..."
        )

    # ------------------------------------------------------------------
    # Property 3c — integration: _build_report satisfies the invariant
    # ------------------------------------------------------------------

    @given(attack_counts=_attack_counts_dict)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_build_report_total_events_equals_sum_of_attack_counts(
        self, attack_counts
    ):
        """
        Property 3c: After calling ``_build_report`` with mocked DB rows,
        ``Report.total_events`` equals ``sum(Report.attack_counts.values())``.

        Mocks ``get_session``, ``calculate_mttd_all``, and ``calculate_mttr_all``
        so no real database is required.

        **Validates: Requirements 11.7**
        """
        # The DB GROUP BY query returns (attack_type, count) rows
        fake_attack_rows = list(attack_counts.items())
        expected_total = sum(attack_counts.values())

        async def _run_test():
            mock_ctx = _make_mock_session(fake_attack_rows, mitigation_count=0)
            agent = ObservabilityAgent()

            with (
                patch(
                    "backend.agents.observability_agent.session_context",
                    return_value=mock_ctx,
                ),
                patch.object(
                    agent, "calculate_mttd_all", new=AsyncMock(return_value={})
                ),
                patch.object(
                    agent, "calculate_mttr_all", new=AsyncMock(return_value={})
                ),
            ):
                return await agent._build_report(
                    "daily",
                    date(2024, 1, 1),
                    date(2024, 1, 2),
                )

        report = _run(_run_test())

        assert isinstance(report, Report), "Expected a Report instance"
        assert report.total_events == expected_total, (
            f"Report.total_events={report.total_events} != "
            f"expected {expected_total} for attack_counts={attack_counts}"
        )
        assert report.total_events == sum(report.attack_counts.values()), (
            f"Report.total_events={report.total_events} != "
            f"sum(attack_counts.values())={sum(report.attack_counts.values())}"
        )

    # ------------------------------------------------------------------
    # Property 3d — None attack_type is normalised to "unknown"
    # ------------------------------------------------------------------

    @given(
        counts=st.lists(
            st.integers(min_value=1, max_value=500),
            min_size=1,
            max_size=10,
        )
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_none_attack_type_normalised_and_total_still_consistent(
        self, counts
    ):
        """
        Property 3d: When the DB returns None as an attack_type (mapped to
        "unknown" by _build_report), the total_events invariant still holds.

        **Validates: Requirements 11.7**
        """
        # Mix of None and named attack types
        fake_attack_rows = [(None, counts[0])] + [
            (f"type_{i}", c) for i, c in enumerate(counts[1:])
        ]
        expected_total = sum(counts)

        async def _run_test():
            mock_ctx = _make_mock_session(fake_attack_rows, mitigation_count=0)
            agent = ObservabilityAgent()

            with (
                patch(
                    "backend.agents.observability_agent.session_context",
                    return_value=mock_ctx,
                ),
                patch.object(
                    agent, "calculate_mttd_all", new=AsyncMock(return_value={})
                ),
                patch.object(
                    agent, "calculate_mttr_all", new=AsyncMock(return_value={})
                ),
            ):
                return await agent._build_report(
                    "daily",
                    date(2024, 1, 1),
                    date(2024, 1, 2),
                )

        report = _run(_run_test())

        assert report.total_events == expected_total, (
            f"Report.total_events={report.total_events} != "
            f"expected {expected_total}"
        )
        assert report.total_events == sum(report.attack_counts.values()), (
            f"Invariant violated: total_events={report.total_events} != "
            f"sum(attack_counts)={sum(report.attack_counts.values())}"
        )
        # None attack_type must be stored as "unknown"
        assert "unknown" in report.attack_counts, (
            "None attack_type should be normalised to 'unknown'"
        )

    # ------------------------------------------------------------------
    # Edge cases
    # ------------------------------------------------------------------

    def test_empty_attack_events_gives_zero_total(self):
        """
        Edge case: no attack events → total_events == 0 and attack_counts == {}.

        **Validates: Requirements 11.7**
        """
        async def _run_test():
            mock_ctx = _make_mock_session([], mitigation_count=0)
            agent = ObservabilityAgent()

            with (
                patch(
                    "backend.agents.observability_agent.session_context",
                    return_value=mock_ctx,
                ),
                patch.object(
                    agent, "calculate_mttd_all", new=AsyncMock(return_value={})
                ),
                patch.object(
                    agent, "calculate_mttr_all", new=AsyncMock(return_value={})
                ),
            ):
                return await agent._build_report(
                    "daily",
                    date(2024, 1, 1),
                    date(2024, 1, 2),
                )

        report = _run(_run_test())
        assert report.total_events == 0
        assert report.attack_counts == {}
        assert sum(report.attack_counts.values()) == report.total_events

    def test_single_attack_type_total_equals_its_count(self):
        """
        Edge case: single attack type → total_events equals that type's count.

        **Validates: Requirements 11.7**
        """
        async def _run_test():
            mock_ctx = _make_mock_session([("ddos", 42)], mitigation_count=0)
            agent = ObservabilityAgent()

            with (
                patch(
                    "backend.agents.observability_agent.session_context",
                    return_value=mock_ctx,
                ),
                patch.object(
                    agent, "calculate_mttd_all", new=AsyncMock(return_value={})
                ),
                patch.object(
                    agent, "calculate_mttr_all", new=AsyncMock(return_value={})
                ),
            ):
                return await agent._build_report(
                    "daily",
                    date(2024, 1, 1),
                    date(2024, 1, 2),
                )

        report = _run(_run_test())
        assert report.total_events == 42
        assert report.attack_counts == {"ddos": 42}
        assert sum(report.attack_counts.values()) == report.total_events

    def test_multiple_attack_types_total_is_sum_of_all(self):
        """
        Edge case: multiple attack types → total_events is the sum of all counts.

        **Validates: Requirements 11.7**
        """
        fake_rows = [
            ("ddos", 100),
            ("port_scan", 50),
            ("brute_force", 25),
            ("mitm", 10),
        ]
        expected_total = 185

        async def _run_test():
            mock_ctx = _make_mock_session(fake_rows, mitigation_count=0)
            agent = ObservabilityAgent()

            with (
                patch(
                    "backend.agents.observability_agent.session_context",
                    return_value=mock_ctx,
                ),
                patch.object(
                    agent, "calculate_mttd_all", new=AsyncMock(return_value={})
                ),
                patch.object(
                    agent, "calculate_mttr_all", new=AsyncMock(return_value={})
                ),
            ):
                return await agent._build_report(
                    "daily",
                    date(2024, 1, 1),
                    date(2024, 1, 2),
                )

        report = _run(_run_test())
        assert report.total_events == expected_total
        assert sum(report.attack_counts.values()) == report.total_events

    def test_zero_count_attack_type_included_in_total(self):
        """
        Edge case: an attack type with count 0 contributes 0 to total_events.
        The invariant still holds.

        **Validates: Requirements 11.7**
        """
        fake_rows = [("ddos", 10), ("port_scan", 0), ("brute_force", 5)]
        expected_total = 15

        async def _run_test():
            mock_ctx = _make_mock_session(fake_rows, mitigation_count=0)
            agent = ObservabilityAgent()

            with (
                patch(
                    "backend.agents.observability_agent.session_context",
                    return_value=mock_ctx,
                ),
                patch.object(
                    agent, "calculate_mttd_all", new=AsyncMock(return_value={})
                ),
                patch.object(
                    agent, "calculate_mttr_all", new=AsyncMock(return_value={})
                ),
            ):
                return await agent._build_report(
                    "daily",
                    date(2024, 1, 1),
                    date(2024, 1, 2),
                )

        report = _run(_run_test())
        assert report.total_events == expected_total
        assert sum(report.attack_counts.values()) == report.total_events
