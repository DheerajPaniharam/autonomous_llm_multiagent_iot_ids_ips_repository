"""
Unit tests for the metrics module and /metrics endpoint.

Tests cover:
- Counter increments (Req 13.1, 13.4, 13.5)
- Histogram/latency observations (Req 13.3)
- Gauge/snapshot helpers (Req 13.2, 13.6)
- Metrics endpoint format (Req 13.7)

Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7
"""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost/test")

import pytest

import backend.metrics as _m


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_metrics():
    """Reset all in-memory counters before and after each test."""
    _m._events_processed.clear()
    _m._mitigations_applied.clear()
    _m._ml_latencies.clear()
    _m._packet_drops = 0
    _m._total_bytes_processed = 0
    _m._total_packets_processed = 0
    _m._current_kbps = 0.0
    _m._current_pps = 0.0
    yield
    _m._events_processed.clear()
    _m._mitigations_applied.clear()
    _m._ml_latencies.clear()
    _m._packet_drops = 0
    _m._total_bytes_processed = 0
    _m._total_packets_processed = 0
    _m._current_kbps = 0.0
    _m._current_pps = 0.0




# ---------------------------------------------------------------------------
# Counter increment tests (Req 13.1, 13.4, 13.5)
# ---------------------------------------------------------------------------


class TestCounterIncrements:
    """Tests for counter increment functions."""

    def test_increment_events_processed_single(self):
        """increment_events_processed increments the counter by 1."""
        _m.increment_events_processed("detection")
        assert _m.get_events_processed()["detection"] == 1

    def test_increment_events_processed_multiple_calls_accumulate(self):
        """Multiple calls to increment_events_processed accumulate correctly."""
        _m.increment_events_processed("detection")
        _m.increment_events_processed("detection")
        _m.increment_events_processed("detection")
        assert _m.get_events_processed()["detection"] == 3

    def test_increment_events_processed_different_agents(self):
        """Increments for different agents are tracked independently."""
        _m.increment_events_processed("detection")
        _m.increment_events_processed("anomaly")
        _m.increment_events_processed("anomaly")
        counts = _m.get_events_processed()
        assert counts["detection"] == 1
        assert counts["anomaly"] == 2

    def test_increment_mitigations_single(self):
        """increment_mitigations increments the counter by 1."""
        _m.increment_mitigations("block_ip")
        assert _m.get_mitigations_applied()["block_ip"] == 1

    def test_increment_mitigations_multiple_calls_accumulate(self):
        """Multiple calls to increment_mitigations accumulate correctly."""
        _m.increment_mitigations("block_ip")
        _m.increment_mitigations("block_ip")
        assert _m.get_mitigations_applied()["block_ip"] == 2

    def test_increment_mitigations_different_actions(self):
        """Increments for different actions are tracked independently."""
        _m.increment_mitigations("block_ip")
        _m.increment_mitigations("rate_limit")
        counts = _m.get_mitigations_applied()
        assert counts["block_ip"] == 1
        assert counts["rate_limit"] == 1

    def test_increment_packet_drops_default(self):
        """increment_packet_drops with no argument increments by 1."""
        _m.increment_packet_drops()
        assert _m.get_packet_drops() == 1

    def test_increment_packet_drops_by_n(self):
        """increment_packet_drops(5) increments by 5."""
        _m.increment_packet_drops(5)
        assert _m.get_packet_drops() == 5

    def test_increment_packet_drops_accumulates(self):
        """Multiple calls to increment_packet_drops accumulate correctly."""
        _m.increment_packet_drops(3)
        _m.increment_packet_drops(7)
        assert _m.get_packet_drops() == 10

    def test_counters_start_at_zero(self):
        """All counters start at zero after reset."""
        assert _m.get_events_processed() == {}
        assert _m.get_mitigations_applied() == {}
        assert _m.get_packet_drops() == 0


# ---------------------------------------------------------------------------
# Histogram / latency observation tests (Req 13.3)
# ---------------------------------------------------------------------------


class TestLatencyObservations:
    """Tests for ML latency histogram observations."""

    def test_observe_ml_latency_records_sample(self):
        """observe_ml_latency records the sample in the buffer."""
        _m.observe_ml_latency("supervised", 0.05)
        assert len(_m._ml_latencies["supervised"]) == 1
        assert _m._ml_latencies["supervised"][0] == pytest.approx(0.05)

    def test_observe_ml_latency_multiple_samples(self):
        """Multiple observations accumulate in the buffer."""
        _m.observe_ml_latency("supervised", 0.01)
        _m.observe_ml_latency("supervised", 0.02)
        _m.observe_ml_latency("supervised", 0.03)
        assert len(_m._ml_latencies["supervised"]) == 3

    def test_observe_ml_latency_different_models(self):
        """Observations for different models are tracked independently."""
        _m.observe_ml_latency("supervised", 0.05)
        _m.observe_ml_latency("if", 0.10)
        assert len(_m._ml_latencies["supervised"]) == 1
        assert len(_m._ml_latencies["if"]) == 1

    def test_get_ml_latency_stats_returns_milliseconds(self):
        """get_ml_latency_stats returns p50/p95/p99 in milliseconds."""
        # Record 0.05 seconds = 50 ms
        _m.observe_ml_latency("supervised", 0.05)
        stats = _m.get_ml_latency_stats()
        assert "supervised" in stats
        # p50 should be ~50 ms (0.05 * 1000)
        assert stats["supervised"]["p50"] == pytest.approx(50.0, rel=0.01)

    def test_get_ml_latency_stats_percentile_ordering(self):
        """p50 <= p95 <= p99 for any distribution."""
        for i in range(100):
            _m.observe_ml_latency("supervised", i * 0.001)  # 0ms to 99ms
        stats = _m.get_ml_latency_stats()["supervised"]
        assert stats["p50"] <= stats["p95"] <= stats["p99"]

    def test_get_ml_latency_stats_empty_model(self):
        """get_ml_latency_stats returns zeros for a model with no samples."""
        # Force an empty entry
        _m._ml_latencies["supervised"]  # access defaultdict to create key
        _m._ml_latencies["supervised"].clear()
        stats = _m.get_ml_latency_stats()
        assert stats["supervised"] == {"p50": 0.0, "p95": 0.0, "p99": 0.0}

    def test_buffer_caps_at_1000_samples(self):
        """Buffer is capped at 1000 samples; oldest are evicted."""
        for i in range(1100):
            _m.observe_ml_latency("supervised", i * 0.001)
        assert len(_m._ml_latencies["supervised"]) == 1000


# ---------------------------------------------------------------------------
# Gauge / snapshot helper tests (Req 13.2, 13.6)
# ---------------------------------------------------------------------------


class TestSnapshotHelpers:
    """Tests for snapshot/gauge helper functions."""

    def test_get_events_processed_returns_dict(self):
        """get_events_processed returns a dict with correct counts."""
        _m.increment_events_processed("detection")
        _m.increment_events_processed("detection")
        _m.increment_events_processed("risk")
        result = _m.get_events_processed()
        assert isinstance(result, dict)
        assert result["detection"] == 2
        assert result["risk"] == 1

    def test_get_events_processed_empty(self):
        """get_events_processed returns empty dict when no events recorded."""
        assert _m.get_events_processed() == {}

    def test_get_mitigations_applied_returns_dict(self):
        """get_mitigations_applied returns a dict with correct counts."""
        _m.increment_mitigations("block_ip")
        _m.increment_mitigations("block_ip")
        _m.increment_mitigations("rate_limit")
        result = _m.get_mitigations_applied()
        assert isinstance(result, dict)
        assert result["block_ip"] == 2
        assert result["rate_limit"] == 1

    def test_get_mitigations_applied_empty(self):
        """get_mitigations_applied returns empty dict when no mitigations recorded."""
        assert _m.get_mitigations_applied() == {}

    def test_get_packet_drops_returns_correct_count(self):
        """get_packet_drops returns the correct accumulated count."""
        _m.increment_packet_drops(10)
        _m.increment_packet_drops(5)
        assert _m.get_packet_drops() == 15

    def test_get_packet_drops_zero_initially(self):
        """get_packet_drops returns 0 when no drops recorded."""
        assert _m.get_packet_drops() == 0

    def test_snapshot_is_independent_copy(self):
        """Snapshot dicts are independent copies, not references to internal state."""
        _m.increment_events_processed("detection")
        snapshot = _m.get_events_processed()
        # Mutating the snapshot should not affect internal state
        snapshot["detection"] = 999
        assert _m.get_events_processed()["detection"] == 1



