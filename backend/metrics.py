"""
Lightweight in-memory metrics counters for the IoT IDS/IPS system.

Prometheus integration is a planned future improvement.
All public functions here are intentional no-ops so the rest of the
codebase can call them unchanged — wiring up a real metrics backend
later requires only changes to this file and metrics_endpoint.py.

Future improvement: replace this module with prometheus_client counters
and expose them at /metrics for Prometheus scraping.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.agents.queues import AgentQueues

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory counters (simple thread-safe-enough for asyncio single-thread use)
# ---------------------------------------------------------------------------

_events_processed: dict[str, int] = defaultdict(int)
_mitigations_applied: dict[str, int] = defaultdict(int)
_ml_latencies: dict[str, list[float]] = defaultdict(list)
_packet_drops: int = 0
_total_bytes_processed: int = 0
_total_packets_processed: int = 0
_current_kbps: float = 0.0
_current_pps: float = 0.0



# ---------------------------------------------------------------------------
# Public API — same signatures as the prometheus_client version
# ---------------------------------------------------------------------------

def increment_events_processed(agent: str) -> None:
    """Count events processed per agent."""
    _events_processed[agent] += 1


def observe_ml_latency(model: str, latency_seconds: float) -> None:
    """Record an ML inference latency sample (keeps last 1000 per model)."""
    buf = _ml_latencies[model]
    buf.append(latency_seconds)
    if len(buf) > 1000:
        buf.pop(0)


def increment_mitigations(action: str) -> None:
    """Count mitigations applied per action type."""
    _mitigations_applied[action] += 1


def increment_packet_drops(count: int = 1) -> None:
    """Count dropped packets."""
    global _packet_drops
    _packet_drops += count


def update_queue_depths(queues: "AgentQueues") -> None:
    """No-op — queue depths are read live from AgentQueues in the API."""
    pass


def update_incidents_active(count: int) -> None:
    """No-op — active incident count is queried live from the DB in the API."""
    pass


async def update_incidents_active_from_db() -> None:
    """No-op — kept for API compatibility."""
    pass


# ---------------------------------------------------------------------------
# Snapshot helpers (used by /api/v1/metrics endpoint)
# ---------------------------------------------------------------------------

def get_events_processed() -> dict[str, int]:
    return dict(_events_processed)


def get_mitigations_applied() -> dict[str, int]:
    return dict(_mitigations_applied)


def get_packet_drops() -> int:
    return _packet_drops


def get_ml_latency_stats() -> dict[str, dict[str, float]]:
    """Return p50/p95/p99 latency in milliseconds for each model."""
    result: dict[str, dict[str, float]] = {}
    for model, samples in _ml_latencies.items():
        if not samples:
            result[model] = {"p50": 0.0, "p95": 0.0, "p99": 0.0}
            continue
        arr = sorted(samples)
        n = len(arr)
        result[model] = {
            "p50": arr[int(n * 0.50)] * 1000,
            "p95": arr[int(n * 0.95)] * 1000,
            "p99": arr[min(int(n * 0.99), n - 1)] * 1000,
        }
    return result


def add_network_stats(bytes_count: float, packets_count: float) -> None:
    """Accumulate total bytes and packets processed by the traffic agent."""
    global _total_bytes_processed, _total_packets_processed
    _total_bytes_processed += int(bytes_count)
    _total_packets_processed += int(packets_count)


def get_network_stats() -> tuple[int, int]:
    """Retrieve total bytes and packets processed."""
    return _total_bytes_processed, _total_packets_processed


def update_current_rates(kbps: float, pps: float) -> None:
    """Update current network throughput rates."""
    global _current_kbps, _current_pps
    _current_kbps = kbps
    _current_pps = pps


def get_current_rates() -> tuple[float, float]:
    """Get current network throughput rates."""
    return _current_kbps, _current_pps

