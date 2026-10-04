"""
Rate limiter — tracks per-IP request rates and applies soft limits.
"""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta


class RateLimiter:
    """Sliding-window rate limiter per source IP."""

    def __init__(self, window_seconds: int = 60, max_requests: int = 1000) -> None:
        self._window = window_seconds
        self._max = max_requests
        self._buckets: dict[str, deque] = defaultdict(deque)

    def is_rate_limited(self, ip: str) -> bool:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self._window)
        bucket = self._buckets[ip]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        bucket.append(now)
        return len(bucket) > self._max

    def get_rate(self, ip: str) -> float:
        """Return requests/second for the given IP."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self._window)
        bucket = self._buckets[ip]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return len(bucket) / self._window
