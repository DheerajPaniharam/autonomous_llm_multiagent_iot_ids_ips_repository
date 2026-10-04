"""
Async message queue infrastructure for inter-agent communication.
All queues are bounded (capacity=1000) to enforce backpressure.
A shared singleton is used so all agents reference the same queues.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from itertools import count

from backend.metrics import increment_packet_drops

logger = logging.getLogger(__name__)

QUEUE_CAPACITY = 1000
_PRIORITY_SEQ = count()

# Packet-drop counter (incremented when detection/anomaly queues are full)
_packet_drops: int = 0


def get_packet_drops() -> int:
    return _packet_drops


@dataclass
class AgentQueues:
    """Holds all bounded asyncio.Queue instances for the agent pipeline."""
    detection_queue:     asyncio.Queue   # FeatureVector → Analysis Agent
    anomaly_queue:       asyncio.Queue   # FeatureVector → Analysis Agent
    risk_queue:          asyncio.Queue   # ThreatScore   → Orchestrator
    orchestrator_queue:  asyncio.Queue   # Back-compat alias for the orchestrator intake queue
    prevention_queue:    asyncio.Queue   # MitigationCommand → Response Agent
    healing_queue:       asyncio.Queue   # HealingCommand    → Response Agent
    logging_queue:       asyncio.Queue   # LogEntry          → Observability Agent


_queues: AgentQueues | None = None


def get_queues() -> AgentQueues:
    """Return the singleton AgentQueues, creating it if necessary."""
    global _queues
    if _queues is None:
        risk_queue = asyncio.Queue(maxsize=QUEUE_CAPACITY)
        _queues = AgentQueues(
            detection_queue    = asyncio.Queue(maxsize=QUEUE_CAPACITY),
            anomaly_queue      = asyncio.Queue(maxsize=QUEUE_CAPACITY),
            risk_queue         = risk_queue,
            orchestrator_queue = asyncio.PriorityQueue(maxsize=QUEUE_CAPACITY),
            prevention_queue   = asyncio.Queue(maxsize=QUEUE_CAPACITY),
            healing_queue      = asyncio.Queue(maxsize=QUEUE_CAPACITY),
            logging_queue      = asyncio.Queue(maxsize=QUEUE_CAPACITY * 10),  # larger buffer
        )
    return _queues


async def safe_put(queue: asyncio.Queue, item: object, drop_counter: bool = False) -> bool:
    """
    Non-blocking put. If the queue is full, drops the item and logs a warning.
    Returns True if item was enqueued, False if dropped.

    PriorityQueue items are normalized to ``(priority, seq, payload)`` so ties do not
    trigger ``TypeError`` when heapq compares payload objects.
    """
    global _packet_drops
    try:
        normalized_item = item
        if isinstance(queue, asyncio.PriorityQueue) and isinstance(item, tuple) and len(item) == 2:
            priority, payload = item
            normalized_item = (priority, next(_PRIORITY_SEQ), payload)
        queue.put_nowait(normalized_item)
        return True
    except asyncio.QueueFull:
        if drop_counter:
            _packet_drops += 1
            increment_packet_drops()
        logger.warning(
            "Queue full (%s items) — dropping item. Total drops: %d",
            queue.maxsize,
            _packet_drops,
        )
        return False
