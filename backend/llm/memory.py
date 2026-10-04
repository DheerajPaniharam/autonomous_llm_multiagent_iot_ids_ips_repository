"""
Sliding-window conversation memory per incident for LLM context.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class IncidentMemory:
    """Stores recent LLM exchanges for a single incident."""
    incident_id: str
    max_turns: int = 10
    _history: deque = field(default_factory=lambda: deque(maxlen=10))

    def add(self, role: str, content: str) -> None:
        self._history.append({
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def get_context(self) -> list[dict]:
        return list(self._history)

    def clear(self) -> None:
        self._history.clear()


class MemoryStore:
    """Global store of per-incident memories."""

    def __init__(self) -> None:
        self._memories: dict[str, IncidentMemory] = {}

    def get_or_create(self, incident_id: str) -> IncidentMemory:
        if incident_id not in self._memories:
            self._memories[incident_id] = IncidentMemory(incident_id=incident_id)
        return self._memories[incident_id]

    def clear(self, incident_id: str) -> None:
        self._memories.pop(incident_id, None)


memory_store = MemoryStore()
