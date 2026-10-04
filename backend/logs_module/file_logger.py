"""
File logger — appends structured LogEntry records to a local log file.
"""
from __future__ import annotations

import json
import logging
import os
from backend.models.messages import LogEntry

logger = logging.getLogger(__name__)

_LOG_FILE_PATH = os.environ.get("APP_LOG_PATH", "logs/ids_system.log")

# Ensure directory exists
if os.path.dirname(_LOG_FILE_PATH):
    os.makedirs(os.path.dirname(_LOG_FILE_PATH), exist_ok=True)


async def write_to_log_file(entry: LogEntry) -> bool:
    """Append LogEntry to local log file as a single JSON line."""
    payload = {
        "timestamp": entry.timestamp.isoformat(),
        "level": entry.level,
        "source_agent": entry.source_agent,
        "event_type": entry.event_type,
        **entry.payload,
    }
    try:
        # Open file and append line synchronously in executor
        import asyncio
        def _append():
            with open(_LOG_FILE_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
        
        await asyncio.get_event_loop().run_in_executor(None, _append)
        return True
    except Exception as exc:
        logger.error("Failed to write log entry to file: %s", exc)
        raise
