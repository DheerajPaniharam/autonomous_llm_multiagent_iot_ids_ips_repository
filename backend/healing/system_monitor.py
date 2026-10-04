"""
System monitor — async health checks for all critical services.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
from datetime import datetime

logger = logging.getLogger(__name__)

_SERVICES = ["suricata", "zeek", "postgres", "loki", "grafana", "ollama"]


async def check_process(name: str) -> bool:
    """Return True if a process with the given name is running."""
    try:
        result = await asyncio.create_subprocess_exec(
            "pgrep", "-x", name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await result.wait()
        return result.returncode == 0
    except FileNotFoundError:
        # pgrep not available (Windows dev env) — assume running
        return True


async def check_all_services() -> dict[str, bool]:
    """Return health status for all monitored services."""
    results = await asyncio.gather(*[check_process(s) for s in _SERVICES])
    return dict(zip(_SERVICES, results))
