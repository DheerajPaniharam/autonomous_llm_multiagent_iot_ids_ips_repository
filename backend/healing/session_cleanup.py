"""
Session cleanup — clears stale nftables rules and connection tracking.
"""
from __future__ import annotations

import asyncio
import logging

from backend.firewall import nftables_manager

logger = logging.getLogger(__name__)


async def clear_stale_rules() -> int:
    """Remove expired nftables rules. Returns count removed."""
    loop = asyncio.get_event_loop()
    removed = await loop.run_in_executor(None, nftables_manager.clear_expired_rules)
    if removed:
        logger.info("Cleared %d stale firewall rules", removed)
    return removed


async def reset_connection_tracking() -> None:
    """Flush conntrack table (Linux only)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "conntrack", "-F",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        logger.info("Connection tracking table flushed")
    except FileNotFoundError:
        logger.debug("conntrack not available — skipping")
