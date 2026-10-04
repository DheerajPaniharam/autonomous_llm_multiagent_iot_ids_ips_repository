"""
Log parser — converts raw Suricata/Zeek log lines to structured dicts.
"""
from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)


def parse_suricata_line(line: str) -> dict | None:
    """Parse a Suricata eve.json line."""
    try:
        return json.loads(line.strip())
    except json.JSONDecodeError:
        return None


def parse_zeek_line(line: str, columns: list[str], sep: str = "\t") -> dict | None:
    """Parse a Zeek TSV log line given column headers."""
    if line.startswith("#") or not line.strip():
        return None
    parts = line.strip().split(sep)
    if len(parts) != len(columns):
        return None
    return dict(zip(columns, parts))
