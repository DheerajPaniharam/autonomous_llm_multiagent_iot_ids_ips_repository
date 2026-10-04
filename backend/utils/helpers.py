"""
Shared utility functions for the IoT IDS/IPS system.

Provides IP validation, timestamp helpers, flow ID generation,
safe dict access, severity derivation, and other small utilities
used across multiple agents and API handlers.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# IP address utilities
# ---------------------------------------------------------------------------

def is_valid_ip(ip: str) -> bool:
    """Return True if `ip` is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Return True if `ip` is a private/RFC-1918 address."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def anonymize_ip(ip: str, mask_last_octet: bool = True) -> str:
    """
    Anonymize an IP address for privacy mode.

    IPv4: replaces the last octet with 0  (e.g. 192.168.1.100 → 192.168.1.0)
    IPv6: replaces the last 64 bits with ::  (e.g. 2001:db8::1 → 2001:db8::)
    """
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            parts = ip.split(".")
            parts[-1] = "0"
            return ".".join(parts)
        else:
            # IPv6 — zero out the last 64 bits
            packed = addr.packed
            return str(ipaddress.IPv6Address(packed[:8] + b"\x00" * 8))
    except ValueError:
        return ip  # return as-is if unparseable


def ip_in_list(ip: str, ip_list: list[str]) -> bool:
    """
    Return True if `ip` matches any entry in `ip_list`.
    Entries may be individual IPs or CIDR networks (e.g. "10.0.0.0/8").
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for entry in ip_list:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------------------
# Timestamp utilities
# ---------------------------------------------------------------------------

def utcnow() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


def utcnow_naive() -> datetime:
    """Return the current UTC datetime without timezone info (for DB compat)."""
    return datetime.utcnow()


def format_iso(dt: datetime) -> str:
    """Format a datetime as an ISO 8601 string with Z suffix."""
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def seconds_between(start: datetime, end: datetime) -> float:
    """Return the number of seconds between two datetimes (end - start)."""
    delta = end - start
    return delta.total_seconds()


# ---------------------------------------------------------------------------
# Flow ID helpers
# ---------------------------------------------------------------------------

def compute_flow_id(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    timestamp: datetime,
    bucket_seconds: int = 10,
) -> str:
    """
    Compute a deterministic flow identifier.

    Flows within the same `bucket_seconds` window with identical
    (src_ip, src_port, dst_ip, dst_port, protocol) share the same ID.
    """
    bucket = int(timestamp.timestamp() / bucket_seconds) * bucket_seconds
    raw = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}-{bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Severity derivation
# ---------------------------------------------------------------------------

def derive_severity(composite_score: float) -> str:
    """
    Map a composite score to a severity label.

    Returns one of: "medium", "high", "critical"
    """
    if composite_score >= 0.9:
        return "critical"
    if composite_score >= 0.75:
        return "high"
    return "medium"


# ---------------------------------------------------------------------------
# Safe dict / attribute access
# ---------------------------------------------------------------------------

def safe_get(d: dict, *keys: str, default: Any = None) -> Any:
    """
    Safely traverse a nested dict using a sequence of keys.

    Example:
        safe_get(data, "a", "b", "c", default=0)
        # equivalent to data.get("a", {}).get("b", {}).get("c", 0)
    """
    current = d
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current


def flatten_dict(d: dict, parent_key: str = "", sep: str = ".") -> dict:
    """
    Flatten a nested dict into a single-level dict with dotted keys.

    Example:
        flatten_dict({"a": {"b": 1, "c": 2}})
        # → {"a.b": 1, "a.c": 2}
    """
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


# ---------------------------------------------------------------------------
# String / text utilities
# ---------------------------------------------------------------------------

def truncate(text: str, max_length: int = 200, suffix: str = "…") -> str:
    """Truncate `text` to `max_length` characters, appending `suffix` if cut."""
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def slugify(text: str) -> str:
    """Convert a string to a lowercase slug (letters, digits, hyphens only)."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    return text


# ---------------------------------------------------------------------------
# Numeric utilities
# ---------------------------------------------------------------------------

def clamp(value: float, lo: float, hi: float) -> float:
    """Clamp `value` to the range [lo, hi]."""
    return max(lo, min(hi, value))


def safe_mean(values: list[float]) -> float:
    """Return the mean of `values`, or 0.0 if the list is empty."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def safe_std(values: list[float]) -> float:
    """Return the population standard deviation of `values`, or 0.0 if empty."""
    if len(values) < 2:
        return 0.0
    mean = safe_mean(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return variance ** 0.5
