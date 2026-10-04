"""
nftables manager — adds/removes firewall rules via subprocess.
All operations are idempotent and logged.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import subprocess
import uuid
import re
from datetime import datetime, timedelta
from typing import NamedTuple

def _is_simulation_mode() -> bool:
    """Return True when firewall execution should be treated as simulation-only."""
    return os.environ.get("FIREWALL_MODE", "production").strip().lower() == "simulation"

logger = logging.getLogger(__name__)


class FirewallRule(NamedTuple):
    rule_id: str
    ip: str
    action: str          # drop or rate_limit
    chain: str           # INPUT
    expires_at: datetime | None


_active_rules: dict[str, FirewallRule] = {}
_FIREWALL_TABLE = "inet"
_FIREWALL_CHAIN = "ids"
_FIREWALL_HOOK_CHAIN = "input"


def _chain_target() -> list[str]:
    return [_FIREWALL_TABLE, _FIREWALL_CHAIN, _FIREWALL_HOOK_CHAIN]


def _run(cmd: list[str]) -> tuple[bool, str]:
    """Execute an nftables command. Returns (success, stdout)."""
    if _is_simulation_mode():
        rendered = " ".join(cmd)
        logger.info("FIREWALL_MODE=simulation: dry-run nftables command: %s", rendered)
        return True, "simulation"

    executor_socket = os.environ.get("FIREWALL_EXECUTOR_SOCKET", "").strip()
    if executor_socket:
        request = (json.dumps({"command": cmd}) + "\n").encode()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(executor_socket)
                client.sendall(request)
                response = b""
                while not response.endswith(b"\n"):
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            result = json.loads(response.decode())
            if result.get("ok"):
                return True, result.get("stdout", "")
            logger.error("Firewall executor rejected nftables command: %s", result.get("error", "unknown error"))
            return False, result.get("error", "firewall executor rejected command")
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Firewall executor unavailable: %s", exc)
            return False, str(exc)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            logger.warning("nftables error: %s", result.stderr.strip())
            return False, result.stderr
        return True, result.stdout
    except FileNotFoundError:
        logger.error("nftables not found while FIREWALL_MODE=production")
        return False, "nftables not found"
    except subprocess.TimeoutExpired:
        logger.error("nftables command timed out: %s", " ".join(cmd))
        return False, ""


def _delete_kernel_rules_for_ip(ip: str) -> None:
    """Scan INPUT chain and delete any rules matching the IP and our comment tags."""
    list_cmd = ["nft", "-a", "list", "chain", *_chain_target()]
    success, stdout = _run(list_cmd)
    if not success or "nftables not found" in stdout or "nftables simulation" in stdout:
        return

    # Find rules like: ip saddr 1.2.3.4 counter drop comment "ids-block-abc12345" # handle 54
    # or ip saddr 1.2.3.4 limit rate 100/second counter accept comment "ids-ratelimit-abc12345" # handle 55
    lines = stdout.splitlines()
    for line in lines:
        if ip in line and ("ids-block-" in line or "ids-ratelimit-" in line):
            handle_match = re.search(r'handle (\d+)', line)
            if handle_match:
                handle = handle_match.group(1)
                del_cmd = ["nft", "delete", "rule", *_chain_target(), "handle", handle]
                _run(del_cmd)


def add_block_rule(ip: str, ttl_seconds: int) -> str:
    """Block all traffic from `ip` for `ttl_seconds`. Returns rule_id."""
    # Check if a rule for this IP already exists in-memory
    for rid, rule in list(_active_rules.items()):
        if rule.ip == ip and rule.action == "drop":
            expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
            _active_rules[rid] = rule._replace(expires_at=expires_at)
            logger.info("Renewed block on %s for %ds (rule=%s)", ip, ttl_seconds, rid)
            return rid

    # Delete any preexisting rules in nftables for this IP to prevent duplicates
    _delete_kernel_rules_for_ip(ip)

    rule_id = str(uuid.uuid4())[:8]
    cmd = [
        "nft", "insert", "rule", *_chain_target(),
        "ip", "saddr", ip, "counter", "drop", 
        "comment", f"ids-block-{rule_id}"
    ]
    success, _ = _run(cmd)
    if success:
        expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
        _active_rules[rule_id] = FirewallRule(rule_id, ip, "drop", "INPUT", expires_at)
        logger.info("Blocked %s for %ds (rule=%s)", ip, ttl_seconds, rule_id)
    return rule_id


def add_rate_limit_rule(
    ip: str, pps_limit: int = 100, ttl_seconds: int = 1800
) -> str:
    """Drop traffic from `ip` above `pps_limit` until its TTL expires."""
    if pps_limit < 1:
        raise ValueError("pps_limit must be at least 1")
    if ttl_seconds < 1:
        raise ValueError("ttl_seconds must be at least 1")

    # Check if a rule for this IP already exists in-memory
    for rid, rule in list(_active_rules.items()):
        if rule.ip == ip and rule.action == "rate_limit":
            expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
            _active_rules[rid] = rule._replace(expires_at=expires_at)
            logger.info("Renewed rate limit on %s for %ds (rule=%s)", ip, ttl_seconds, rid)
            return rid

    # Delete any preexisting rules in nftables for this IP to prevent duplicates
    _delete_kernel_rules_for_ip(ip)

    rule_id = str(uuid.uuid4())[:8]
    cmd = [
        "nft", "insert", "rule", *_chain_target(),
        "ip", "saddr", ip, "limit", "rate", "over",
        f"{pps_limit}/second", "counter", "drop",
        "comment", f"ids-ratelimit-{rule_id}"
    ]
    success, _ = _run(cmd)
    if success:
        expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
        _active_rules[rule_id] = FirewallRule(rule_id, ip, "rate_limit", "INPUT", expires_at)
        logger.info(
            "Rate-limited %s above %d pps for %ds (rule=%s)",
            ip, pps_limit, ttl_seconds, rule_id,
        )
    return rule_id


def remove_rule(rule_id: str) -> bool:
    """Remove a rule by its ID."""
    rule = _active_rules.get(rule_id)
    if not rule:
        return False

    comment_tag = f"ids-ratelimit-{rule_id}" if rule.action == "rate_limit" else f"ids-block-{rule_id}"

    list_cmd = ["nft", "-a", "list", "chain", *_chain_target()]
    success, stdout = _run(list_cmd)

    if not success:
        if "nftables not found" in stdout:
            # The kernel rule cannot exist when nft is unavailable, so local
            # state can be removed safely.
            del _active_rules[rule_id]
            logger.info("Removed rule %s for %s (nftables unavailable)", rule_id, rule.ip)
            return True
        return False

    if _is_simulation_mode() or "nftables not found" in stdout or stdout == "simulation":
        # Simulation mode
        del _active_rules[rule_id]
        logger.info("Removed rule %s for %s (simulation)", rule_id, rule.ip)
        return True

    # Parse the handle from output
    # Example: rule ip saddr 1.2.3.4 counter drop comment "ids-block-abc12345" # handle 54
    handle_match = re.search(fr'{comment_tag}".*?handle (\d+)', stdout)
    
    # Handle the case where quotes are not in stdout depending on nftables version
    if not handle_match:
        handle_match = re.search(fr'{comment_tag}.*?handle (\d+)', stdout)

    if handle_match:
        handle = handle_match.group(1)
        del_cmd = ["nft", "delete", "rule", *_chain_target(), "handle", handle]
        del_success, _ = _run(del_cmd)
        if del_success:
            del _active_rules[rule_id]
            logger.info("Removed rule %s for %s", rule_id, rule.ip)
            return True
        return False
    else:
        logger.warning("Could not find handle for rule %s", rule_id)
        return False


def list_rules() -> list[FirewallRule]:
    return list(_active_rules.values())


def clear_expired_rules() -> int:
    """Remove all rules past their expiry time. Returns count removed."""
    now = datetime.utcnow()
    expired = [
        rid for rid, rule in _active_rules.items()
        if rule.expires_at and rule.expires_at <= now
    ]
    for rid in expired:
        remove_rule(rid)
    return len(expired)
