"""
Service restart utilities with retry logic (max 3 attempts, exponential backoff).

Supports three restart strategies in order of preference:
  1. Docker container restart  (docker restart <name>)
  2. systemctl restart         (Linux systemd)
  3. Graceful no-op            (dev/test environments without Docker or systemd)
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time

logger = logging.getLogger(__name__)

_MAX_ATTEMPTS = 3
_BACKOFF_BASE = 2  # seconds
_PERMISSION_DENIED_COOLDOWN_SECONDS = 300
_permission_denied_until: dict[str, float] = {}

# Map logical service names to Docker container names / systemd unit names
_DOCKER_NAMES: dict[str, str] = {
    "suricata":       "suricata",
    "zeek":           "zeek",
    "postgres":       "ids-db-1",
    "loki":           "ids-loki-1",
    "grafana":        "ids-grafana-1",
    "promtail":       "ids-promtail-1",
    "ollama":         "ids-ollama-1",
    "api":            "ids-api-1",
}

_SYSTEMD_NAMES: dict[str, str] = {
    "suricata":       "suricata",
    "zeek":           "zeek",
    "postgres":       "postgresql",
    "loki":           "loki",
    "grafana":        "grafana",
    "promtail":       "promtail",
    "ollama":         "ollama",
}


def _mark_permission_denied(service: str) -> None:
    _permission_denied_until[service] = time.monotonic() + _PERMISSION_DENIED_COOLDOWN_SECONDS


def is_permission_denied(service: str) -> bool:
    expires_at = _permission_denied_until.get(service, 0.0)
    if not expires_at:
        return False
    if time.monotonic() >= expires_at:
        _permission_denied_until.pop(service, None)
        return False
    return True


async def _try_docker_restart(service: str) -> bool:
    """Attempt `docker restart <container>`. Returns True on success."""
    if not shutil.which("docker"):
        return False
    container = _DOCKER_NAMES.get(service, service)
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "restart", container,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        if proc.returncode == 0:
            logger.info("Docker restart succeeded for %s (container=%s)", service, container)
            return True
        logger.warning("Docker restart failed for %s: %s", service, stderr.decode().strip())
        return False
    except asyncio.TimeoutError:
        logger.error("Docker restart timed out for %s", service)
        return False
    except Exception as exc:
        logger.warning("Docker restart error for %s: %s", service, exc)
        return False


async def _try_systemctl_restart(service: str) -> tuple[bool, bool]:
    """Attempt `systemctl restart <unit>`. Returns True on success."""
    if not shutil.which("systemctl"):
        return False, False
    unit = _SYSTEMD_NAMES.get(service, service)
    try:
        proc = await asyncio.create_subprocess_exec(
            "systemctl", "restart", unit,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode == 0:
            logger.info("systemctl restart succeeded for %s (unit=%s)", service, unit)
            return True, False
        err = stderr.decode().strip()
        # Detect permission/authentication failures to avoid tight retry loops
        perm_fail = False
        if any(tok in err.lower() for tok in ("access denied", "authentication", "permission", "failed to start")):
            perm_fail = True
            _mark_permission_denied(service)
            logger.warning("systemctl restart permission error for %s: %s", service, err)
        else:
            logger.warning("systemctl restart failed for %s: %s", service, err)
        return False, perm_fail
    except asyncio.TimeoutError:
        logger.error("systemctl restart timed out for %s", service)
        return False, False
    except Exception as exc:
        logger.warning("systemctl restart error for %s: %s", service, exc)
        return False, False


async def restart_service(service: str, attempt: int = 1) -> bool:
    """
    Attempt to restart a service using Docker or systemctl.
    Retries up to _MAX_ATTEMPTS times with exponential backoff.
    Returns True on success, False after all attempts exhausted.
    """
    if is_permission_denied(service):
        logger.warning("Skipping restart for %s because a recent permission failure is cached", service)
        return False

    if attempt > _MAX_ATTEMPTS:
        logger.error("Service %s failed to restart after %d attempts", service, _MAX_ATTEMPTS)
        return False

    logger.info("Restarting %s (attempt %d/%d)", service, attempt, _MAX_ATTEMPTS)

    # Try Docker first (most common deployment), then systemctl
    if await _try_docker_restart(service):
        return True
    sys_success, perm_fail = await _try_systemctl_restart(service)
    if sys_success:
        return True
    if perm_fail:
        # Permission denied — log once and do not aggressively retry.
        logger.warning("Permission denied for systemctl restart of %s — aborting further attempts", service)
        return False

    logger.warning(
        "No restart mechanism available for %s (Docker/systemctl not found or failed) — attempt %d",
        service, attempt,
    )

    # Exponential backoff before next attempt
    backoff = _BACKOFF_BASE ** attempt
    logger.info("Waiting %ds before retry for %s", backoff, service)
    await asyncio.sleep(backoff)
    return await restart_service(service, attempt + 1)
