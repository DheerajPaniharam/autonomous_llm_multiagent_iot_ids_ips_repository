"""
Response Agent — merges mitigation and healing.
Consumes MitigationCommands from prevention_queue and HealingCommands from healing_queue.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from backend.agents.queues import get_queues, safe_put
from backend.firewall import nftables_manager
from backend.healing.service_restart import is_permission_denied, restart_service
from backend.healing.session_cleanup import clear_stale_rules
from backend.healing.system_monitor import check_all_services
from backend.models.messages import HealingCommand, LogEntry, MitigationCommand
from backend.metrics import increment_mitigations, increment_events_processed

logger = logging.getLogger(__name__)

_STATE_FILE = Path("state/active_rules.json")
_EXPIRY_INTERVAL = 60  # seconds between expiry sweeps
_RESOURCE_THRESHOLD = 0.90  # 90% CPU or memory


def _ttl_for_score(composite_score: float) -> int:
    if composite_score >= 0.9:
        return 86400
    elif composite_score >= 0.75:
        return 3600
    return 1800


class ResponseAgent:
    """
    Handles both prevention and healing workflows.
    """

    def __init__(self, whitelist: list[str] | None = None) -> None:
        self._whitelist: set[str] = set(whitelist or [])
        self._running = False
        self._task: asyncio.Task | None = None
        self._prevention_task: asyncio.Task | None = None
        self._healing_task: asyncio.Task | None = None
        self._expiry_task: asyncio.Task | None = None
        self._healed = 0
        self._applied = 0
        self._service_states: dict[str, dict[str, float | bool]] = {}
        self._alert_cooldown_until: dict[str, float] = {}

    async def start(self) -> None:
        self._running = True
        await self._restore_state()
        self._prevention_task = asyncio.create_task(self._run_prevention())
        self._healing_task = asyncio.create_task(self._run_healing())
        self._expiry_task = asyncio.create_task(self._expiry_loop())
        self._task = asyncio.create_task(self._monitor_tasks())
        logger.info("ResponseAgent started (whitelist=%d IPs)", len(self._whitelist))

    async def stop(self) -> None:
        self._running = False
        for task in (self._prevention_task, self._healing_task, self._expiry_task, self._task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        await self._save_state()
        logger.info("ResponseAgent stopped — %d rules applied, %d healing actions", self._applied, self._healed)

    async def _monitor_tasks(self) -> None:
        tasks = [t for t in (self._prevention_task, self._healing_task, self._expiry_task) if t is not None]
        if tasks:
            try:
                await asyncio.gather(*tasks)
            except asyncio.CancelledError:
                pass

    async def _run_prevention(self) -> None:
        queues = get_queues()
        while self._running:
            try:
                cmd: MitigationCommand = await asyncio.wait_for(
                    queues.prevention_queue.get(), timeout=1.0
                )
                await self._execute_mitigation(cmd)
                queues.prevention_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("ResponseAgent prevention error: %s", exc)

    async def _run_healing(self) -> None:
        queues = get_queues()
        while self._running:
            try:
                cmd: HealingCommand = await asyncio.wait_for(
                    queues.healing_queue.get(), timeout=1.0
                )
                await self.handle_healing_command(cmd)
                queues.healing_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("ResponseAgent healing error: %s", exc)

    async def _execute_mitigation(self, cmd: MitigationCommand) -> str:
        if self.is_whitelisted(cmd.target_ip):
            logger.info("Skipping %s for whitelisted IP %s", cmd.action, cmd.target_ip)
            return "whitelisted"

        if cmd.action == "block_ip":
            rule_id = await self.block_ip(cmd.target_ip, cmd.ttl_seconds)
            increment_mitigations("block_ip")
            await self._set_device_isolated_status(cmd.target_ip, True)
        elif cmd.action == "rate_limit":
            rule_id = await self.rate_limit(cmd.target_ip, ttl_seconds=cmd.ttl_seconds or 1800)
            increment_mitigations("rate_limit")
        elif cmd.action == "isolate_device":
            rule_id = await self.isolate_device(cmd.target_ip, cmd.ttl_seconds)
            increment_mitigations("isolate_device")
        else:
            logger.warning("Unknown mitigation action: %s", cmd.action)
            return "unknown_action"

        await self._log_action(cmd, rule_id)
        await self._persist_mitigation(cmd, rule_id)
        self._applied += 1
        increment_events_processed("ResponseAgent")
        return rule_id

    async def handle_healing_command(self, cmd: HealingCommand) -> bool:
        logger.info("Healing command: %s → %s", cmd.action, cmd.target)
        success = False

        if cmd.action == "restart_service":
            success = await self._restart_service(cmd.target)
        elif cmd.action == "clear_rules":
            await clear_stale_rules()
            success = True
        elif cmd.action == "optimize_resources":
            await self._optimize_resources()
            success = True
        elif cmd.action == "restore_connectivity":
            success = await self._restart_service(cmd.target)

        if success:
            self._healed += 1
            increment_events_processed("ResponseAgent")
            verified = await self._verify_recovery(cmd.target)
            if not verified:
                await self._alert(f"Recovery verification failed for {cmd.target}")
        return success

    async def _expiry_loop(self) -> None:
        while self._running:
            await asyncio.sleep(_EXPIRY_INTERVAL)
            removed = await self.clear_expired_rules()
            if removed:
                logger.info("Expired %d firewall rules", removed)

    async def clear_expired_rules(self) -> int:
        loop = asyncio.get_event_loop()
        now = datetime.utcnow()
        expired_rules = [
            r for r in nftables_manager.list_rules()
            if r.expires_at and r.expires_at <= now
        ]

        if not expired_rules:
            return 0

        removed_count = 0
        for r in expired_rules:
            success = await loop.run_in_executor(None, nftables_manager.remove_rule, r.rule_id)
            if success:
                removed_count += 1
                if r.action == "drop":
                    await self._set_device_isolated_status(r.ip, False)

        return removed_count

    async def block_ip(self, ip: str, ttl_seconds: int) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, nftables_manager.add_block_rule, ip, ttl_seconds
        )

    async def rate_limit(
        self, ip: str, pps_limit: int = 100, ttl_seconds: int = 1800
    ) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, nftables_manager.add_rate_limit_rule, ip, pps_limit, ttl_seconds
        )

    async def isolate_device(self, ip: str, ttl_seconds: int) -> str:
        loop = asyncio.get_event_loop()
        rule_id = await loop.run_in_executor(
            None, nftables_manager.add_block_rule, ip, ttl_seconds
        )
        await self._set_device_isolated_status(ip, True)
        return rule_id

    async def clear_stale_rules(self) -> int:
        return await clear_stale_rules()

    async def _set_device_isolated_status(self, ip: str, is_isolated: bool) -> None:
        from backend.database.connection import session_context
        from backend.database.models import IoTDeviceModel
        from sqlalchemy import update
        from datetime import datetime as _dt

        try:
            async with session_context() as session:
                stmt = (
                    update(IoTDeviceModel)
                    .where(IoTDeviceModel.ip_address == ip)
                    .values(is_isolated=is_isolated, last_seen=_dt.utcnow())
                )
                await session.execute(stmt)
                logger.info("Updated device isolation status for %s to %s", ip, is_isolated)
        except Exception as exc:
            logger.error(
                "Failed to update database isolation status for IP %s to %s: %s",
                ip,
                is_isolated,
                exc,
            )

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self._whitelist

    def add_to_whitelist(self, ip: str) -> None:
        self._whitelist.add(ip)

    def set_whitelist(self, ips: list[str]) -> None:
        self._whitelist = set(ips)
        logger.info("ResponseAgent whitelist updated with %d IPs", len(ips))

    async def _restart_service(self, service: str, attempt: int = 1) -> bool:
        if not self._should_attempt_restart(service):
            return False
        success = await restart_service(service, attempt)
        if not success:
            if is_permission_denied(service):
                self._service_states[service] = {"permission_denied": True, "cooldown_until": time.monotonic() + 300}
                return False
            self._mark_cooldown(service, 2 ** min(attempt, 3))
            await self._alert(f"Service {service} failed to restart after {attempt} attempts")
        return success

    def _should_attempt_restart(self, service: str) -> bool:
        state = self._service_states.get(service, {})
        cooldown_until = float(state.get("cooldown_until", 0.0))
        return time.monotonic() >= cooldown_until

    def _mark_cooldown(self, service: str, seconds: float) -> None:
        self._service_states[service] = {"permission_denied": False, "cooldown_until": time.monotonic() + seconds}

    async def _verify_recovery(self, service: str) -> bool:
        for _ in range(6):
            await asyncio.sleep(10)
            health = await check_all_services()
            if health.get(service, True):
                return True
        return False

    async def _optimize_resources(self) -> None:
        await clear_stale_rules()
        logger.info("Resource optimisation applied")

    async def _alert(self, message: str) -> None:
        now = time.monotonic()
        if self._alert_cooldown_until.get(message, 0.0) > now:
            return
        self._alert_cooldown_until[message] = now + 300
        entry = LogEntry(
            level="critical",
            source_agent="response_agent",
            event_type="healing_failed",
            payload={"message": message},
            timestamp=datetime.utcnow(),
        )
        await safe_put(get_queues().logging_queue, entry)
        logger.critical("ResponseAgent alert: %s", message)

    async def _log_action(self, cmd: MitigationCommand, rule_id: str) -> None:
        entry = LogEntry(
            level="info",
            source_agent="response_agent",
            event_type="mitigation_executed",
            payload={"action": cmd.action, "target_ip": cmd.target_ip, "rule_id": rule_id},
            timestamp=datetime.utcnow(),
        )
        await safe_put(get_queues().logging_queue, entry)

    async def _persist_mitigation(self, cmd: MitigationCommand, rule_id: str) -> None:
        try:
            from backend.logs_module.db_logger import write_mitigation_action
            await write_mitigation_action(cmd, rule_id)
        except Exception as exc:
            logger.error("Failed to persist mitigation action: %s", exc)

    async def _save_state(self) -> None:
        try:
            _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            rules = [
                {"rule_id": r.rule_id, "ip": r.ip, "action": r.action,
                 "expires_at": r.expires_at.isoformat() if r.expires_at else None}
                for r in nftables_manager.list_rules()
            ]
            _STATE_FILE.write_text(json.dumps(rules, indent=2))
            logger.info("Saved %d active rules to %s", len(rules), _STATE_FILE)
        except Exception as exc:
            logger.error("Failed to save response agent state: %s", exc)

    async def _restore_state(self) -> None:
        if not _STATE_FILE.exists():
            return
        try:
            data = json.loads(_STATE_FILE.read_text())
            for rule in data:
                if rule.get("action") == "block_ip" and rule.get("ip"):
                    expires_at_str = rule.get("expires_at")
                    if expires_at_str:
                        try:
                            expires_at = datetime.fromisoformat(expires_at_str)
                            remaining_ttl = int((expires_at - datetime.utcnow()).total_seconds())
                        except Exception:
                            remaining_ttl = 3600  # Fallback to 1 hour if parsing fails
                    else:
                        remaining_ttl = 3600  # Fallback to 1 hour
                    
                    if remaining_ttl > 0:
                        await self.block_ip(rule["ip"], remaining_ttl)
                        logger.info("Restored firewall block rule for %s with %ds remaining TTL", rule["ip"], remaining_ttl)
                    else:
                        logger.info("Skipping restore of expired block rule for %s", rule["ip"])
        except Exception as exc:
            logger.error("Failed to restore response agent state: %s", exc)
