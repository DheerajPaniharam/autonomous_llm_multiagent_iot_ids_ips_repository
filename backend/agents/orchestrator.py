"""
LLM Orchestrator — central coordinator that receives AttackEvents,
invokes local LLM for contextual analysis, resolves conflicts,
dispatches mitigation/healing commands, and manages incident lifecycle.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, NamedTuple

from backend.agents.queues import get_queues, safe_put
from backend.llm.langchain_setup import analyze_threat
from backend.llm.prompt_templates import THREAT_ANALYSIS_TEMPLATE
from backend.models.messages import (
    AttackEvent, FeatureVector, Incident, IncidentState,
    LogEntry, MitigationCommand, ThreatScore,
)

_COMPOSITE_THRESHOLD = 0.65
_SCORE_WINDOW_MS = 500  # ms to wait for second score before pass-through


class _PendingScores(NamedTuple):
    lightgbm: ThreatScore | None
    if_: ThreatScore | None
    fv: FeatureVector | None
    created_at: datetime
from backend.api.ws_manager import ws_manager
from backend.metrics import increment_events_processed
from backend.logs_module.db_logger import write_attack_event, write_incident
from backend.utils.helpers import derive_severity

logger = logging.getLogger(__name__)

# Shared state accessible by all agents
_shared_state: dict[str, Any] = {}


def rule_based_fallback(composite_score: float, event_id: str | None = None) -> MitigationCommand | None:
    """Deterministic fallback when LLM is unavailable (Req 18.3)."""
    if composite_score >= 0.9:
        return MitigationCommand(
            event_id=event_id,
            action="block_ip",
            target_ip="0.0.0.0",
            ttl_seconds=3600,
            priority=1,
        )
    elif composite_score >= 0.65:
        return MitigationCommand(
            event_id=event_id,
            action="rate_limit",
            target_ip="0.0.0.0",
            ttl_seconds=1800,
            priority=2,
        )
    return None


class AlertManager:
    """Aggregates and dispatches alerts (Req 15.1–15.7)."""

    def __init__(self) -> None:
        self._window: dict[str, list[datetime]] = defaultdict(list)
        self._window_minutes = 5
        self._threshold = 10

    async def emit_alert(self, event: AttackEvent) -> None:
        attack_type = event.attack_type or "unknown"
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=self._window_minutes)

        # Prune old entries
        self._window[attack_type] = [t for t in self._window[attack_type] if t > cutoff]
        self._window[attack_type].append(now)

        count = len(self._window[attack_type])
        if count > self._threshold:
            logger.warning(
                "AGGREGATED ALERT: %d %s events in %d min (score=%.2f)",
                count, attack_type, self._window_minutes, event.composite_score,
            )
        else:
            logger.warning(
                "ALERT: %s detected (score=%.2f, flow=%s)",
                attack_type, event.composite_score, event.flow_id,
            )
        # Broadcast alert to websocket clients
        try:
            payload = {
                "flow_id": event.flow_id,
                "attack_type": attack_type,
                "composite_score": event.composite_score,
                "severity": derive_severity(event.composite_score),
                "timestamp": event.timestamp.isoformat() if hasattr(event.timestamp, 'isoformat') else str(event.timestamp),
            }
            fv = getattr(event, "feature_vector", None)
            if fv is not None:
                payload.update({
                    "src_ip": getattr(fv, "src_ip", None),
                    "dst_ip": getattr(fv, "dst_ip", None),
                    "protocol": getattr(fv, "protocol", None),
                })
            await ws_manager.broadcast({"type": "alert", "payload": payload})
        except Exception:
            pass

    async def acknowledge(self, alert_id: str, user: str) -> None:
        logger.info("Alert %s acknowledged by %s", alert_id, user)


class LLMOrchestrator:
    """
    Central multi-agent coordinator.
    Receives AttackEvents, runs LLM analysis, dispatches commands.
    """

    def __init__(self, composite_threshold: float = _COMPOSITE_THRESHOLD) -> None:
        self._running = False
        self._task: asyncio.Task | None = None
        self._alert_manager = AlertManager()
        self._incidents: dict[str, Incident] = {}
        self._recent_events: list[AttackEvent] = []
        self._campaign_window: dict[str, list[AttackEvent]] = defaultdict(list)
        self._processed = 0
        self.composite_threshold = composite_threshold
        self._pending_events: dict[str, AttackEvent] = {}

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run())
        logger.info("LLMOrchestrator started")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        # Flush any remaining pending events immediately during stop:
        for flow_id, event in list(self._pending_events.items()):
            event.composite_score = max(event.lightgbm_score or 0.0, event.if_score or 0.0)
            await self.handle_attack_event(event)
        self._pending_events.clear()
        logger.info("LLMOrchestrator stopped — %d events processed", self._processed)

    def _coerce_event(self, item: Any) -> AttackEvent | None:
        """Normalize queued payloads from the merged pipeline into an AttackEvent."""
        if isinstance(item, AttackEvent):
            return item

        if isinstance(item, ThreatScore):
            fv = item.feature_vector or FeatureVector(
                flow_id=item.flow_id,
                timestamp=item.timestamp,
                src_ip="0.0.0.0",
                dst_ip="0.0.0.0",
                src_port=0,
                dst_port=0,
                protocol="TCP",
                packet_rate=0.0,
                byte_rate=0.0,
                flow_duration=0.0,
                tcp_flags="",
                connection_errors=0,
                port_entropy=0.0,
                is_known_iot_port=False,
            )
            return AttackEvent(
                flow_id=item.flow_id,
                feature_vector=fv,
                lightgbm_score=item.score if item.source == "lightgbm" else 0.0,
                if_score=item.score if item.source == "if" else 0.0,
                composite_score=item.score,
                attack_type=item.attack_type or "unknown",
                timestamp=item.timestamp,
            )

        if isinstance(item, tuple):
            if len(item) == 3:
                _, _, payload = item
            else:
                _, payload = item
            return self._coerce_event(payload)

        return None

    async def _run(self) -> None:
        queues = get_queues()
        while self._running:
            try:
                item = await asyncio.wait_for(
                    queues.orchestrator_queue.get(), timeout=1.0
                )
                event = self._coerce_event(item)
                if event is None:
                    queues.orchestrator_queue.task_done()
                    continue
                await self._enqueue_for_aggregation(event)
                queues.orchestrator_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("LLMOrchestrator error: %s", exc)

    async def _enqueue_for_aggregation(self, event: AttackEvent) -> None:
        flow_id = event.flow_id
        if not flow_id:
            await self.handle_attack_event(event)
            return

        if flow_id in self._pending_events:
            existing = self._pending_events[flow_id]
            # Merge scores
            lgbm = event.lightgbm_score if (event.lightgbm_score and event.lightgbm_score > 0.0) else existing.lightgbm_score
            if_sc = event.if_score if (event.if_score and event.if_score > 0.0) else existing.if_score
            fv = event.feature_vector or existing.feature_vector
            
            # Select attack_type: prefer specific over generic/unknown/zero_day_anomaly
            attack_type = event.attack_type
            if attack_type in ("unknown", "zero_day_anomaly") and existing.attack_type not in ("unknown", "zero_day_anomaly"):
                attack_type = existing.attack_type
            
            existing.lightgbm_score = lgbm
            existing.if_score = if_sc
            existing.attack_type = attack_type
            existing.feature_vector = fv
        else:
            self._pending_events[flow_id] = event
            asyncio.create_task(self._process_aggregated_event_after_delay(flow_id))

    async def _process_aggregated_event_after_delay(self, flow_id: str) -> None:
        await asyncio.sleep(_SCORE_WINDOW_MS / 1000.0)
        event = self._pending_events.pop(flow_id, None)
        if event:
            event.composite_score = max(event.lightgbm_score or 0.0, event.if_score or 0.0)
            await self.handle_attack_event(event)

    # ------------------------------------------------------------------
    # Core handler
    # ------------------------------------------------------------------

    async def handle_attack_event(self, event: AttackEvent) -> None:
        self._processed += 1
        self._recent_events.append(event)
        if len(self._recent_events) > 20:
            self._recent_events.pop(0)

        # Increment Prometheus counter (Requirement 13.1)
        increment_events_processed("orchestrator")
        increment_events_processed("LLMOrchestrator")

        # LLM analysis
        llm_result = await self._analyze_with_llm(event)

        # Persist attack event to database
        event_db_id = await self._persist_attack_event(event, llm_result)

        # Determine mitigation
        cmd = await self._build_mitigation_command(event, llm_result, event_db_id)
        if cmd:
            # Resolve conflicts before dispatching
            resolved = await self._resolve_conflicts([cmd])
            for c in resolved:
                await self._dispatch_mitigation(c)

        # Incident management for high-severity events
        if event.composite_score >= 0.65:
            await self._create_or_update_incident(event, llm_result, event_db_id)

        # Alert for high-severity events
        if event.composite_score >= 0.65:
            await self._alert_manager.emit_alert(event)

        # Campaign correlation
        await self._correlate_campaign(event)

        # Log
        await self._log_event(event, llm_result)

    # ------------------------------------------------------------------
    # LLM analysis
    # ------------------------------------------------------------------

    async def _analyze_with_llm(self, event: AttackEvent) -> dict | None:
        fv = event.feature_vector
        recent = [f"{e.attack_type}@{e.composite_score:.2f}" for e in self._recent_events[-5:]]
        prompt = THREAT_ANALYSIS_TEMPLATE.format(
            attack_type=event.attack_type,
            threat_score=event.composite_score,
            src_ip=fv.src_ip if fv else "unknown",
            dst_ip=fv.dst_ip if fv else "unknown",
            protocol=fv.protocol if fv else "unknown",
            flow_duration=fv.flow_duration if fv else 0.0,
            recent_events=", ".join(recent) or "none",
            baseline_deviation="unknown",
        )
        return await analyze_threat(prompt)

    # ------------------------------------------------------------------
    # Mitigation
    # ------------------------------------------------------------------

    async def _build_mitigation_command(
        self, event: AttackEvent, llm_result: dict | None, event_db_id: str | None = None
    ) -> MitigationCommand | None:
        fv = event.feature_vector
        target_ip = fv.src_ip if fv else "0.0.0.0"

        if llm_result:
            action = llm_result.get("action", "")
            if action == "monitor":
                return None
            if action in ("block_ip", "rate_limit", "isolate_device"):
                ttl = 3600 if event.composite_score >= 0.9 else 1800
                return MitigationCommand(
                    event_id=event_db_id,
                    action=action,
                    target_ip=target_ip,
                    ttl_seconds=ttl,
                    priority=1 if event.composite_score >= 0.9 else 2,
                )

        # Fallback to rule-based
        cmd = rule_based_fallback(event.composite_score, event_db_id)
        if cmd:
            cmd.target_ip = target_ip
        return cmd

    async def _resolve_conflicts(
        self, commands: list[MitigationCommand]
    ) -> list[MitigationCommand]:
        """Deduplicate commands for the same target IP, keeping highest priority."""
        seen: dict[str, MitigationCommand] = {}
        for cmd in commands:
            existing = seen.get(cmd.target_ip)
            if existing is None or cmd.priority < existing.priority:
                seen[cmd.target_ip] = cmd
        return list(seen.values())

    async def _dispatch_mitigation(self, cmd: MitigationCommand) -> None:
        await safe_put(get_queues().prevention_queue, cmd)

    # ------------------------------------------------------------------
    # DB persistence
    # ------------------------------------------------------------------

    async def _persist_attack_event(
        self, event: AttackEvent, llm_result: dict | None
    ) -> str | None:
        """Write AttackEvent to the attack_events table. Returns DB record ID."""
        try:
            llm_str = str(llm_result) if llm_result else None
            record_id = await write_attack_event(event, llm_str)
            return record_id
        except Exception as exc:
            logger.error("Failed to persist attack event: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Incident lifecycle
    # ------------------------------------------------------------------

    async def _create_or_update_incident(
        self, event: AttackEvent, llm_result: dict | None, event_db_id: str | None = None
    ) -> None:
        incident_id = str(uuid.uuid4())
        severity = "critical" if event.composite_score >= 0.9 else (
            "high" if event.composite_score >= 0.75 else "medium"
        )
        incident = Incident(
            id=incident_id,
            state=IncidentState.DETECTED,
            severity=severity,
            attack_type=event.attack_type,
            response_plan=[],
            detected_at=datetime.utcnow(),
        )
        self._incidents[incident_id] = incident

        # Persist incident to database
        try:
            await write_incident(incident, event_db_id)
            logger.info("Incident persisted: %s (%s)", incident_id, severity)
        except Exception as exc:
            logger.error("Failed to persist incident: %s", exc)

    # ------------------------------------------------------------------
    # Campaign correlation
    # ------------------------------------------------------------------

    async def _correlate_campaign(self, event: AttackEvent) -> None:
        key = event.attack_type
        window = self._campaign_window[key]
        cutoff = datetime.utcnow() - timedelta(seconds=5)
        window[:] = [e for e in window if e.timestamp > cutoff]
        window.append(event)
        if len(window) >= 3:
            logger.warning(
                "Campaign detected: %d %s events in 5s", len(window), key
            )

    # ------------------------------------------------------------------
    # Shared state broadcast
    # ------------------------------------------------------------------

    async def broadcast_state_change(self, key: str, value: Any) -> None:
        _shared_state[key] = value
        logger.debug("Shared state updated: %s=%s", key, value)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    async def _log_event(self, event: AttackEvent, llm_result: dict | None) -> None:
        entry = LogEntry(
            level="warning" if event.composite_score >= 0.65 else "info",
            source_agent="orchestrator",
            event_type="attack_event_processed",
            payload={
                "flow_id": event.flow_id,
                "attack_type": event.attack_type,
                "composite_score": event.composite_score,
                "llm_analysis": str(llm_result) if llm_result else None,
            },
            timestamp=datetime.utcnow(),
        )
        await safe_put(get_queues().logging_queue, entry)
