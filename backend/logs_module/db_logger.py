"""
Database logger — writes structured LogEntry records to PostgreSQL.
Also persists AttackEvent and Incident records to their respective tables.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from backend.database.connection import session_context
from backend.database.models import (
    AttackEventModel,
    IncidentModel,
    MitigationActionModel,
    SystemLogModel,
)
from backend.models.messages import AttackEvent, Incident, LogEntry, MitigationCommand

logger = logging.getLogger(__name__)


async def write_log_entry(entry: LogEntry) -> None:
    """Persist a LogEntry to the system_logs table."""
    try:
        async with session_context() as session:
            record = SystemLogModel(
                level=entry.level,
                source_agent=entry.source_agent,
                event_type=entry.event_type,
                payload=entry.payload,
                timestamp=entry.timestamp,
            )
            session.add(record)
            # commit is handled by the get_session context manager
    except Exception as exc:
        logger.error("DB log write failed: %s", exc)
        raise


async def write_attack_event(event: AttackEvent, llm_analysis: str | None = None) -> str:
    """Persist an AttackEvent to attack_events table. Returns record ID."""
    try:
        async with session_context() as session:
            fv = event.feature_vector
            record = AttackEventModel(
                flow_id=event.flow_id,
                timestamp=event.timestamp,
                src_ip=fv.src_ip if fv else "0.0.0.0",
                dst_ip=fv.dst_ip if fv else "0.0.0.0",
                src_port=fv.src_port if fv else None,
                dst_port=fv.dst_port if fv else None,
                protocol=fv.protocol if fv else None,
                attack_type=event.attack_type,
                lightgbm_score=event.lightgbm_score,
                if_score=event.if_score,
                composite_score=event.composite_score,
                llm_analysis=llm_analysis,
            )
            session.add(record)
            await session.flush()
            return str(record.id)
    except Exception as exc:
        logger.error("Attack event write failed: %s", exc)
        raise


async def write_incident(incident: Incident, event_db_id: str | None = None) -> str:
    """Persist an Incident to the incidents table. Returns record ID."""
    try:
        async with session_context() as session:
            record = IncidentModel(
                id=incident.id,
                state=incident.state.value if hasattr(incident.state, "value") else str(incident.state),
                severity=incident.severity,
                attack_type=incident.attack_type,
                response_plan={"event_id": event_db_id} if event_db_id else {},
                detected_at=incident.detected_at,
                resolved_at=incident.resolved_at,
            )
            session.add(record)
            await session.flush()

            # Back-link the attack event to this incident if we have its DB id
            if event_db_id:
                from sqlalchemy import update
                await session.execute(
                    update(AttackEventModel)
                    .where(AttackEventModel.id == event_db_id)
                    .values(incident_id=incident.id)
                )

            return str(record.id)
    except Exception as exc:
        logger.error("Incident write failed: %s", exc)
        raise


async def write_mitigation_action(command: MitigationCommand, rule_id: str) -> str:
    """Persist a successfully executed firewall mitigation."""
    try:
        now = datetime.now(timezone.utc)
        expires_at = None
        if command.ttl_seconds > 0:
            expires_at = now.replace(microsecond=0)
            from datetime import timedelta
            expires_at += timedelta(seconds=command.ttl_seconds)

        async with session_context() as session:
            record = MitigationActionModel(
                event_id=command.event_id,
                action_type=command.action,
                target_ip=command.target_ip,
                rule_id=rule_id,
                status="applied",
                ttl_seconds=command.ttl_seconds or None,
                applied_at=now,
                expires_at=expires_at,
            )
            session.add(record)
            await session.flush()
            return str(record.id)
    except Exception as exc:
        logger.error("Mitigation action write failed: %s", exc)
        raise
