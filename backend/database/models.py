"""
SQLAlchemy ORM models for all PostgreSQL tables.
Covers: attack_events, mitigation_actions, healing_actions, incidents,
        risk_score_log, iot_devices, users, auth_log,
        model_versions, signature_updates, threat_intel_entries.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Index, Integer,
    String, Text, ForeignKey, JSON, func,
)
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Incidents (referenced by attack_events and healing_actions)
# ---------------------------------------------------------------------------

class IncidentModel(Base):
    __tablename__ = "incidents"

    id          = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    state       = Column(String(16), nullable=False)   # detected/analyzing/mitigating/resolved/closed
    severity    = Column(String(8),  nullable=False)   # low/medium/high/critical
    attack_type = Column(String(64))
    response_plan = Column(JSON)
    detected_at = Column(DateTime(timezone=True), nullable=False)
    resolved_at = Column(DateTime(timezone=True))
    created_at  = Column(DateTime(timezone=True), server_default=func.now())

    attack_events   = relationship("AttackEventModel",  back_populates="incident")
    healing_actions = relationship("HealingActionModel", back_populates="incident")


# ---------------------------------------------------------------------------
# Attack Events
# ---------------------------------------------------------------------------

class AttackEventModel(Base):
    __tablename__ = "attack_events"

    id              = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    flow_id         = Column(String(64), nullable=False)
    timestamp       = Column(DateTime(timezone=True), nullable=False)
    src_ip          = Column(INET, nullable=False)
    dst_ip          = Column(INET, nullable=False)
    src_port        = Column(Integer)
    dst_port        = Column(Integer)
    protocol        = Column(String(16))
    attack_type       = Column(String(64))
    lightgbm_score    = Column(Float)
    if_score          = Column(Float)
    composite_score   = Column(Float, nullable=False)
    llm_analysis    = Column(Text)
    incident_id     = Column(UUID(as_uuid=False), ForeignKey("incidents.id"))
    created_at      = Column(DateTime(timezone=True), server_default=func.now())

    incident            = relationship("IncidentModel", back_populates="attack_events")
    mitigation_actions  = relationship("MitigationActionModel", back_populates="event")

    __table_args__ = (
        Index("idx_events_timestamp",  "timestamp"),
        Index("idx_events_src_ip",     "src_ip"),
        Index("idx_events_composite",  "composite_score"),
    )


# ---------------------------------------------------------------------------
# Mitigation Actions
# ---------------------------------------------------------------------------

class MitigationActionModel(Base):
    __tablename__ = "mitigation_actions"

    id          = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    event_id    = Column(UUID(as_uuid=False), ForeignKey("attack_events.id"))
    action_type = Column(String(32), nullable=False)  # block_ip/rate_limit/isolate_device
    target_ip   = Column(INET, nullable=False)
    rule_id     = Column(String(128))
    status      = Column(String(16), nullable=False)  # pending/applied/expired/failed
    ttl_seconds = Column(Integer)
    applied_at  = Column(DateTime(timezone=True))
    expires_at  = Column(DateTime(timezone=True))
    created_at  = Column(DateTime(timezone=True), server_default=func.now())

    event = relationship("AttackEventModel", back_populates="mitigation_actions")

    __table_args__ = (
        Index("idx_mitigations_status", "status", "expires_at"),
    )


# ---------------------------------------------------------------------------
# Healing Actions
# ---------------------------------------------------------------------------

class HealingActionModel(Base):
    __tablename__ = "healing_actions"

    id          = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    incident_id = Column(UUID(as_uuid=False), ForeignKey("incidents.id"))
    action_type = Column(String(32), nullable=False)
    target      = Column(String(128))
    attempt     = Column(Integer, default=1)
    status      = Column(String(16), nullable=False)  # pending/success/failed
    executed_at = Column(DateTime(timezone=True))
    created_at  = Column(DateTime(timezone=True), server_default=func.now())

    incident = relationship("IncidentModel", back_populates="healing_actions")


# ---------------------------------------------------------------------------
# Risk Score Log
# ---------------------------------------------------------------------------

class RiskScoreLogModel(Base):
    __tablename__ = "risk_score_log"

    id                = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    flow_id           = Column(String(64), nullable=False)
    lightgbm_score    = Column(Float)
    if_score          = Column(Float)
    composite_score   = Column(Float, nullable=False)
    forwarded       = Column(Boolean, nullable=False)
    scored_at       = Column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# IoT Devices
# ---------------------------------------------------------------------------

class IoTDeviceModel(Base):
    __tablename__ = "iot_devices"

    device_id            = Column(String(64), primary_key=True)
    ip_address           = Column(INET, nullable=False)
    mac_address          = Column(String(17))
    device_type          = Column(String(16), nullable=False, default="unknown")
    protocols            = Column(JSON)
    first_seen           = Column(DateTime(timezone=True), nullable=False)
    last_seen            = Column(DateTime(timezone=True), nullable=False)
    is_isolated          = Column(Boolean, default=False)
    baseline_packet_rate = Column(Float, default=0.0)
    baseline_byte_rate   = Column(Float, default=0.0)

    __table_args__ = (
        Index("idx_devices_ip", "ip_address"),
    )


# ---------------------------------------------------------------------------
# Users & Auth Log
# ---------------------------------------------------------------------------

class UserModel(Base):
    __tablename__ = "users"

    id            = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    username      = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    role          = Column(String(16), nullable=False)  # admin/analyst/viewer
    created_at    = Column(DateTime(timezone=True), server_default=func.now())


class AuthLogModel(Base):
    __tablename__ = "auth_log"

    id         = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    username   = Column(String(64))
    action     = Column(String(32))   # login_success/login_failure/logout
    ip_address = Column(INET)
    timestamp  = Column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# Audit Log (user actions)
# ---------------------------------------------------------------------------

class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id           = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    username     = Column(String(64), nullable=False)
    action       = Column(String(64), nullable=False)  # acknowledge_incident, isolate_device, release_device, update_config, etc.
    resource_type = Column(String(32))  # incident, device, config, etc.
    resource_id  = Column(String(128))  # ID of the resource being acted upon
    details      = Column(JSON)  # Additional context about the action
    status       = Column(String(16), default="success")  # success/failure
    ip_address   = Column(INET)
    user_agent   = Column(String(256))
    timestamp    = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_username", "username"),
        Index("idx_audit_action", "action"),
        Index("idx_audit_resource", "resource_type", "resource_id"),
    )


# ---------------------------------------------------------------------------
# Model Versions
# ---------------------------------------------------------------------------

class ModelVersionModel(Base):
    __tablename__ = "model_versions"

    id          = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    model_type  = Column(String(8),   nullable=False)   # lightgbm / if
    version_id  = Column(String(64),  nullable=False)
    file_path   = Column(String(256), nullable=False)
    accuracy    = Column(Float)
    precision   = Column(Float)
    recall      = Column(Float)
    f1_score    = Column(Float)
    roc_auc     = Column(Float)
    is_active   = Column(Boolean, default=False)
    approved_by = Column(String(64))
    created_at  = Column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# Signature Updates
# ---------------------------------------------------------------------------

class SignatureUpdateModel(Base):
    __tablename__ = "signature_updates"

    id         = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    source_url = Column(String(256))
    checksum   = Column(String(64))
    rule_count = Column(Integer)
    status     = Column(String(16))   # applied/failed/rolled_back
    applied_at = Column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# System Log
# ---------------------------------------------------------------------------

class SystemLogModel(Base):
    __tablename__ = "system_logs"

    id           = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    level        = Column(String(16), nullable=False)   # info/warning/error/critical
    source_agent = Column(String(64), nullable=False)
    event_type   = Column(String(64), nullable=False)
    payload      = Column(JSON)
    timestamp    = Column(DateTime(timezone=True), nullable=False)
    created_at   = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("idx_logs_timestamp",    "timestamp"),
        Index("idx_logs_source_agent", "source_agent"),
        Index("idx_logs_level",        "level"),
    )


# ---------------------------------------------------------------------------
# Threat Intelligence Entries
# ---------------------------------------------------------------------------

class ThreatIntelEntryModel(Base):
    __tablename__ = "threat_intel_entries"

    id          = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    entry_type  = Column(String(16), nullable=False)   # ip / domain
    value       = Column(String(256), nullable=False)
    source      = Column(String(128))
    confidence  = Column(Float, default=1.0)
    imported_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at  = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("idx_intel_value", "value"),
    )
