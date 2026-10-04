"""initial_schema

Revision ID: ebcc1f7445f7
Revises:
Create Date: 2026-05-23 00:00:00.000000

Creates all tables for the IoT IDS/IPS system:
  incidents, attack_events, mitigation_actions, healing_actions,
  risk_score_log, iot_devices, users, auth_log,
  model_versions, signature_updates, system_logs, threat_intel_entries
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "ebcc1f7445f7"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # incidents  (referenced by attack_events and healing_actions)
    # ------------------------------------------------------------------
    op.create_table(
        "incidents",
        sa.Column("id",           sa.String(36),  primary_key=True),
        sa.Column("state",        sa.String(16),  nullable=False),
        sa.Column("severity",     sa.String(8),   nullable=False),
        sa.Column("attack_type",  sa.String(64)),
        sa.Column("response_plan", sa.JSON),
        sa.Column("detected_at",  sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at",  sa.DateTime(timezone=True)),
        sa.Column("created_at",   sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # attack_events
    # ------------------------------------------------------------------
    op.create_table(
        "attack_events",
        sa.Column("id",              sa.String(36),  primary_key=True),
        sa.Column("flow_id",         sa.String(64),  nullable=False),
        sa.Column("timestamp",       sa.DateTime(timezone=True), nullable=False),
        sa.Column("src_ip",          sa.String(45),  nullable=False),
        sa.Column("dst_ip",          sa.String(45),  nullable=False),
        sa.Column("src_port",        sa.Integer),
        sa.Column("dst_port",        sa.Integer),
        sa.Column("protocol",        sa.String(16)),
        sa.Column("attack_type",     sa.String(64)),
        sa.Column("supervised_score",        sa.Float),
        sa.Column("if_score",        sa.Float),
        sa.Column("composite_score", sa.Float,       nullable=False),
        sa.Column("llm_analysis",    sa.Text),
        sa.Column("incident_id",     sa.String(36),  sa.ForeignKey("incidents.id")),
        sa.Column("created_at",      sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_events_timestamp",  "attack_events", ["timestamp"])
    op.create_index("idx_events_src_ip",     "attack_events", ["src_ip"])
    op.create_index("idx_events_composite",  "attack_events", ["composite_score"])

    # ------------------------------------------------------------------
    # mitigation_actions
    # ------------------------------------------------------------------
    op.create_table(
        "mitigation_actions",
        sa.Column("id",          sa.String(36),  primary_key=True),
        sa.Column("event_id",    sa.String(36),  sa.ForeignKey("attack_events.id")),
        sa.Column("action_type", sa.String(32),  nullable=False),
        sa.Column("target_ip",   sa.String(45),  nullable=False),
        sa.Column("rule_id",     sa.String(128)),
        sa.Column("status",      sa.String(16),  nullable=False),
        sa.Column("ttl_seconds", sa.Integer),
        sa.Column("applied_at",  sa.DateTime(timezone=True)),
        sa.Column("expires_at",  sa.DateTime(timezone=True)),
        sa.Column("created_at",  sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_mitigations_status", "mitigation_actions", ["status", "expires_at"])

    # ------------------------------------------------------------------
    # healing_actions
    # ------------------------------------------------------------------
    op.create_table(
        "healing_actions",
        sa.Column("id",          sa.String(36),  primary_key=True),
        sa.Column("incident_id", sa.String(36),  sa.ForeignKey("incidents.id")),
        sa.Column("action_type", sa.String(32),  nullable=False),
        sa.Column("target",      sa.String(128)),
        sa.Column("attempt",     sa.Integer,     default=1),
        sa.Column("status",      sa.String(16),  nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at",  sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # risk_score_log
    # ------------------------------------------------------------------
    op.create_table(
        "risk_score_log",
        sa.Column("id",              sa.String(36), primary_key=True),
        sa.Column("flow_id",         sa.String(64), nullable=False),
        sa.Column("supervised_score",        sa.Float),
        sa.Column("if_score",        sa.Float),
        sa.Column("composite_score", sa.Float,      nullable=False),
        sa.Column("forwarded",       sa.Boolean,    nullable=False),
        sa.Column("scored_at",       sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # iot_devices
    # ------------------------------------------------------------------
    op.create_table(
        "iot_devices",
        sa.Column("device_id",            sa.String(64),  primary_key=True),
        sa.Column("ip_address",           sa.String(45),  nullable=False),
        sa.Column("mac_address",          sa.String(17)),
        sa.Column("device_type",          sa.String(16),  nullable=False, server_default="unknown"),
        sa.Column("protocols",            sa.JSON),
        sa.Column("first_seen",           sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen",            sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_isolated",          sa.Boolean,     default=False),
        sa.Column("baseline_packet_rate", sa.Float,       default=0.0),
        sa.Column("baseline_byte_rate",   sa.Float,       default=0.0),
    )
    op.create_index("idx_devices_ip", "iot_devices", ["ip_address"])

    # ------------------------------------------------------------------
    # users
    # ------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id",            sa.String(36),  primary_key=True),
        sa.Column("username",      sa.String(64),  nullable=False, unique=True),
        sa.Column("password_hash", sa.String(128), nullable=False),
        sa.Column("role",          sa.String(16),  nullable=False),
        sa.Column("created_at",    sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # auth_log
    # ------------------------------------------------------------------
    op.create_table(
        "auth_log",
        sa.Column("id",         sa.String(36), primary_key=True),
        sa.Column("username",   sa.String(64)),
        sa.Column("action",     sa.String(32)),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("timestamp",  sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # model_versions
    # ------------------------------------------------------------------
    op.create_table(
        "model_versions",
        sa.Column("id",          sa.String(36),  primary_key=True),
        sa.Column("model_type",  sa.String(8),   nullable=False),
        sa.Column("version_id",  sa.String(64),  nullable=False),
        sa.Column("file_path",   sa.String(256), nullable=False),
        sa.Column("accuracy",    sa.Float),
        sa.Column("precision",   sa.Float),
        sa.Column("recall",      sa.Float),
        sa.Column("f1_score",    sa.Float),
        sa.Column("roc_auc",     sa.Float),
        sa.Column("is_active",   sa.Boolean,     default=False),
        sa.Column("approved_by", sa.String(64)),
        sa.Column("created_at",  sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # signature_updates
    # ------------------------------------------------------------------
    op.create_table(
        "signature_updates",
        sa.Column("id",         sa.String(36),  primary_key=True),
        sa.Column("source_url", sa.String(256)),
        sa.Column("checksum",   sa.String(64)),
        sa.Column("rule_count", sa.Integer),
        sa.Column("status",     sa.String(16)),
        sa.Column("applied_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # system_logs
    # ------------------------------------------------------------------
    op.create_table(
        "system_logs",
        sa.Column("id",           sa.String(36), primary_key=True),
        sa.Column("level",        sa.String(16), nullable=False),
        sa.Column("source_agent", sa.String(64), nullable=False),
        sa.Column("event_type",   sa.String(64), nullable=False),
        sa.Column("payload",      sa.JSON),
        sa.Column("timestamp",    sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at",   sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_logs_timestamp",    "system_logs", ["timestamp"])
    op.create_index("idx_logs_source_agent", "system_logs", ["source_agent"])
    op.create_index("idx_logs_level",        "system_logs", ["level"])

    # ------------------------------------------------------------------
    # threat_intel_entries
    # ------------------------------------------------------------------
    op.create_table(
        "threat_intel_entries",
        sa.Column("id",          sa.String(36),  primary_key=True),
        sa.Column("entry_type",  sa.String(16),  nullable=False),
        sa.Column("value",       sa.String(256), nullable=False),
        sa.Column("source",      sa.String(128)),
        sa.Column("confidence",  sa.Float,       default=1.0),
        sa.Column("imported_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at",  sa.DateTime(timezone=True)),
    )
    op.create_index("idx_intel_value", "threat_intel_entries", ["value"])


def downgrade() -> None:
    op.drop_table("threat_intel_entries")
    op.drop_table("system_logs")
    op.drop_table("signature_updates")
    op.drop_table("model_versions")
    op.drop_table("auth_log")
    op.drop_table("users")
    op.drop_table("iot_devices")
    op.drop_table("risk_score_log")
    op.drop_table("healing_actions")
    op.drop_table("mitigation_actions")
    op.drop_table("attack_events")
    op.drop_table("incidents")
