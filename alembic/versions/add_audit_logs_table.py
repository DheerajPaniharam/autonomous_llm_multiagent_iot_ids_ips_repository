"""Add audit_logs table for tracking user actions

Revision ID: add_audit_logs_001
Revises: ebcc1f7445f7
Create Date: 2026-08-07 00:00:00.000000

Adds audit_logs table to track user actions like:
  - acknowledge_incident
  - isolate_device
  - release_device
  - update_config
  - etc.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision: str = "add_audit_logs_001"
down_revision: Union[str, Sequence[str], None] = "ebcc1f7445f7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # audit_logs
    # ------------------------------------------------------------------
    op.create_table(
        "audit_logs",
        sa.Column("id",            sa.String(36),  primary_key=True),
        sa.Column("username",      sa.String(64),  nullable=False),
        sa.Column("action",        sa.String(64),  nullable=False),
        sa.Column("resource_type", sa.String(32)),
        sa.Column("resource_id",   sa.String(128)),
        sa.Column("details",       sa.JSON),
        sa.Column("status",        sa.String(16),  server_default="success"),
        sa.Column("ip_address",    sa.String(45)),
        sa.Column("user_agent",    sa.String(256)),
        sa.Column("timestamp",     sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_audit_timestamp",  "audit_logs", ["timestamp"])
    op.create_index("idx_audit_username",   "audit_logs", ["username"])
    op.create_index("idx_audit_action",     "audit_logs", ["action"])
    op.create_index("idx_audit_resource",   "audit_logs", ["resource_type", "resource_id"])


def downgrade() -> None:
    op.drop_table("audit_logs")
