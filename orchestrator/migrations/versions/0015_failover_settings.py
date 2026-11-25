"""Persist failover settings.

Revision ID: 0015
Revises: 0014
"""
import sqlalchemy as sa
from alembic import op

revision = "0015_failover_settings"
down_revision = "0014_instance_awg_version"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "failover_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("down_seconds", sa.Float(), nullable=False),
        sa.Column("proposal_ttl_seconds", sa.Float(), nullable=False),
        sa.Column("cooldown_seconds", sa.Float(), nullable=False),
        sa.Column("eval_interval", sa.Float(), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_failover_settings_singleton"),
        sa.CheckConstraint("mode IN ('off','confirm','auto')", name="ck_failover_settings_mode"),
        sa.CheckConstraint("down_seconds BETWEEN 1 AND 86400", name="ck_failover_settings_down"),
        sa.CheckConstraint("proposal_ttl_seconds BETWEEN 1 AND 604800", name="ck_failover_settings_ttl"),
        sa.CheckConstraint("cooldown_seconds BETWEEN 0 AND 86400", name="ck_failover_settings_cooldown"),
        sa.CheckConstraint("eval_interval BETWEEN 1 AND 3600", name="ck_failover_settings_interval"),
    )


def downgrade():
    op.drop_table("failover_settings")
