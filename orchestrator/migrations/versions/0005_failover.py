"""Persist failover proposals."""

import sqlalchemy as sa
from alembic import op

revision = "0005_failover"
down_revision = "0004_alerts"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "failover_proposals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("instance_id", sa.Integer(), sa.ForeignKey("instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("hop_id", sa.Integer(), sa.ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("from_node_id", sa.Integer(), sa.ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("to_node_id", sa.Integer(), sa.ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("mode_at_creation", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("decided_by", sa.String()),
        sa.Column("error", sa.Text()),
    )


def downgrade():
    op.drop_table("failover_proposals")
