"""Add synthetic probe clients."""

import sqlalchemy as sa
from alembic import op

revision = "0003_probes"
down_revision = "0002_hops"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "probes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hop_id", sa.Integer(), sa.ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("instance_id", sa.Integer(), sa.ForeignKey("instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("runner_node_id", sa.Integer(), sa.ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("peer_id", sa.Integer(), sa.ForeignKey("peers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("hop_id", "instance_id"),
    )


def downgrade():
    op.drop_table("probes")
