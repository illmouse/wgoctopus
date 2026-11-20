"""Add hop nodes and links."""

import sqlalchemy as sa
from alembic import op

revision = "0002_hops"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("nodes") as batch:
        batch.add_column(sa.Column("kind", sa.String(), nullable=False, server_default="awg"))
        batch.add_column(sa.Column("wan_interface", sa.String(15)))
        batch.add_column(sa.Column("hop_ip", sa.String()))
        batch.add_column(sa.Column("backend_ip", sa.String()))
    op.create_table(
        "hop_links",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hop_id", sa.Integer(), sa.ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("instance_id", sa.Integer(), sa.ForeignKey("instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("hop_id", "instance_id"),
    )


def downgrade():
    op.drop_table("hop_links")
    with op.batch_alter_table("nodes") as batch:
        batch.drop_column("backend_ip")
        batch.drop_column("hop_ip")
        batch.drop_column("wan_interface")
        batch.drop_column("kind")
