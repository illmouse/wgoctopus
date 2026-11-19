"""Initial desired and observed state schema."""

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("instances", sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(15), nullable=False, unique=True), sa.Column("listen_port", sa.Integer(), nullable=False, unique=True),
        sa.Column("address", sa.String(), nullable=False), sa.Column("private_key_enc", sa.Text(), nullable=False),
        sa.Column("public_key", sa.String(44), nullable=False), sa.Column("obfuscation", sa.JSON(), nullable=False),
        sa.Column("mtu", sa.Integer()), sa.Column("egress_interface", sa.String(15)), sa.Column("snat_ip", sa.String()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("nodes", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(), nullable=False, unique=True),
        sa.Column("ssh_host", sa.String(), nullable=False), sa.Column("ssh_port", sa.Integer(), nullable=False),
        sa.Column("ssh_user", sa.String(), nullable=False), sa.Column("mgmt_mode", sa.String(), nullable=False),
        sa.Column("agent_port", sa.Integer(), nullable=False), sa.Column("agent_token_enc", sa.Text(), nullable=False),
        sa.Column("egress_interface", sa.String(15)), sa.Column("snat_ip", sa.String()),
        sa.Column("enabled", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("placements", sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("instance_id", sa.Integer(), sa.ForeignKey("instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("node_id", sa.Integer(), sa.ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(), nullable=False), sa.Column("weight", sa.Integer(), nullable=False),
        sa.UniqueConstraint("instance_id", "node_id"))
    op.create_table("peers", sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("instance_id", sa.Integer(), sa.ForeignKey("instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(), nullable=False), sa.Column("public_key", sa.String(44), nullable=False),
        sa.Column("private_key_enc", sa.Text()), sa.Column("preshared_key_enc", sa.Text()),
        sa.Column("allowed_ip", sa.String(), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("owner", sa.String()), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("instance_id", "allowed_ip"))
    op.create_table("node_revisions", sa.Column("node_id", sa.Integer(), sa.ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("desired_revision", sa.Integer(), nullable=False), sa.Column("desired_checksum", sa.String(64)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("node_observed", sa.Column("node_id", sa.Integer(), sa.ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)), sa.Column("applied_revision", sa.Integer()),
        sa.Column("applied_checksum", sa.String(64)), sa.Column("healthy", sa.Boolean(), nullable=False),
        sa.Column("last_error", sa.Text()), sa.Column("raw", sa.JSON()))
    op.create_table("events", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(), nullable=False), sa.Column("subject", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False))


def downgrade():
    for table in ("events", "node_observed", "node_revisions", "peers", "placements", "nodes", "instances"):
        op.drop_table(table)
