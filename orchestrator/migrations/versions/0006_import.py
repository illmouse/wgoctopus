"""Add per-instance import and client configuration settings."""

import sqlalchemy as sa
from alembic import op

revision = "0006_import"
down_revision = "0005_failover"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("instances") as batch:
        batch.add_column(sa.Column("endpoint_host", sa.String(), nullable=True))
        batch.add_column(sa.Column("client_dns", sa.String(), nullable=True))
        batch.add_column(sa.Column("client_keepalive", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("client_allowed_ips", sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table("instances") as batch:
        batch.drop_column("client_allowed_ips")
        batch.drop_column("client_keepalive")
        batch.drop_column("client_dns")
        batch.drop_column("endpoint_host")
