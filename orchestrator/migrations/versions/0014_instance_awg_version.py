"""Persist the AWG version for each instance.

Revision ID: 0014
Revises: 0013
"""
import sqlalchemy as sa
from alembic import op

revision = "0014_instance_awg_version"
down_revision = "0013_node_ssh_credentials"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("instances", sa.Column("awg_version", sa.String(length=3), nullable=False, server_default="3.1"))
    op.execute("""
        UPDATE instances SET awg_version = CASE
          WHEN CAST(obfuscation AS VARCHAR) LIKE '%header_protection_key%' THEN '3.1'
          WHEN CAST(obfuscation AS VARCHAR) LIKE '%random_trailers%' THEN '3.1'
          WHEN CAST(obfuscation AS VARCHAR) LIKE '%content_padding_addition%' THEN '3.0'
          ELSE '2.0' END
    """)


def downgrade():
    op.drop_column("instances", "awg_version")
