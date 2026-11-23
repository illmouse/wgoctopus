"""Persist alert dispatcher state."""

import sqlalchemy as sa
from alembic import op

revision = "0004_alerts"
down_revision = "0003_probes"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("alert_state", sa.Column("key", sa.String(), primary_key=True),
                    sa.Column("value", sa.Text(), nullable=False))


def downgrade():
    op.drop_table("alert_state")
