import sqlalchemy as sa
from alembic import op

revision = "0009_bootstrap_managed"
down_revision = "0008_bot_users"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("bootstrap_managed", sa.Column("id", sa.Integer(), primary_key=True),
                    sa.Column("kind", sa.String(), nullable=False),
                    sa.Column("name", sa.String(), nullable=False),
                    sa.UniqueConstraint("kind", "name"))


def downgrade():
    op.drop_table("bootstrap_managed")
