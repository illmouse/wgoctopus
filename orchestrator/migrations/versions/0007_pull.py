import sqlalchemy as sa
from alembic import op

revision = "0007_pull"
down_revision = "0006_import"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("nodes") as batch:
        batch.add_column(sa.Column("pull_public_key", sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table("nodes") as batch:
        batch.drop_column("pull_public_key")
