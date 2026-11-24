import sqlalchemy as sa
from alembic import op

revision = "0011_node_provisioning"
down_revision = "0010_provisioning"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("nodes") as batch:
        batch.add_column(sa.Column("protected", sa.Boolean(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("provision_options", sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table("nodes") as batch:
        batch.drop_column("provision_options")
        batch.drop_column("protected")
