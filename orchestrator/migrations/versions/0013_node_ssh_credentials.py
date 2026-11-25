"""Store per-node SSH credentials encrypted."""
import sqlalchemy as sa
from alembic import op

revision = "0013_node_ssh_credentials"
down_revision = "0012_web_auth"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("nodes", sa.Column("ssh_private_key_enc", sa.Text()))
    op.add_column("nodes", sa.Column("ssh_public_key", sa.Text()))
    op.add_column("nodes", sa.Column("ssh_password_enc", sa.Text()))


def downgrade():
    op.drop_column("nodes", "ssh_password_enc")
    op.drop_column("nodes", "ssh_public_key")
    op.drop_column("nodes", "ssh_private_key_enc")
