"""Add local web accounts and server-side sessions."""
import sqlalchemy as sa
from alembic import op

revision = "0012_web_auth"
down_revision = "0011_node_provisioning"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "web_accounts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text()),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("source", sa.String(), server_default="local", nullable=False),
        sa.Column("subject", sa.Text()),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("role IN ('admin','operator','viewer')"),
        sa.CheckConstraint("source IN ('local','oidc')"),
    )
    op.create_table(
        "web_sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("account_id", sa.Integer(), sa.ForeignKey("web_accounts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("csrf_token", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip", sa.String()),
    )


def downgrade():
    op.drop_table("web_sessions")
    op.drop_table("web_accounts")
