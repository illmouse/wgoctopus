import sqlalchemy as sa
from alembic import op

revision = "0008_bot_users"
down_revision = "0007_pull"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("bot_users", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("username", sa.String(64), nullable=False, unique=True), sa.Column("tg_id", sa.Integer(), unique=True), sa.Column("role", sa.String(), nullable=False, server_default="user"), sa.Column("config_limit", sa.Integer(), nullable=False, server_default="3"), sa.Column("status", sa.String(), nullable=False, server_default="enabled"), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("disabled_at", sa.DateTime(timezone=True)), sa.Column("disabled_by", sa.String()), sa.Column("language", sa.String(8)), sa.CheckConstraint("role IN ('admin','user')"), sa.CheckConstraint("status IN ('enabled','disabled')"), sa.CheckConstraint("config_limit >= -1"))
    op.create_table("user_requests", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("type", sa.String(), nullable=False), sa.Column("status", sa.String(), nullable=False, server_default="pending"), sa.Column("tg_id", sa.Integer(), nullable=False), sa.Column("username", sa.String(64)), sa.Column("first_name", sa.String()), sa.Column("last_name", sa.String()), sa.Column("requested_limit", sa.Integer()), sa.Column("previous_limit", sa.Integer()), sa.Column("admin_id", sa.Integer()), sa.Column("admin_username", sa.String(64)), sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False), sa.Column("decided_at", sa.DateTime(timezone=True)), sa.Column("notification_refs", sa.JSON(), nullable=False), sa.CheckConstraint("type IN ('access','limit')"), sa.CheckConstraint("status IN ('pending','approved','declined')"))
    op.create_table("admin_username_history", sa.Column("username", sa.String(64), primary_key=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))


def downgrade():
    op.drop_table("admin_username_history")
    op.drop_table("user_requests")
    op.drop_table("bot_users")
