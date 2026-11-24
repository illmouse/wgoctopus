import sqlalchemy as sa
from alembic import op

revision = "0010_provisioning"
down_revision = "0009_bootstrap_managed"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("provision_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("node_id", sa.Integer(), sa.ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("state", sa.String(), nullable=False), sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text()), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)), sa.Column("finished_at", sa.DateTime(timezone=True)))
    op.create_table("provision_steps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("provision_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False), sa.Column("name", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False), sa.Column("log", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)), sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("job_id", "seq"))

def downgrade():
    op.drop_table("provision_steps")
    op.drop_table("provision_jobs")
