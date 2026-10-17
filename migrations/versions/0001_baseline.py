"""Frozen baseline for three independent service databases."""

import os

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    if os.environ.get("SERVICE", "manager") == "manager":
        op.create_table(
            "assets",
            sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
            sa.Column("key", sa.String(64), nullable=False, unique=True),
            sa.Column("enabled", sa.Boolean(), nullable=False),
        )
        op.create_table(
            "audits",
            sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
            sa.Column("actor", sa.String(64), nullable=True),
            sa.Column("action", sa.String(60), nullable=True),
            sa.Column("entity", sa.String(100), nullable=True),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.String(40), nullable=True),
        )
        op.create_table(
            "scopes",
            sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
            sa.Column("name", sa.String(120), nullable=True),
            sa.Column("owner", sa.String(80), nullable=True),
            sa.Column("authorization_reference", sa.String(200), nullable=True),
            sa.Column("valid_from", sa.String(40), nullable=True),
            sa.Column("valid_until", sa.String(40), nullable=True),
            sa.Column("allowed_assets", sa.Text(), nullable=True),
            sa.Column("allowed_checks", sa.Text(), nullable=True),
            sa.Column("max_concurrency", sa.Integer(), nullable=True),
            sa.Column("rate", sa.Integer(), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=True),
        )
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
            sa.Column("username", sa.String(64), nullable=False, unique=True),
            sa.Column("password", sa.Text(), nullable=False),
            sa.Column("role", sa.String(20), nullable=False),
        )
        op.create_table(
            "findings",
            sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
            sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
            sa.Column("title", sa.String(200), nullable=True),
            sa.Column("category", sa.String(80), nullable=True),
            sa.Column("cwe_id", sa.String(20), nullable=True),
            sa.Column("severity", sa.String(20), nullable=True),
            sa.Column("confidence", sa.String(20), nullable=True),
            sa.Column("status", sa.String(30), nullable=True),
            sa.Column("location", sa.String(200), nullable=True),
            sa.Column("parameter", sa.String(80), nullable=True),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("impact", sa.Text(), nullable=True),
            sa.Column("reproduction", sa.Text(), nullable=True),
            sa.Column("remediation", sa.Text(), nullable=True),
            sa.Column("check_id", sa.String(30), nullable=True),
            sa.Column("method", sa.String(10), nullable=True),
            sa.Column("fingerprint", sa.String(64), nullable=True, unique=True),
            sa.Column("first_seen", sa.String(40), nullable=True),
            sa.Column("last_seen", sa.String(40), nullable=True),
        )
        op.create_table(
            "jobs",
            sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
            sa.Column("scope_id", sa.Integer(), sa.ForeignKey("scopes.id"), nullable=True),
            sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
            sa.Column("check_type", sa.String(30), nullable=True),
            sa.Column("status", sa.String(30), nullable=True),
            sa.Column("requested_by", sa.String(64), nullable=True),
            sa.Column("created_at", sa.String(40), nullable=True),
            sa.Column("started_at", sa.String(40), nullable=True),
            sa.Column("finished_at", sa.String(40), nullable=True),
            sa.Column("heartbeat_at", sa.String(40), nullable=True),
            sa.Column("deadline_at", sa.String(40), nullable=True),
            sa.Column("error_code", sa.String(60), nullable=True),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("cancel_requested", sa.Boolean(), nullable=True),
            sa.Column("retest_id", sa.Integer(), nullable=True),
        )
        op.create_table(
            "observations",
            sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
            sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=True),
            sa.Column("job_id", sa.Integer(), sa.ForeignKey("jobs.id"), nullable=True),
            sa.Column("created_at", sa.String(40), nullable=True),
            sa.Column("source", sa.String(30), nullable=True),
            sa.Column("evidence", sa.Text(), nullable=True),
        )
        op.create_table(
            "retests",
            sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
            sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=True),
            sa.Column("job_id", sa.Integer(), sa.ForeignKey("jobs.id"), nullable=True),
            sa.Column("created_at", sa.String(40), nullable=True),
            sa.Column("result", sa.String(30), nullable=True),
            sa.Column("detail", sa.Text(), nullable=True),
        )
    else:
        op.create_table(
            "members",
            sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
            sa.Column("username", sa.String(64), nullable=True, unique=True),
            sa.Column("password", sa.Text(), nullable=True),
            sa.Column("role", sa.String(20), nullable=True),
            sa.Column("display_name", sa.String(100), nullable=True),
        )
        op.create_table(
            "tasks",
            sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
            sa.Column("owner_id", sa.Integer(), sa.ForeignKey("members.id"), nullable=True),
            sa.Column("title", sa.String(200), nullable=True),
            sa.Column("body", sa.Text(), nullable=True),
            sa.Column("visibility", sa.String(20), nullable=True),
        )
        op.create_table(
            "comments",
            sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
            sa.Column("task_id", sa.Integer(), sa.ForeignKey("tasks.id"), nullable=True),
            sa.Column("author_id", sa.Integer(), sa.ForeignKey("members.id"), nullable=True),
            sa.Column("body", sa.Text(), nullable=True),
        )


def downgrade():
    raise RuntimeError("Use project-scoped reset; automatic data loss disabled")
