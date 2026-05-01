"""init

Revision ID: 0001_init
Revises:
Create Date: 2026-05-01
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_init"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_users_email", "users", ["email"])

    # Create enums explicitly (idempotent), then reference with create_type=False
    # so subsequent op.create_table() calls don't re-emit CREATE TYPE without
    # checkfirst (which fails on a re-run with leftover types).
    postgresql.ENUM(
        "pending", "verified", "expired", "failed", name="verification_status"
    ).create(op.get_bind(), checkfirst=True)
    postgresql.ENUM(
        "queued", "running", "completed", "failed", "partial", name="scan_status"
    ).create(op.get_bind(), checkfirst=True)
    postgresql.ENUM(
        "critical", "high", "medium", "low", "info", name="severity"
    ).create(op.get_bind(), checkfirst=True)

    verification_status = postgresql.ENUM(name="verification_status", create_type=False)
    scan_status = postgresql.ENUM(name="scan_status", create_type=False)
    severity = postgresql.ENUM(name="severity", create_type=False)

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("target_url", sa.String(2048), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False, index=True),
        sa.Column("verification_method", sa.String(32), nullable=False, server_default="http_file"),
        sa.Column("verification_token", sa.String(64), nullable=False),
        sa.Column("verification_status", verification_status, nullable=False, server_default="pending"),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id"), index=True),
        sa.Column("status", scan_status, nullable=False, server_default="queued"),
        sa.Column("stage", sa.String(64), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("summary", postgresql.JSON(), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id"), index=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id"), index=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("template_id", sa.String(255), nullable=True),
        sa.Column("cve_ids", postgresql.JSON(), nullable=False, server_default="[]"),
        sa.Column("cwe_ids", postgresql.JSON(), nullable=False, server_default="[]"),
        sa.Column("severity", severity, nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("is_kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("location", sa.String(2048), nullable=True),
        sa.Column("matcher_name", sa.String(255), nullable=True),
        sa.Column("request", sa.Text(), nullable=True),
        sa.Column("response_excerpt", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("references", postgresql.JSON(), nullable=False, server_default="[]"),
        sa.Column("compliance_tags", postgresql.JSON(), nullable=False, server_default="[]"),
        sa.Column("diff_status", sa.String(16), nullable=True),
        sa.Column("dedupe_key", sa.String(128), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_ip", sa.String(64), nullable=True),
        sa.Column("action", sa.String(128), nullable=False, index=True),
        sa.Column("target_type", sa.String(64), nullable=True),
        sa.Column("target_id", sa.String(128), nullable=True),
        sa.Column("details", postgresql.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Vulnerability feed tables (populated by worker)
    op.create_table(
        "cves",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("cvss_v3", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(255), nullable=True),
        sa.Column("cwe_ids", postgresql.JSON(), nullable=False, server_default="[]"),
        sa.Column("references", postgresql.JSON(), nullable=False, server_default="[]"),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "kev",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("date_added", sa.Date(), nullable=True),
        sa.Column("ransomware_use", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("due_date", sa.Date(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("kev")
    op.drop_table("cves")
    op.drop_table("audit_log")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("assets")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
    sa.Enum(name="severity").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="scan_status").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="verification_status").drop(op.get_bind(), checkfirst=True)
