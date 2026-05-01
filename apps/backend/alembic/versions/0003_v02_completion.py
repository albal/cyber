"""v0.2 completion: scheduled scans, API tokens, OSV feed, scan intrusive flag

Revision ID: 0003_v02_completion
Revises: 0002_v02_tenancy_feeds
Create Date: 2026-05-01
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0003_v02_completion"
down_revision = "0002_v02_tenancy_feeds"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Schedule on assets (per-asset cron expression).
    op.add_column("assets", sa.Column("schedule_cron", sa.String(64), nullable=True))
    op.add_column("assets", sa.Column("schedule_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("assets", sa.Column("last_scheduled_at", sa.DateTime(timezone=True), nullable=True))

    # 2. Intrusive flag on scans + verification recency check.
    op.add_column("scans", sa.Column("intrusive", sa.Boolean(), nullable=False, server_default=sa.false()))

    # 3. API tokens for CI/CD.
    op.create_table(
        "api_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id"),
            index=True,
            nullable=False,
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("token_hash", sa.String(128), nullable=False, unique=True, index=True),
        sa.Column("token_prefix", sa.String(16), nullable=False),  # cosmetic display only
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 4. OSV advisories table (keyed by OSV id, indexed by alias for CVE lookup).
    op.create_table(
        "osv_advisories",
        sa.Column("osv_id", sa.String(64), primary_key=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("aliases", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("affected", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("severity", sa.String(32), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_osv_aliases_gin",
        "osv_advisories",
        [sa.text("aliases jsonb_path_ops")],
        postgresql_using="gin",
    )

    # 5. RLS on the new tenant-scoped tables.
    for tbl in ("api_tokens",):
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {tbl}_tenant_isolation ON {tbl}
              USING (
                tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
                OR NULLIF(current_setting('app.tenant_id', true), '') IS NULL
              )
              WITH CHECK (
                tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
                OR NULLIF(current_setting('app.tenant_id', true), '') IS NULL
              )
            """
        )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS api_tokens_tenant_isolation ON api_tokens")
    op.execute("ALTER TABLE api_tokens DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_osv_aliases_gin", table_name="osv_advisories")
    op.drop_table("osv_advisories")
    op.drop_table("api_tokens")
    op.drop_column("scans", "intrusive")
    op.drop_column("assets", "last_scheduled_at")
    op.drop_column("assets", "schedule_enabled")
    op.drop_column("assets", "schedule_cron")
