"""v1.0: FORCE ROW LEVEL SECURITY so RLS applies to the table-owner role too.

Postgres RLS is bypassed by the table owner unless FORCE is set. The
backend connects as the `cyberscan` role which owns these tables, so the
existing policies were effectively advisory — the GUC was set but never
actually scoped any queries. This migration FORCEs RLS on every
tenant-scoped table; the existing policies (which already allow
unset-GUC for migrations / seed) keep working.

Revision ID: 0004_force_rls
Revises: 0003_v02_completion
Create Date: 2026-05-02
"""
from alembic import op


revision = "0004_force_rls"
down_revision = "0003_v02_completion"
branch_labels = None
depends_on = None


_TABLES = (
    "assets",
    "scans",
    "findings",
    "audit_log",
    "notification_channels",
    "users",
    "api_tokens",
)


def upgrade() -> None:
    for tbl in _TABLES:
        op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY")


def downgrade() -> None:
    for tbl in _TABLES:
        op.execute(f"ALTER TABLE {tbl} NO FORCE ROW LEVEL SECURITY")
