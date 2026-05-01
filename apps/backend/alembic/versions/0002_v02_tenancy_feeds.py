"""v0.2: tenants, RBAC role, tenant_id everywhere, EPSS, notifications, finding source.

Revision ID: 0002_v02_tenancy_feeds
Revises: 0001_init
Create Date: 2026-05-08
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0002_v02_tenancy_feeds"
down_revision = "0001_init"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Tenants table.
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 2. Seed a default tenant so existing rows can be backfilled.
    op.execute(
        "INSERT INTO tenants (id, name, slug) VALUES "
        "('00000000-0000-0000-0000-000000000001', 'default', 'default')"
    )

    # 3. Role enum + users.role + users.tenant_id.
    postgresql.ENUM("owner", "admin", "analyst", "viewer", name="role").create(
        op.get_bind(), checkfirst=True
    )
    role = postgresql.ENUM(name="role", create_type=False)

    op.add_column("users", sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("users", sa.Column("role", role, nullable=True))
    op.execute("UPDATE users SET tenant_id = '00000000-0000-0000-0000-000000000001'")
    op.execute("UPDATE users SET role = 'owner' WHERE is_admin = TRUE")
    op.execute("UPDATE users SET role = 'viewer' WHERE role IS NULL")
    op.alter_column("users", "tenant_id", nullable=False)
    op.alter_column("users", "role", nullable=False, server_default="viewer")
    op.create_foreign_key("fk_users_tenant", "users", "tenants", ["tenant_id"], ["id"])
    op.create_index("ix_users_tenant", "users", ["tenant_id"])

    # 4. tenant_id on assets / scans / findings / audit_log / etc.
    for table in ("assets", "scans", "findings"):
        op.add_column(table, sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True))
        op.execute(f"UPDATE {table} SET tenant_id = '00000000-0000-0000-0000-000000000001'")
        op.alter_column(table, "tenant_id", nullable=False)
        op.create_foreign_key(f"fk_{table}_tenant", table, "tenants", ["tenant_id"], ["id"])
        op.create_index(f"ix_{table}_tenant", table, ["tenant_id"])

    op.add_column("audit_log", sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_index("ix_audit_log_tenant", "audit_log", ["tenant_id"])

    # 5. New finding column: source (nuclei|sslyze|zap).
    op.add_column(
        "findings",
        sa.Column("source", sa.String(32), nullable=False, server_default="nuclei"),
    )

    # 6. EPSS feed table.
    op.create_table(
        "epss",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("scored_at", sa.Date(), nullable=True),
    )

    # 7. Notification channels table.
    op.create_table(
        "notification_channels",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("kind", sa.String(32), nullable=False),  # email|slack|teams
        sa.Column("target", sa.String(2048), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "min_severity",
            postgresql.ENUM(name="severity", create_type=False),
            nullable=False,
            server_default="high",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 8. Row-Level Security on tenant-scoped tables. App sets the GUC
    #    `app.tenant_id` per session/transaction to scope reads & writes.
    rls_tables = ("assets", "scans", "findings", "audit_log", "notification_channels", "users")
    for tbl in rls_tables:
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY")
        # Permissive policy: tenant_id must match GUC, OR GUC is unset (admin/migration mode).
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
    rls_tables = ("assets", "scans", "findings", "audit_log", "notification_channels", "users")
    for tbl in rls_tables:
        op.execute(f"DROP POLICY IF EXISTS {tbl}_tenant_isolation ON {tbl}")
        op.execute(f"ALTER TABLE {tbl} DISABLE ROW LEVEL SECURITY")

    op.drop_table("notification_channels")
    op.drop_table("epss")
    op.drop_column("findings", "source")

    op.drop_index("ix_audit_log_tenant", table_name="audit_log")
    op.drop_column("audit_log", "tenant_id")
    for table in ("findings", "scans", "assets"):
        op.drop_constraint(f"fk_{table}_tenant", table, type_="foreignkey")
        op.drop_index(f"ix_{table}_tenant", table_name=table)
        op.drop_column(table, "tenant_id")

    op.drop_index("ix_users_tenant", table_name="users")
    op.drop_constraint("fk_users_tenant", "users", type_="foreignkey")
    op.drop_column("users", "role")
    op.drop_column("users", "tenant_id")
    sa.Enum(name="role").drop(op.get_bind(), checkfirst=True)

    op.drop_table("tenants")
