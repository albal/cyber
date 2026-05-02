"""v1.0: per-asset authentication credentials for authenticated scans.

Stores at most one credential record per asset, ciphertext-only. The
plaintext secret never hits the DB; it's encrypted with Fernet keyed off
API_SECRET_KEY (see cyberscan_api.core.crypto). The router never returns
the ciphertext — only the kind + last 4 chars of the label.

Revision ID: 0005_asset_credentials
Revises: 0004_force_rls
Create Date: 2026-05-02
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0005_asset_credentials"
down_revision = "0004_force_rls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id"),
            index=True,
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            unique=True,
            nullable=False,
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id")),
        # cookie | bearer | basic | header — validated at the API layer.
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("label", sa.String(255), nullable=True),
        # Fernet-encrypted JSON; shape varies by kind. Decryption happens in
        # the worker right before injecting into the scanner. URL-safe base64.
        sa.Column("secret_ciphertext", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.execute("ALTER TABLE asset_credentials ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE asset_credentials FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY asset_credentials_tenant_isolation ON asset_credentials
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
    op.execute("DROP POLICY IF EXISTS asset_credentials_tenant_isolation ON asset_credentials")
    op.drop_table("asset_credentials")
