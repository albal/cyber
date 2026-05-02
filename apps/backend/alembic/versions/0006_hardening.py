"""extras: subdomain enumeration toggle + scan cancellation status.

Revision ID: 0006_hardening
Revises: 0005_asset_credentials
Create Date: 2026-05-02
"""
from alembic import op
import sqlalchemy as sa


revision = "0006_hardening"
down_revision = "0005_asset_credentials"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Per-asset toggle: when on, subfinder runs against the hostname and the
    # discovered subdomains are added as crawl seeds.
    op.add_column(
        "assets",
        sa.Column("enumerate_subdomains", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    # New scan_status value 'cancelled' for user-aborted scans.
    op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'cancelled'")


def downgrade() -> None:
    op.drop_column("assets", "enumerate_subdomains")
    # Postgres has no DROP VALUE for enums; downgrade leaves the value in place.
