"""Seed a default tenant + admin user. Idempotent."""
from sqlalchemy import select

from cyberscan_api.core.config import get_settings
from cyberscan_api.core.db import SessionLocal
from cyberscan_api.core.security import hash_password
from cyberscan_api.models import Role, Tenant, User

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"


def main() -> None:
    s = get_settings()
    with SessionLocal() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == "default"))
        if not tenant:
            tenant = Tenant(id=DEFAULT_TENANT_ID, name="Default", slug="default")
            db.add(tenant)
            db.commit()
            db.refresh(tenant)
            print(f"created tenant: {tenant.slug}")

        existing = db.scalar(select(User).where(User.email == s.seed_admin_email))
        if existing:
            print(f"admin user {s.seed_admin_email} already exists")
            return
        db.add(
            User(
                tenant_id=tenant.id,
                email=s.seed_admin_email,
                password_hash=hash_password(s.seed_admin_password),
                role=Role.owner,
                is_admin=True,
            )
        )
        db.commit()
        print(f"created admin user: {s.seed_admin_email}")


if __name__ == "__main__":
    main()
