"""Seed an admin user from env vars. Idempotent."""
from sqlalchemy import select

from cyberscan_api.core.config import get_settings
from cyberscan_api.core.db import SessionLocal
from cyberscan_api.core.security import hash_password
from cyberscan_api.models import User


def main() -> None:
    s = get_settings()
    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.email == s.seed_admin_email))
        if existing:
            print(f"admin user {s.seed_admin_email} already exists")
            return
        db.add(
            User(
                email=s.seed_admin_email,
                password_hash=hash_password(s.seed_admin_password),
                is_admin=True,
            )
        )
        db.commit()
        print(f"created admin user: {s.seed_admin_email}")


if __name__ == "__main__":
    main()
