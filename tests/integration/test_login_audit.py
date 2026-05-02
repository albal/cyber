"""End-to-end of the login route via TestClient on a sqlite-in-memory DB.
Covers: per-account bucket, per-IP+email bucket, audit rows for success /
failure / rate-limited.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_SECRET_KEY", "test-secret-do-not-use-in-prod")
os.environ.setdefault("ENV", "dev")
os.environ.setdefault("LOGIN_RATE_MAX_ATTEMPTS", "3")
os.environ.setdefault("LOGIN_RATE_WINDOW_S", "60")
os.environ.setdefault("LOGIN_ACCOUNT_MAX_ATTEMPTS", "5")
os.environ.setdefault("LOGIN_ACCOUNT_WINDOW_S", "3600")

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.core.config import get_settings  # noqa: E402

get_settings.cache_clear()  # type: ignore[attr-defined]


try:
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from cyberscan_api.core import db as core_db
    from cyberscan_api.core.security import hash_password
    from cyberscan_api.main import app
    from cyberscan_api.models import AuditLog, Tenant, User
    from cyberscan_api.models.tables import Base
    from cyberscan_api.services import rate_limit
except ModuleNotFoundError as exc:  # pragma: no cover
    pytest.skip(f"backend deps unavailable: {exc}", allow_module_level=True)


# A shared in-memory sqlite. AAA: each test wipes auth state via fixtures.
_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=__import__("sqlalchemy.pool", fromlist=["StaticPool"]).StaticPool,
)


def _create_schema():
    """Create only the tables the login flow touches. RLS / Postgres-only
    bits are skipped — sqlite ignores GRANT/ROW LEVEL SECURITY anyway."""
    # Drop pgcrypto-only server defaults that sqlite can't evaluate.
    Base.metadata.create_all(
        _engine,
        tables=[
            Tenant.__table__,
            User.__table__,
            AuditLog.__table__,
        ],
    )


def _override_db():
    db = Session(bind=_engine)
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def _wipe_buckets_and_db():
    rate_limit._clear_local()
    Base.metadata.drop_all(_engine, tables=[
        AuditLog.__table__, User.__table__, Tenant.__table__,
    ])
    _create_schema()
    yield
    rate_limit._clear_local()


@pytest.fixture()
def client(monkeypatch):
    # set_config('app.tenant_id') is a noop on sqlite. Patch _pin_tenant
    # so it doesn't error out.
    from cyberscan_api.services import auth_dep

    monkeypatch.setattr(auth_dep, "_pin_tenant", lambda *_a, **_kw: None)
    app.dependency_overrides[core_db.get_db] = _override_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(core_db.get_db, None)


def _seed_user(email="user@example.com", password="hunter2"):
    import uuid

    with Session(bind=_engine) as db:
        tenant = Tenant(id=uuid.uuid4(), name="default", slug="default")
        db.add(tenant)
        db.flush()
        user = User(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            email=email,
            password_hash=hash_password(password),
            role="owner",
        )
        db.add(user)
        db.commit()
        return user.id, tenant.id


def _audit_actions() -> list[str]:
    with Session(bind=_engine) as db:
        return [r.action for r in db.query(AuditLog).order_by(AuditLog.created_at).all()]


# ---------- happy path -------------------------------------------------------


def test_successful_login_logs_audit_row(client):
    _seed_user()
    r = client.post(
        "/api/v1/auth/login",
        data={"username": "user@example.com", "password": "hunter2"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 200
    assert "access_token" in r.json()
    assert _audit_actions() == ["auth.login.success"]


def test_failed_login_logs_audit_row(client):
    _seed_user()
    r = client.post(
        "/api/v1/auth/login",
        data={"username": "user@example.com", "password": "wrong"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 401
    assert _audit_actions() == ["auth.login.failure"]


def test_failed_login_for_unknown_email_still_audited(client):
    r = client.post(
        "/api/v1/auth/login",
        data={"username": "ghost@example.com", "password": "x"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 401
    actions = _audit_actions()
    assert actions == ["auth.login.failure"]


# ---------- rate-limit buckets ----------------------------------------------


def test_per_ip_email_bucket_blocks_after_max_attempts(client):
    _seed_user()
    for _ in range(3):
        client.post(
            "/api/v1/auth/login",
            data={"username": "user@example.com", "password": "wrong"},
        )
    r = client.post(
        "/api/v1/auth/login",
        data={"username": "user@example.com", "password": "hunter2"},  # correct now
    )
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    actions = _audit_actions()
    # 3 failures, then 1 rate-limited; correct password never reached
    # because the bucket fired first.
    assert actions[:3] == ["auth.login.failure"] * 3
    assert actions[3] == "auth.login.rate_limited"


def test_successful_login_resets_both_buckets(client):
    _seed_user()
    # Two failures (under the 3 limit).
    for _ in range(2):
        client.post(
            "/api/v1/auth/login",
            data={"username": "user@example.com", "password": "wrong"},
        )
    # Successful login.
    r_ok = client.post(
        "/api/v1/auth/login",
        data={"username": "user@example.com", "password": "hunter2"},
    )
    assert r_ok.status_code == 200

    # 3 more failures shouldn't trip immediately because the bucket was reset.
    for _ in range(2):
        r_fail = client.post(
            "/api/v1/auth/login",
            data={"username": "user@example.com", "password": "wrong"},
        )
        assert r_fail.status_code == 401, r_fail.text
