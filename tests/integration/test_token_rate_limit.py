"""POST /api/v1/tokens is admin-only and now also per-user rate-limited.
This blunts the 'compromised admin session mints tokens in a hot loop'
class of attack."""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

os.environ.setdefault("API_SECRET_KEY", "test-secret-do-not-use-in-prod")
os.environ.setdefault("ENV", "dev")
os.environ.setdefault("TOKEN_CREATE_MAX", "3")
os.environ.setdefault("TOKEN_CREATE_WINDOW_S", "60")

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.core.config import get_settings  # noqa: E402

get_settings.cache_clear()  # type: ignore[attr-defined]


try:
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from cyberscan_api.core import db as core_db
    from cyberscan_api.core.security import create_access_token, hash_password
    from cyberscan_api.main import app
    from cyberscan_api.models import ApiToken, AuditLog, Tenant, User
    from cyberscan_api.models.tables import Base
    from cyberscan_api.services import rate_limit
except ModuleNotFoundError as exc:  # pragma: no cover
    pytest.skip(f"backend deps unavailable: {exc}", allow_module_level=True)


_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=__import__("sqlalchemy.pool", fromlist=["StaticPool"]).StaticPool,
)


def _override_db():
    db = Session(bind=_engine)
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def _wipe_state():
    rate_limit._clear_local()
    Base.metadata.drop_all(
        _engine,
        tables=[
            ApiToken.__table__,
            AuditLog.__table__,
            User.__table__,
            Tenant.__table__,
        ],
    )
    Base.metadata.create_all(
        _engine,
        tables=[
            Tenant.__table__,
            User.__table__,
            ApiToken.__table__,
            AuditLog.__table__,
        ],
    )
    yield
    rate_limit._clear_local()


@pytest.fixture()
def auth_client(monkeypatch):
    from cyberscan_api.services import auth_dep

    monkeypatch.setattr(auth_dep, "_pin_tenant", lambda *_a, **_kw: None)
    app.dependency_overrides[core_db.get_db] = _override_db

    # Seed an admin user.
    with Session(bind=_engine) as db:
        tenant = Tenant(id=uuid.uuid4(), name="default", slug="default")
        db.add(tenant)
        db.flush()
        admin = User(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            email="admin@example.com",
            password_hash=hash_password("admin"),
            role="admin",
        )
        db.add(admin)
        db.commit()
        admin_id = str(admin.id)

    token = create_access_token(admin_id, {"email": "admin@example.com"})
    try:
        yield TestClient(app), token
    finally:
        app.dependency_overrides.pop(core_db.get_db, None)


def test_token_creation_blocked_after_max(auth_client):
    client, jwt = auth_client
    headers = {"Authorization": f"Bearer {jwt}"}

    for i in range(3):
        r = client.post("/api/v1/tokens", json={"name": f"t{i}"}, headers=headers)
        assert r.status_code == 201, r.text

    # 4th creation trips the per-user bucket.
    r = client.post("/api/v1/tokens", json={"name": "t-blocked"}, headers=headers)
    assert r.status_code == 429
    assert "Retry-After" in r.headers


def test_token_creation_audit_carries_actor_ip(auth_client):
    client, jwt = auth_client
    headers = {"Authorization": f"Bearer {jwt}"}

    r = client.post("/api/v1/tokens", json={"name": "ci"}, headers=headers)
    assert r.status_code == 201

    with Session(bind=_engine) as db:
        rows = list(db.query(AuditLog).all())
    create_rows = [r for r in rows if r.action == "token.create"]
    assert len(create_rows) == 1
    # TestClient sets request.client.host to "testclient"; with no
    # trusted proxies configured, that's what shows up in actor_ip.
    assert create_rows[0].actor_ip == "testclient"
