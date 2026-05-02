"""write_audit: defaults pulled from User, actor_ip from request, override
arguments respected. The audit_log column has been there since v0.1 but
nothing was populating it; this helper makes that the default path.
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.services.audit import write_audit  # noqa: E402


class _FakeUser:
    def __init__(self, *, tenant_id, user_id):
        self.tenant_id = tenant_id
        self.id = user_id


class _FakeSession:
    def __init__(self):
        self.added: list = []

    def add(self, obj):
        self.added.append(obj)


class _FakeRequest:
    def __init__(self, peer: Optional[str], xff: Optional[str] = None):
        class _H(dict):
            def get(self, k, default=None):  # type: ignore[override]
                return super().get(k.lower(), default)

        class _C:
            def __init__(self, host):
                self.host = host

        self.client = _C(peer) if peer else None
        self.headers = _H()
        if xff:
            self.headers["x-forwarded-for"] = xff


def _reset_settings(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from cyberscan_api.core.config import get_settings

    get_settings.cache_clear()  # type: ignore[attr-defined]


def test_actor_ip_is_pulled_from_request(monkeypatch):
    _reset_settings(monkeypatch, TRUSTED_PROXIES="")
    db = _FakeSession()
    req = _FakeRequest(peer="203.0.113.5")

    row = write_audit(db, action="x.test", request=req)
    assert row.actor_ip == "203.0.113.5"
    assert db.added == [row]


def test_actor_ip_respects_trusted_proxies(monkeypatch):
    _reset_settings(monkeypatch, TRUSTED_PROXIES="10.0.0.0/8")
    db = _FakeSession()
    req = _FakeRequest(peer="10.0.0.7", xff="198.51.100.42")

    row = write_audit(db, action="x.test", request=req)
    assert row.actor_ip == "198.51.100.42"


def test_user_provides_tenant_and_actor(monkeypatch):
    _reset_settings(monkeypatch)
    db = _FakeSession()
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    user = _FakeUser(tenant_id=tenant_id, user_id=user_id)

    row = write_audit(db, action="x.test", user=user)
    assert row.tenant_id == tenant_id
    assert row.actor_user_id == user_id


def test_explicit_overrides_win_over_user(monkeypatch):
    """Login-failure audits have user=None but pass tenant_id/actor_user_id
    explicitly when the email exists. The override has to win."""
    _reset_settings(monkeypatch)
    db = _FakeSession()
    user_t = uuid.uuid4()
    user_id = uuid.uuid4()
    user = _FakeUser(tenant_id=user_t, user_id=user_id)
    explicit_t = uuid.uuid4()

    row = write_audit(db, action="x.test", user=user, tenant_id=explicit_t)
    assert row.tenant_id == explicit_t
    assert row.actor_user_id == user_id  # not overridden


def test_anonymous_audit_has_no_user_or_tenant(monkeypatch):
    _reset_settings(monkeypatch)
    db = _FakeSession()
    row = write_audit(db, action="auth.login.failure", details={"email": "x@y.z"})
    assert row.tenant_id is None
    assert row.actor_user_id is None
    assert row.actor_ip is None
    assert row.details == {"email": "x@y.z"}


def test_explicit_actor_ip_wins_over_request(monkeypatch):
    _reset_settings(monkeypatch)
    db = _FakeSession()
    req = _FakeRequest(peer="203.0.113.5")
    row = write_audit(db, action="x.test", request=req, actor_ip="9.9.9.9")
    assert row.actor_ip == "9.9.9.9"
