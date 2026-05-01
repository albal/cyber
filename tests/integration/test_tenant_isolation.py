"""Multi-tenant isolation: RLS is *forced* on tenant-scoped tables.

These tests require a live Postgres with the schema migrated through
0004_force_rls. They seed two tenants and verify:
  - Pinning the GUC to A returns only A's rows.
  - Pinning to B returns only B's rows.
  - Unset GUC (admin / migration mode) returns both.
  - INSERT with a foreign tenant_id is blocked by WITH CHECK.

Set TEST_DATABASE_URL to opt in (e.g. when the docker stack is up):

    TEST_DATABASE_URL=postgresql+psycopg://cyberscan:cyberscan@localhost:5432/cyberscan \\
        pytest tests/integration/test_tenant_isolation.py
"""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

DB_URL = os.environ.get("TEST_DATABASE_URL")
if not DB_URL:
    pytest.skip("TEST_DATABASE_URL not set — skipping live-DB tests", allow_module_level=True)

from sqlalchemy import create_engine, text  # noqa: E402

ENGINE = create_engine(DB_URL, pool_pre_ping=True)


def _scope(conn, tenant_id):
    conn.execute(
        text("SELECT set_config('app.tenant_id', :tid, true)"),
        {"tid": str(tenant_id) if tenant_id else ""},
    )


@pytest.fixture()
def two_tenants():
    a_id, b_id = uuid.uuid4(), uuid.uuid4()
    a_user, b_user = uuid.uuid4(), uuid.uuid4()
    with ENGINE.begin() as conn:
        _scope(conn, None)
        for tid, slug in (
            (a_id, f"iso-a-{a_id.hex[:6]}"),
            (b_id, f"iso-b-{b_id.hex[:6]}"),
        ):
            conn.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
                {"id": str(tid), "n": slug, "s": slug},
            )
        for uid, tid in ((a_user, a_id), (b_user, b_id)):
            conn.execute(
                text(
                    "INSERT INTO users (id, tenant_id, email, password_hash, role) "
                    "VALUES (:id, :tid, :email, '!', 'owner')"
                ),
                {"id": str(uid), "tid": str(tid), "email": f"{uid.hex[:8]}@iso.test"},
            )
    yield {"a_tenant": a_id, "b_tenant": b_id, "a_user": a_user, "b_user": b_user}
    with ENGINE.begin() as conn:
        _scope(conn, None)
        for tid in (a_id, b_id):
            for tbl in ("api_tokens", "audit_log", "findings", "scans", "assets", "users"):
                conn.execute(text(f"DELETE FROM {tbl} WHERE tenant_id = :t"), {"t": str(tid)})
            conn.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": str(tid)})


def _make_asset(conn, *, tenant_id, user_id, name):
    aid = uuid.uuid4()
    conn.execute(
        text(
            "INSERT INTO assets "
            "(id, tenant_id, name, target_url, hostname, verification_method, "
            " verification_token, verification_status, created_by) "
            "VALUES (:id, :tid, :n, 'http://x', 'x', 'http_file', 'tok', 'pending', :uid)"
        ),
        {"id": str(aid), "tid": str(tenant_id), "n": name, "uid": str(user_id)},
    )
    return aid


def test_select_returns_only_pinned_tenant_rows(two_tenants):
    t = two_tenants
    with ENGINE.begin() as conn:
        _scope(conn, None)
        _make_asset(conn, tenant_id=t["a_tenant"], user_id=t["a_user"], name="A-only")
        _make_asset(conn, tenant_id=t["b_tenant"], user_id=t["b_user"], name="B-only")
    with ENGINE.begin() as conn:
        _scope(conn, t["a_tenant"])
        names = {
            r.name
            for r in conn.execute(text("SELECT name FROM assets WHERE name IN ('A-only','B-only')")).all()
        }
    assert names == {"A-only"}


def test_select_returns_only_other_tenant_when_switched(two_tenants):
    t = two_tenants
    with ENGINE.begin() as conn:
        _scope(conn, None)
        _make_asset(conn, tenant_id=t["a_tenant"], user_id=t["a_user"], name="A2")
        _make_asset(conn, tenant_id=t["b_tenant"], user_id=t["b_user"], name="B2")
    with ENGINE.begin() as conn:
        _scope(conn, t["b_tenant"])
        names = {r.name for r in conn.execute(text("SELECT name FROM assets WHERE name IN ('A2','B2')")).all()}
    assert names == {"B2"}


def test_unset_guc_sees_both(two_tenants):
    t = two_tenants
    with ENGINE.begin() as conn:
        _scope(conn, None)
        _make_asset(conn, tenant_id=t["a_tenant"], user_id=t["a_user"], name="A-admin")
        _make_asset(conn, tenant_id=t["b_tenant"], user_id=t["b_user"], name="B-admin")
    with ENGINE.begin() as conn:
        _scope(conn, None)
        names = {
            r.name
            for r in conn.execute(text("SELECT name FROM assets WHERE name IN ('A-admin','B-admin')")).all()
        }
    assert names == {"A-admin", "B-admin"}


def test_insert_into_other_tenant_blocked_by_with_check(two_tenants):
    t = two_tenants
    aid = uuid.uuid4()
    with pytest.raises(Exception):  # noqa: B017
        with ENGINE.begin() as conn:
            _scope(conn, t["a_tenant"])
            conn.execute(
                text(
                    "INSERT INTO assets "
                    "(id, tenant_id, name, target_url, hostname, verification_method, "
                    " verification_token, verification_status, created_by) "
                    "VALUES (:id, :tid, 'cross', 'http://x', 'x', 'http_file', 'tok', 'pending', :uid)"
                ),
                {"id": str(aid), "tid": str(t["b_tenant"]), "uid": str(t["a_user"])},
            )
    with ENGINE.begin() as conn:
        _scope(conn, None)
        row = conn.execute(text("SELECT 1 FROM assets WHERE id = :id"), {"id": str(aid)}).first()
        assert row is None


def test_findings_scoped_by_tenant(two_tenants):
    t = two_tenants
    with ENGINE.begin() as conn:
        _scope(conn, None)
        a_asset = _make_asset(conn, tenant_id=t["a_tenant"], user_id=t["a_user"], name="A-find")
        b_asset = _make_asset(conn, tenant_id=t["b_tenant"], user_id=t["b_user"], name="B-find")
        for asset, tenant, user, label in (
            (a_asset, t["a_tenant"], t["a_user"], "FA"),
            (b_asset, t["b_tenant"], t["b_user"], "FB"),
        ):
            scan_id = uuid.uuid4()
            conn.execute(
                text(
                    "INSERT INTO scans (id, tenant_id, asset_id, status, progress, created_by) "
                    "VALUES (:id, :tid, :aid, 'completed', 100, :uid)"
                ),
                {"id": str(scan_id), "tid": str(tenant), "aid": str(asset), "uid": str(user)},
            )
            conn.execute(
                text(
                    "INSERT INTO findings "
                    "(id, tenant_id, scan_id, asset_id, title, severity, risk_score, dedupe_key, source) "
                    "VALUES (:id, :tid, :sid, :aid, :title, 'high', 75, :dk, 'nuclei')"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tid": str(tenant),
                    "sid": str(scan_id),
                    "aid": str(asset),
                    "title": label,
                    "dk": str(uuid.uuid4()),
                },
            )
    with ENGINE.begin() as conn:
        _scope(conn, t["a_tenant"])
        titles = {r.title for r in conn.execute(text("SELECT title FROM findings WHERE title IN ('FA','FB')")).all()}
    assert titles == {"FA"}


def test_audit_log_scoped_by_tenant(two_tenants):
    t = two_tenants
    with ENGINE.begin() as conn:
        _scope(conn, None)
        for tenant in (t["a_tenant"], t["b_tenant"]):
            conn.execute(
                text(
                    "INSERT INTO audit_log (id, tenant_id, action, target_type, target_id) "
                    "VALUES (:id, :tid, 'iso.test', 'asset', :tt)"
                ),
                {"id": str(uuid.uuid4()), "tid": str(tenant), "tt": f"audit-for-{tenant}"},
            )
    with ENGINE.begin() as conn:
        _scope(conn, t["a_tenant"])
        seen = {
            r.target_id
            for r in conn.execute(text("SELECT target_id FROM audit_log WHERE action = 'iso.test'")).all()
        }
    assert f"audit-for-{t['a_tenant']}" in seen
    assert f"audit-for-{t['b_tenant']}" not in seen


def test_api_tokens_scoped_by_tenant(two_tenants):
    t = two_tenants
    with ENGINE.begin() as conn:
        _scope(conn, None)
        for tenant, user, label in (
            (t["a_tenant"], t["a_user"], "tokA"),
            (t["b_tenant"], t["b_user"], "tokB"),
        ):
            conn.execute(
                text(
                    "INSERT INTO api_tokens "
                    "(id, tenant_id, created_by, name, token_hash, token_prefix) "
                    "VALUES (:id, :tid, :uid, :name, :h, 'cyb_abc')"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tid": str(tenant),
                    "uid": str(user),
                    "name": label,
                    "h": uuid.uuid4().hex,
                },
            )
    with ENGINE.begin() as conn:
        _scope(conn, t["b_tenant"])
        names = {
            r.name
            for r in conn.execute(text("SELECT name FROM api_tokens WHERE name IN ('tokA','tokB')")).all()
        }
    assert names == {"tokB"}
