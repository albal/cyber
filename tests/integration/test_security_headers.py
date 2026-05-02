"""SecurityHeadersMiddleware: every API response carries the conservative
hardening headers; HSTS only when the request was over HTTPS.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_SECRET_KEY", "test-secret-do-not-use-in-prod")
os.environ.setdefault("ENV", "dev")

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.core.config import get_settings  # noqa: E402

get_settings.cache_clear()  # type: ignore[attr-defined]

try:
    from fastapi.testclient import TestClient
    from cyberscan_api.main import app
except ModuleNotFoundError as exc:  # pragma: no cover
    pytest.skip(f"backend deps unavailable: {exc}", allow_module_level=True)


client = TestClient(app)


def test_healthz_returns_security_headers():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["permissions-policy"] == "()"


def test_hsts_omitted_on_plain_http():
    r = client.get("/healthz")
    assert "strict-transport-security" not in {k.lower() for k in r.headers}


def test_hsts_present_when_x_forwarded_proto_is_https():
    r = client.get("/healthz", headers={"X-Forwarded-Proto": "https"})
    assert "strict-transport-security" in {k.lower() for k in r.headers}
    assert "max-age=" in r.headers["strict-transport-security"]


def test_security_headers_on_404():
    """Even error responses carry the headers."""
    r = client.get("/this-does-not-exist")
    assert r.status_code == 404
    assert r.headers["x-content-type-options"] == "nosniff"
