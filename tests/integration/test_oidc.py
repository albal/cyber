"""OIDC helper logic — role parsing and discovery URL fallback. No network."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# OIDC settings must be set before importing the module, since `is_enabled`
# reads via the lru_cache'd `get_settings`.
os.environ["OIDC_ISSUER"] = "https://idp.example.com/realms/cyberscan"
os.environ["OIDC_AUDIENCE"] = "cyberscan"
os.environ["OIDC_DEFAULT_TENANT"] = "default"

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.core.config import get_settings  # noqa: E402
from cyberscan_api.models import Role  # noqa: E402

# Reset cached settings before importing oidc so the module sees our env.
get_settings.cache_clear()  # type: ignore[attr-defined]

try:
    from cyberscan_api.services import oidc  # noqa: E402
except ModuleNotFoundError as exc:
    pytest.skip(f"oidc deps unavailable: {exc}", allow_module_level=True)


def test_is_enabled_reflects_issuer_setting():
    assert oidc.is_enabled() is True


# ---------- _role_from_claims -------------------------------------------------


def test_role_from_string_claim():
    assert oidc._role_from_claims({"role": "admin"}) == Role.admin


def test_role_from_uppercase_claim():
    assert oidc._role_from_claims({"role": "OWNER"}) == Role.owner


def test_role_from_list_claim_picks_first_known():
    assert (
        oidc._role_from_claims({"role": ["unknown-thing", "analyst", "owner"]})
        == Role.analyst
    )


def test_role_from_unknown_claim_value_returns_none():
    assert oidc._role_from_claims({"role": "godmode"}) is None


def test_role_when_claim_missing_returns_none():
    assert oidc._role_from_claims({"sub": "u"}) is None


def test_role_with_empty_list_returns_none():
    assert oidc._role_from_claims({"role": []}) is None


# ---------- _discover_jwks_uri ------------------------------------------------


def test_discovery_returns_jwks_uri_from_well_known():
    class _R:
        def __init__(self):
            self.status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "issuer": "https://idp.example.com/realms/cyberscan",
                "jwks_uri": "https://idp.example.com/realms/cyberscan/protocol/openid-connect/certs",
            }

    with patch("cyberscan_api.services.oidc.httpx.get", return_value=_R()):
        uri = oidc._discover_jwks_uri("https://idp.example.com/realms/cyberscan")
    assert uri.endswith("/openid-connect/certs")


def test_discovery_falls_back_when_well_known_404s():
    import httpx

    def _raise(*args, **kwargs):
        raise httpx.HTTPError("boom")

    with patch("cyberscan_api.services.oidc.httpx.get", side_effect=_raise):
        uri = oidc._discover_jwks_uri("https://idp.example.com/")
    assert uri == "https://idp.example.com/.well-known/jwks.json"


# ---------- verify_and_get_user (rejection paths only — happy path needs network) ---


def test_verify_rejects_token_with_alg_none():
    """A JWT crafted with alg=none must be rejected even before signature check."""
    import jwt as pyjwt

    token = pyjwt.encode({"sub": "u"}, "anything", algorithm="HS256")
    head, _, _ = token.split(".")
    # Re-encode the header with alg=none.
    import base64
    import json

    header = {"alg": "none", "typ": "JWT"}
    fake = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        + "."
        + token.split(".", 1)[1]
    )
    assert oidc.verify_and_get_user(fake, db=object()) is None  # type: ignore[arg-type]


def test_verify_rejects_garbage():
    assert oidc.verify_and_get_user("not-a-jwt", db=object()) is None  # type: ignore[arg-type]
