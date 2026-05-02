"""OIDC alg-confusion: a token signed HS256 with the issuer's *public* key
must be rejected, even though it would otherwise verify against that key.

This is the classic "I gave you my public key, you used it as an HMAC
secret" attack. Cyberscan only allows asymmetric algs (RS*/ES*/PS*) — any
other ``alg`` header value is rejected before the signature is even
checked.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

os.environ["OIDC_ISSUER"] = "https://idp.example.com/realms/cyberscan"
os.environ["OIDC_AUDIENCE"] = "cyberscan"
os.environ["OIDC_DEFAULT_TENANT"] = "default"

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.core.config import get_settings  # noqa: E402

get_settings.cache_clear()  # type: ignore[attr-defined]

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import jwt as pyjwt
    from cyberscan_api.services import oidc
except ModuleNotFoundError as exc:  # pragma: no cover
    pytest.skip(f"oidc deps unavailable: {exc}", allow_module_level=True)


def _rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub, pub_pem


def _b64u(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def test_hs256_token_signed_with_rsa_public_key_is_rejected():
    """Forge: hand-build an HS256 JWT using the issuer's public key as the
    HMAC secret. PyJWT refuses to *encode* this configuration, but an
    attacker isn't going through PyJWT — they're emitting bytes. So we
    sign by hand and hand the result to verify_and_get_user.

    If the alg gate were missing and we passed algorithms=['HS256'], the
    token would verify (the public key bytes would match the HMAC secret).
    With the asymmetric-only allowlist it is rejected before signature
    check."""
    import hashlib
    import hmac
    import json

    _, _, pub_pem = _rsa_keypair()

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "u", "iss": os.environ["OIDC_ISSUER"], "aud": "cyberscan"}
    signing_input = (
        _b64u(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64u(json.dumps(payload, separators=(",", ":")).encode())
    )
    sig = hmac.new(pub_pem, signing_input.encode(), hashlib.sha256).digest()
    forged = signing_input + "." + _b64u(sig)

    class _SK:
        key = pub_pem

    class _Client:
        def get_signing_key_from_jwt(self, _t):
            return _SK()

    with patch.object(oidc, "_get_jwks_client", return_value=_Client()):
        assert oidc.verify_and_get_user(forged, db=object()) is None  # type: ignore[arg-type]


def test_rs256_token_with_unsupported_alg_in_header_is_rejected():
    """Anything outside the asymmetric allowlist must be rejected."""
    forged = pyjwt.encode({"sub": "u"}, "secret", algorithm="HS384")
    assert oidc.verify_and_get_user(forged, db=object()) is None  # type: ignore[arg-type]


def test_rs256_token_through_happy_path_is_accepted_signature_wise(monkeypatch):
    """Sanity check: a properly signed RS256 token reaches signature
    verification (it'll then fail provisioning because we mock the DB,
    but the alg gate should let it through)."""
    priv, _, _ = _rsa_keypair()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    token = pyjwt.encode(
        {
            "sub": "u",
            "iss": os.environ["OIDC_ISSUER"],
            "aud": "cyberscan",
            "iat": 1700000000,
            "exp": 9999999999,
            "email": "user@example.com",
        },
        priv_pem,
        algorithm="RS256",
    )

    class _SK:
        key = pub_pem

    class _Client:
        def get_signing_key_from_jwt(self, _t):
            return _SK()

    with patch.object(oidc, "_get_jwks_client", return_value=_Client()):
        # _provision_user requires a real DB session; we just want to confirm
        # the alg gate doesn't reject a valid RS256 token. Patch _provision_user
        # to short-circuit and return a sentinel so we can tell verification
        # passed.
        with patch.object(oidc, "_provision_user", return_value="ok"):
            assert oidc.verify_and_get_user(token, db=object()) == "ok"  # type: ignore[arg-type]
