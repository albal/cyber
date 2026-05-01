"""JWT roundtrip + password hashing — covers the auth primitives end-to-end."""
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

# Ensure deterministic settings before security module loads its lru_cache
os.environ.setdefault("API_SECRET_KEY", "test-secret-do-not-use-in-prod")
os.environ.setdefault("JWT_EXPIRES_MIN", "60")

import jwt as pyjwt  # noqa: E402

from cyberscan_api.core.config import get_settings  # noqa: E402
from cyberscan_api.core.security import (  # noqa: E402
    create_access_token,
    decode_token,
    hash_password,
    verify_password,
)

SETTINGS = get_settings()


# ---------- password hashing --------------------------------------------------


def test_hash_password_is_not_plaintext():
    h = hash_password("hunter2")
    assert h != "hunter2"
    assert h.startswith("$2")  # bcrypt format


def test_hash_password_is_salted():
    a = hash_password("hunter2")
    b = hash_password("hunter2")
    assert a != b  # bcrypt embeds a per-call salt


def test_verify_password_accepts_correct():
    h = hash_password("correct-horse-battery-staple")
    assert verify_password("correct-horse-battery-staple", h) is True


def test_verify_password_rejects_wrong():
    h = hash_password("hunter2")
    assert verify_password("wrong", h) is False


def test_verify_password_rejects_empty():
    h = hash_password("hunter2")
    assert verify_password("", h) is False


# ---------- JWT roundtrip -----------------------------------------------------


def test_jwt_roundtrip_carries_subject_and_extras():
    tok = create_access_token("user-id-123", {"email": "x@example.com", "role": "owner"})
    payload = decode_token(tok)
    assert payload["sub"] == "user-id-123"
    assert payload["email"] == "x@example.com"
    assert payload["role"] == "owner"
    assert "exp" in payload and "iat" in payload


def test_jwt_signature_required():
    tok = create_access_token("u")
    # Tamper with the payload section (middle of the dot-separated triple).
    head, body, sig = tok.split(".")
    tampered = ".".join([head, body, sig[::-1]])
    with pytest.raises(pyjwt.PyJWTError):
        decode_token(tampered)


def test_jwt_rejects_wrong_algorithm():
    settings = SETTINGS
    bad = pyjwt.encode({"sub": "u"}, settings.api_secret_key, algorithm="HS512")
    with pytest.raises(pyjwt.PyJWTError):
        decode_token(bad)


def test_jwt_expired_rejected():
    settings = SETTINGS
    payload = {"sub": "u", "iat": int(time.time()) - 7200, "exp": int(time.time()) - 3600}
    expired = pyjwt.encode(payload, settings.api_secret_key, algorithm=settings.jwt_algorithm)
    with pytest.raises(pyjwt.ExpiredSignatureError):
        decode_token(expired)


def test_jwt_includes_iat_exp_in_seconds():
    tok = create_access_token("user")
    payload = decode_token(tok)
    assert isinstance(payload["iat"], int)
    assert isinstance(payload["exp"], int)
    assert payload["exp"] > payload["iat"]
