"""Asset-credentials encryption and scanner-auth projection."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cryptography.fernet import InvalidToken  # noqa: E402

from cyberscan_api.core.crypto import decrypt_json, encrypt_json  # noqa: E402
from cyberscan_api.schemas import (  # noqa: E402
    AssetCredentialBasic,
    AssetCredentialBearer,
    AssetCredentialCookie,
    AssetCredentialHeader,
)
from cyberscan_worker.auth.credentials import (  # noqa: E402
    ScannerAuth,
    decrypt as worker_decrypt,
    load_for_asset,
    to_scanner_auth,
)
from pydantic import ValidationError  # noqa: E402


SECRET = "test-secret-key-32-bytes-of-entropy"


# ---------- Fernet roundtrip --------------------------------------------------


def test_encrypt_decrypt_roundtrip():
    payload = {"cookie_header": "session=abc; token=xyz"}
    cipher = encrypt_json(payload, secret=SECRET)
    assert isinstance(cipher, str) and cipher
    assert cipher != json.dumps(payload)  # noqa: F821
    assert decrypt_json(cipher, secret=SECRET) == payload


def test_encrypt_is_nondeterministic():
    """Fernet uses a fresh IV per call — same plaintext yields different ciphers."""
    payload = {"token": "t"}
    a = encrypt_json(payload, secret=SECRET)
    b = encrypt_json(payload, secret=SECRET)
    assert a != b


def test_decrypt_with_wrong_key_raises():
    cipher = encrypt_json({"token": "t"}, secret=SECRET)
    with pytest.raises(InvalidToken):
        decrypt_json(cipher, secret="different-secret")


def test_decrypt_garbage_raises():
    with pytest.raises(InvalidToken):
        decrypt_json("not-a-valid-fernet-token", secret=SECRET)


# ---------- worker side decrypts what backend encrypted ----------------------


def test_backend_encrypt_worker_decrypt():
    """Both sides derive the same key from the shared API_SECRET_KEY."""
    cipher = encrypt_json({"token": "t-12345"}, secret=SECRET)
    decoded = worker_decrypt(cipher, secret=SECRET)
    assert decoded == {"token": "t-12345"}


# ---------- ScannerAuth projection -------------------------------------------


def test_to_scanner_auth_cookie():
    auth = to_scanner_auth(kind="cookie", secret={"cookie_header": "s=1; t=2"})
    assert isinstance(auth, ScannerAuth)
    assert auth.headers == []
    assert auth.cookie_header == "s=1; t=2"
    assert not auth.is_empty()


def test_to_scanner_auth_bearer():
    auth = to_scanner_auth(kind="bearer", secret={"token": "abc"})
    assert auth.headers == ["Authorization: Bearer abc"]
    assert auth.cookie_header is None


def test_to_scanner_auth_basic_uses_base64():
    """Basic auth headers must be base64(user:pass)."""
    import base64

    auth = to_scanner_auth(kind="basic", secret={"username": "alice", "password": "hunter2"})
    expected = "Basic " + base64.b64encode(b"alice:hunter2").decode()
    assert auth.headers == [f"Authorization: {expected}"]


def test_to_scanner_auth_custom_header():
    auth = to_scanner_auth(kind="header", secret={"name": "X-API-Key", "value": "k1"})
    assert auth.headers == ["X-API-Key: k1"]


def test_to_scanner_auth_unknown_kind_returns_empty():
    auth = to_scanner_auth(kind="hocus-pocus", secret={"foo": "bar"})
    assert auth.is_empty()


# ---------- load_for_asset (decryption + projection) -------------------------


def test_load_for_asset_full_path():
    cipher = encrypt_json({"token": "abc"}, secret=SECRET)
    auth = load_for_asset(ciphertext=cipher, kind="bearer", secret_key=SECRET)
    assert auth.headers == ["Authorization: Bearer abc"]


def test_load_for_asset_returns_empty_when_no_credentials():
    auth = load_for_asset(ciphertext=None, kind=None, secret_key=SECRET)
    assert auth.is_empty()


def test_load_for_asset_silently_returns_empty_on_decrypt_failure():
    """If the API key rotated since storage, decryption will fail. We do
    NOT crash the scan — just log and proceed unauthenticated."""
    cipher = encrypt_json({"token": "abc"}, secret=SECRET)
    auth = load_for_asset(ciphertext=cipher, kind="bearer", secret_key="wrong")
    assert auth.is_empty()


# ---------- Pydantic schema validation ---------------------------------------


def test_cookie_schema_rejects_blank_value():
    with pytest.raises(ValidationError):
        AssetCredentialCookie(cookie_header="")


def test_cookie_schema_pins_kind():
    with pytest.raises(ValidationError):
        AssetCredentialCookie(kind="bearer", cookie_header="x=1")


def test_basic_schema_accepts_normal_creds():
    c = AssetCredentialBasic(username="alice", password="hunter2")
    assert c.username == "alice"
    assert c.kind == "basic"


def test_basic_schema_rejects_blank_password():
    with pytest.raises(ValidationError):
        AssetCredentialBasic(username="alice", password="")


def test_bearer_schema_label_optional():
    c = AssetCredentialBearer(token="t")
    assert c.label is None


def test_header_schema_requires_name_and_value():
    with pytest.raises(ValidationError):
        AssetCredentialHeader(name="", value="x")
    with pytest.raises(ValidationError):
        AssetCredentialHeader(name="X-Foo", value="")


# json import for the assertion above
import json  # noqa: E402
