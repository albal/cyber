"""Symmetric encryption for at-rest secrets (asset credentials).

Fernet keyed off the application's `API_SECRET_KEY` via HKDF-SHA256.
Nothing fancy — the goal is to ensure a leaked DB dump doesn't yield
plaintext credentials. The key derivation is deterministic so the
worker can decrypt what the API encrypted using only the shared
`API_SECRET_KEY`.

If you rotate `API_SECRET_KEY`, existing rows become unreadable. A
proper rotation would mint a new key, re-encrypt with both, then drop
the old key (out of scope for v1.0).
"""
from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


_HKDF_SALT = b"cyberscan-asset-credentials-v1"
_HKDF_INFO = b"asset_credentials.fernet"


def _derive_key(secret: str) -> bytes:
    """Derive a 32-byte url-safe-base64 Fernet key from the app secret."""
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(secret.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def _fernet(secret: str) -> Fernet:
    return Fernet(_derive_key(secret))


def encrypt_json(payload: dict[str, Any], *, secret: str) -> str:
    """Encrypt a JSON-serializable payload; returns a Fernet token (str)."""
    blob = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _fernet(secret).encrypt(blob).decode("ascii")


def decrypt_json(token: str, *, secret: str) -> dict[str, Any]:
    """Decrypt a previously-encrypted token. Raises InvalidToken on tamper /
    wrong key."""
    blob = _fernet(secret).decrypt(token.encode("ascii"))
    return json.loads(blob)


# Re-export for callers that want to catch decryption failures.
__all__ = ["encrypt_json", "decrypt_json", "InvalidToken"]
