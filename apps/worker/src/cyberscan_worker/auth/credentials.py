"""Pure helpers: load + decrypt asset credentials, project to scanner headers.

Mirrors the encryption used in `apps/backend/src/cyberscan_api/core/crypto.py`
so the worker can decrypt what the API encrypted using only the shared
`API_SECRET_KEY`.
"""
from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger(__name__)


_HKDF_SALT = b"cyberscan-asset-credentials-v1"
_HKDF_INFO = b"asset_credentials.fernet"


@dataclass(slots=True)
class ScannerAuth:
    """Headers + cookie string ready to feed into katana / nuclei.

    `headers` is a list of "Name: value" strings (the format both katana
    and nuclei accept via -H). `cookie_header` is a single Cookie header
    value (no name prefix), suitable for katana's -cookie or nuclei's
    -H "Cookie: ...".
    """

    headers: list[str]
    cookie_header: str | None = None

    def is_empty(self) -> bool:
        return not self.headers and not self.cookie_header


def _derive_key(secret: str) -> bytes:
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(secret.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def decrypt(token: str, *, secret: str) -> dict:
    return json.loads(Fernet(_derive_key(secret)).decrypt(token.encode("ascii")))


def to_scanner_auth(*, kind: str, secret: dict) -> ScannerAuth:
    """Project a decrypted credential into headers / cookie for the scanners."""
    if kind == "cookie":
        return ScannerAuth(headers=[], cookie_header=secret.get("cookie_header"))
    if kind == "bearer":
        return ScannerAuth(headers=[f"Authorization: Bearer {secret['token']}"])
    if kind == "basic":
        b64 = base64.b64encode(
            f"{secret['username']}:{secret['password']}".encode("utf-8")
        ).decode("ascii")
        return ScannerAuth(headers=[f"Authorization: Basic {b64}"])
    if kind == "header":
        return ScannerAuth(headers=[f"{secret['name']}: {secret['value']}"])
    log.warning("unknown credential kind: %s", kind)
    return ScannerAuth(headers=[])


def load_for_asset(*, ciphertext: str | None, kind: str | None, secret_key: str) -> ScannerAuth:
    """Convenience: ciphertext+kind → ScannerAuth, swallowing decrypt errors."""
    if not ciphertext or not kind:
        return ScannerAuth(headers=[])
    try:
        decoded = decrypt(ciphertext, secret=secret_key)
    except InvalidToken:
        log.warning("credential decryption failed (wrong API_SECRET_KEY?)")
        return ScannerAuth(headers=[])
    return to_scanner_auth(kind=kind, secret=decoded)
