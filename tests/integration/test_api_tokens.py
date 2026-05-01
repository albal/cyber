"""API-token plumbing tests — hash + prefix sanity, no DB."""
import hashlib
import re
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.services.auth_dep import API_TOKEN_PREFIX  # noqa: E402


def _new_token() -> str:
    return f"{API_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


def test_token_starts_with_known_prefix():
    t = _new_token()
    assert t.startswith(API_TOKEN_PREFIX)
    assert API_TOKEN_PREFIX == "cyb_"


def test_hash_is_deterministic_and_64_hex():
    t = _new_token()
    h1 = hashlib.sha256(t.encode()).hexdigest()
    h2 = hashlib.sha256(t.encode()).hexdigest()
    assert h1 == h2
    assert re.fullmatch(r"[0-9a-f]{64}", h1)


def test_hash_differs_between_tokens():
    a, b = _new_token(), _new_token()
    assert a != b
    assert hashlib.sha256(a.encode()).hexdigest() != hashlib.sha256(b.encode()).hexdigest()
