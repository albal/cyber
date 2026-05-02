"""client_ip: X-Forwarded-For is honored only when the immediate peer is in
``trusted_proxies``. Otherwise, the header is ignored — no rate-limit
bypass via XFF spoofing.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))


def _make_request(peer: Optional[str], xff: Optional[str] = None):
    """Tiny fake matching the bits of starlette.Request that client_ip uses."""

    class _Headers(dict):
        def get(self, key, default=None):  # type: ignore[override]
            return super().get(key.lower(), default)

    class _Client:
        def __init__(self, host):
            self.host = host

    class _Req:
        def __init__(self):
            self.client = _Client(peer) if peer else None
            self.headers = _Headers()
            if xff:
                self.headers["x-forwarded-for"] = xff

    return _Req()


def _reload_settings(monkeypatch, trusted: str):
    monkeypatch.setenv("TRUSTED_PROXIES", trusted)
    from cyberscan_api.core.config import get_settings

    get_settings.cache_clear()  # type: ignore[attr-defined]


def test_xff_ignored_when_no_trusted_proxies(monkeypatch):
    _reload_settings(monkeypatch, "")
    from cyberscan_api.services.client_ip import client_ip

    req = _make_request(peer="203.0.113.5", xff="1.2.3.4")
    assert client_ip(req) == "203.0.113.5"


def test_xff_honored_when_peer_is_trusted(monkeypatch):
    _reload_settings(monkeypatch, "10.0.0.0/8")
    from cyberscan_api.services.client_ip import client_ip

    req = _make_request(peer="10.0.0.7", xff="198.51.100.42")
    assert client_ip(req) == "198.51.100.42"


def test_xff_ignored_when_peer_not_trusted(monkeypatch):
    """Spoofing test: untrusted peer claims an XFF — must be ignored."""
    _reload_settings(monkeypatch, "10.0.0.0/8")
    from cyberscan_api.services.client_ip import client_ip

    req = _make_request(peer="203.0.113.5", xff="1.2.3.4")
    assert client_ip(req) == "203.0.113.5"


def test_xff_walks_chain_and_returns_first_untrusted(monkeypatch):
    """Two-proxy chain: outer proxy forwarded the original client + the inner
    proxy. We strip trusted hops from the right and return the first
    untrusted entry."""
    _reload_settings(monkeypatch, "10.0.0.0/8")
    from cyberscan_api.services.client_ip import client_ip

    req = _make_request(peer="10.0.0.7", xff="198.51.100.42, 10.0.0.99")
    assert client_ip(req) == "198.51.100.42"


def test_returns_unknown_when_no_client(monkeypatch):
    _reload_settings(monkeypatch, "")
    from cyberscan_api.services.client_ip import client_ip

    req = _make_request(peer=None)
    assert client_ip(req) == "unknown"


def test_handles_garbage_xff(monkeypatch):
    """Malformed XFF entries don't crash — they're treated as untrusted."""
    _reload_settings(monkeypatch, "10.0.0.0/8")
    from cyberscan_api.services.client_ip import client_ip

    req = _make_request(peer="10.0.0.1", xff="not-an-ip")
    # Untrusted entry → returned as-is.
    assert client_ip(req) == "not-an-ip"
