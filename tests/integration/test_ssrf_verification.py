"""SSRF guard on services.verification — refuses any hostname that
resolves to a private/loopback/link-local address. Cloud-metadata
(169.254.169.254) is the canonical bullseye.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))


def _reset_settings(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from cyberscan_api.core.config import get_settings

    get_settings.cache_clear()  # type: ignore[attr-defined]


def _fake_getaddrinfo(answers):
    def _stub(host, port, *args, **kwargs):
        # getaddrinfo returns 5-tuples; only the sockaddr (index 4) matters here.
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0)) for ip in answers]

    return _stub


# ---------- _is_public_ip -----------------------------------------------------


@pytest.mark.parametrize(
    "ip,expected_public",
    [
        ("8.8.8.8", True),
        ("1.1.1.1", True),
        ("127.0.0.1", False),
        ("10.0.0.5", False),
        ("172.16.0.1", False),
        ("192.168.1.1", False),
        ("169.254.169.254", False),  # cloud metadata
        ("0.0.0.0", False),
        ("224.0.0.1", False),  # multicast
        ("::1", False),
        ("fe80::1", False),
        ("fd00::1", False),  # IPv6 ULA
        ("2606:4700:4700::1111", True),  # cloudflare DNS
    ],
)
def test_is_public_ip(monkeypatch, ip, expected_public):
    _reset_settings(monkeypatch)
    from cyberscan_api.services.verification import _is_public_ip

    assert _is_public_ip(ip) is expected_public


# ---------- _safe_get refuses on resolution -----------------------------------


def test_safe_get_refuses_metadata_endpoint(monkeypatch):
    _reset_settings(monkeypatch, ALLOW_PRIVATE_TARGETS="false")
    from cyberscan_api.services import verification

    with patch.object(socket, "getaddrinfo", _fake_getaddrinfo(["169.254.169.254"])):
        with pytest.raises(verification._PrivateAddressRefused):
            verification._safe_get("http://metadata.example/")


def test_safe_get_refuses_loopback(monkeypatch):
    _reset_settings(monkeypatch, ALLOW_PRIVATE_TARGETS="false")
    from cyberscan_api.services import verification

    with patch.object(socket, "getaddrinfo", _fake_getaddrinfo(["127.0.0.1"])):
        with pytest.raises(verification._PrivateAddressRefused):
            verification._safe_get("http://localhost/")


def test_safe_get_refuses_mixed_public_private_answers(monkeypatch):
    """DNS rebinding: an attacker's record contains a public + a private
    IP. We refuse the whole hostname rather than gambling on which one
    httpx connects to."""
    _reset_settings(monkeypatch, ALLOW_PRIVATE_TARGETS="false")
    from cyberscan_api.services import verification

    with patch.object(
        socket, "getaddrinfo", _fake_getaddrinfo(["8.8.8.8", "192.168.1.1"])
    ):
        with pytest.raises(verification._PrivateAddressRefused):
            verification._safe_get("http://rebinding.example/")


def test_safe_get_allows_public_destination(monkeypatch):
    """Public-only resolution should pass through to httpx."""
    _reset_settings(monkeypatch, ALLOW_PRIVATE_TARGETS="false")
    from cyberscan_api.services import verification

    with patch.object(socket, "getaddrinfo", _fake_getaddrinfo(["93.184.216.34"])):
        with patch.object(verification.httpx, "get", return_value="OK") as m:
            result = verification._safe_get("http://example.com/")
            assert result == "OK"
            m.assert_called_once()


def test_safe_get_bypassed_when_private_targets_allowed(monkeypatch):
    """Self-hosted intranet verification: opt-in switch disables the guard."""
    _reset_settings(monkeypatch, ALLOW_PRIVATE_TARGETS="true")
    from cyberscan_api.services import verification

    with patch.object(verification.httpx, "get", return_value="OK") as m:
        # No DNS stub: the guard is fully bypassed and we never call getaddrinfo.
        result = verification._safe_get("http://10.0.0.42/")
        assert result == "OK"
        m.assert_called_once()


# ---------- _verify_http_file end-to-end --------------------------------------


def test_verify_http_file_refuses_private_target(monkeypatch):
    _reset_settings(monkeypatch, ALLOW_PRIVATE_TARGETS="false")
    from cyberscan_api.services import verification

    with patch.object(socket, "getaddrinfo", _fake_getaddrinfo(["10.0.0.1"])):
        ok, reason = verification.verify("http_file", "internal.host", "TKN")
        assert ok is False
        # Both schemes attempted, both rejected — the user-facing error is
        # the generic "not found" message; the SSRF refusal is logged
        # internally via httpx.HTTPError catch.
        assert "not found" in reason or "did not match" in reason
