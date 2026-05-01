"""Verification helpers — token format, hostname extraction, instructions text."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.services.verification import (  # noqa: E402
    DNS_TXT_HOST,
    HEADER_NAME,
    WELL_KNOWN_PATH,
    hostname_from_url,
    instructions_for,
    new_token,
)


# ---------- new_token ---------------------------------------------------------


def test_new_token_unique():
    a, b = new_token(), new_token()
    assert a != b


def test_new_token_url_safe():
    """secrets.token_urlsafe characters: letters, digits, '-' and '_'."""
    t = new_token()
    assert all(c.isalnum() or c in "-_" for c in t)


def test_new_token_long_enough_to_resist_guessing():
    # token_urlsafe(24) → ~32 chars; require at least 24
    assert len(new_token()) >= 24


# ---------- hostname_from_url -------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://example.com", "example.com"),
        ("https://example.com/path", "example.com"),
        ("http://10.0.0.1:8080/", "10.0.0.1"),
        ("https://app.example.com:8443/x?q=1", "app.example.com"),
        ("http://juice-shop:3000", "juice-shop"),  # single-label dev hostnames
    ],
)
def test_hostname_extraction(url: str, expected: str):
    assert hostname_from_url(url) == expected


def test_hostname_lowercase_passthrough():
    # urlparse already lowercases the host portion
    assert hostname_from_url("HTTP://EXAMPLE.COM/Path") == "example.com"


def test_hostname_extraction_rejects_blank():
    with pytest.raises(ValueError):
        hostname_from_url("not-a-url")


# ---------- instructions_for --------------------------------------------------


def test_http_file_instructions_include_well_known_path():
    text = instructions_for("http_file", "example.com", "TKN")
    assert WELL_KNOWN_PATH.format(token="TKN") in text
    assert "TKN" in text
    assert "example.com" in text


def test_dns_txt_instructions_include_underscore_record():
    text = instructions_for("dns_txt", "example.com", "TKN")
    assert DNS_TXT_HOST.format(domain="example.com") in text
    assert "_cyberscan-verify.example.com" in text


def test_header_instructions_mention_custom_header():
    text = instructions_for("http_header", "example.com", "TKN")
    assert HEADER_NAME in text
    assert "X-Cyberscan-Verify" in text
    assert "TKN" in text


def test_unknown_method_raises():
    with pytest.raises(ValueError):
        instructions_for("carrier-pigeon", "example.com", "TKN")
