"""Verification helper unit tests (token + URL formatting)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.services.verification import (  # noqa: E402
    hostname_from_url,
    instructions_for,
    new_token,
)


def test_new_token_unique():
    a = new_token()
    b = new_token()
    assert a != b
    assert len(a) >= 24


def test_hostname_from_url():
    assert hostname_from_url("https://example.com/path?x=1") == "example.com"
    assert hostname_from_url("http://10.0.0.1:8080/") == "10.0.0.1"


def test_instructions_render():
    t = "TOKEN123"
    text = instructions_for("http_file", "example.com", t)
    assert ".well-known/cyberscan-TOKEN123.txt" in text
    assert t in text
    text2 = instructions_for("dns_txt", "example.com", t)
    assert "_cyberscan-verify.example.com" in text2
    text3 = instructions_for("http_header", "example.com", t)
    assert "X-Cyberscan-Verify" in text3
