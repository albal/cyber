"""Subfinder JSONL output parser — pure logic, no network."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cyberscan_worker.recon import subfinder  # noqa: E402


def test_parse_extracts_unique_hosts():
    raw = "\n".join(
        [
            json.dumps({"host": "api.example.com", "source": "crt"}),
            json.dumps({"host": "www.example.com"}),
            json.dumps({"host": "api.example.com", "source": "dnsdumpster"}),
        ]
    )
    out = subfinder.parse(raw)
    assert out == ["api.example.com", "www.example.com"]


def test_parse_lowercases_hosts():
    raw = json.dumps({"host": "API.Example.COM"})
    assert subfinder.parse(raw) == ["api.example.com"]


def test_parse_handles_subdomain_alias():
    raw = json.dumps({"subdomain": "shop.example.com"})
    assert subfinder.parse(raw) == ["shop.example.com"]


def test_parse_skips_blank_lines_and_records():
    raw = "\n".join(
        [
            "",
            json.dumps({"host": "ok.example.com"}),
            json.dumps({"host": ""}),
            json.dumps({}),
        ]
    )
    assert subfinder.parse(raw) == ["ok.example.com"]


def test_parse_tolerates_plain_lines():
    """If subfinder emits non-JSON lines (-oJ alternate), accept them."""
    raw = "plain.example.com\n" + json.dumps({"host": "json.example.com"})
    out = subfinder.parse(raw)
    assert "plain.example.com" in out
    assert "json.example.com" in out


def test_parse_empty_input():
    assert subfinder.parse("") == []
