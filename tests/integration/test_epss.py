"""EPSS CSV parser tests (no network)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cyberscan_worker.feeds.epss import _parse_csv  # noqa: E402


def test_parse_csv_basic():
    raw = "cve,epss,percentile\nCVE-2021-44228,0.97,0.99\nCVE-2017-5638,0.95,0.98\n"
    rows = _parse_csv(raw)
    assert len(rows) == 2
    assert rows[0] == ("CVE-2021-44228", 0.97, 0.99)


def test_parse_csv_skips_comments():
    raw = "# model_version: v3.0 score_date: 2026-05-01\ncve,epss,percentile\nCVE-X,0.1,0.5\n"
    rows = _parse_csv(raw)
    assert rows == [("CVE-X", 0.1, 0.5)]


def test_parse_csv_skips_malformed_numeric():
    raw = "cve,epss,percentile\nCVE-OK,0.1,0.5\nCVE-BAD,not-a-number,0.5\n"
    rows = _parse_csv(raw)
    assert ("CVE-OK", 0.1, 0.5) in rows
    assert all(r[0] != "CVE-BAD" for r in rows)
