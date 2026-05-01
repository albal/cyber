"""Notification dispatcher formatting tests (pure-python, no SMTP/HTTP)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cyberscan_worker.notify.dispatcher import (  # noqa: E402
    ScanSummary,
    _max_sev,
    _summary_text,
)


def _summary(critical=0, high=0, medium=0, low=0, info=0, new=0, fixed=0):
    return ScanSummary(
        scan_id="abc-123",
        asset_name="main-site",
        target_url="https://example.com",
        counts={"critical": critical, "high": high, "medium": medium, "low": low, "info": info},
        new=new,
        fixed=fixed,
        top_findings=[
            ("Log4Shell", "critical", 99.7, ["CVE-2021-44228"]),
            ("Weak TLS", "medium", 55.0, []),
        ],
    )


def test_max_sev_picks_highest_with_count():
    assert _max_sev({"critical": 0, "high": 2, "medium": 5}) == "high"
    assert _max_sev({"critical": 1, "high": 0}) == "critical"
    assert _max_sev({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}) == "info"


def test_summary_text_renders_top_findings():
    text = _summary_text(_summary(critical=1, high=2, new=1, fixed=0))
    assert "main-site" in text
    assert "Log4Shell" in text
    assert "CVE-2021-44228" in text
    assert "Scan ID: abc-123" in text
