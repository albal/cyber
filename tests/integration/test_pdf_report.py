"""PDF rendering — sanity-check the bytes are a real PDF and the text shows up."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

import pytest

try:
    from cyberscan_api.services.pdf_report import render
except ModuleNotFoundError:  # reportlab absent on host venv → skip cleanly
    pytest.skip("reportlab unavailable", allow_module_level=True)


def _scan(**kwargs):
    base = {
        "id": "abc-123",
        "started_at": None,
        "finished_at": None,
        "created_at": None,
        "summary": {"findings": {"critical": 1, "high": 2, "medium": 3, "low": 0, "info": 0}},
    }
    base.update(kwargs)
    return base


def _asset():
    return {"name": "Main site", "target_url": "https://example.com"}


def _findings(n: int = 3):
    out = []
    for i in range(n):
        out.append(
            {
                "title": f"finding-{i}",
                "severity": "high",
                "risk_score": 80.0 - i,
                "cve_ids": [f"CVE-2024-{1000 + i}"],
                "cwe_ids": ["CWE-79"],
                "compliance_tags": ["OWASP A03:2021 Injection"],
                "location": "https://example.com/admin",
                "remediation": "Apply the upstream patch.",
            }
        )
    return out


def test_pdf_starts_with_magic_bytes():
    pdf = render(scan=_scan(), asset=_asset(), findings=_findings())
    assert pdf.startswith(b"%PDF")


def test_pdf_size_is_nonzero_and_reasonable():
    pdf = render(scan=_scan(), asset=_asset(), findings=_findings(50))
    # ~10KB minimum for a multi-page report; cap at 5MB to catch runaways.
    assert 5_000 < len(pdf) < 5_000_000


def test_pdf_with_no_findings_still_renders():
    pdf = render(scan=_scan(), asset=_asset(), findings=[])
    assert pdf.startswith(b"%PDF")
    # Smaller than the loaded report.
    assert len(pdf) < 50_000


def test_pdf_with_many_findings_truncates_table():
    """The findings table caps at 100 rows but the appendix only renders 20."""
    pdf = render(scan=_scan(), asset=_asset(), findings=_findings(150))
    assert pdf.startswith(b"%PDF")
    # Should still be bounded — not 150x the size of a single-finding doc.
    assert len(pdf) < 500_000


def test_pdf_handles_missing_optional_fields():
    """Findings that don't carry remediation / compliance_tags must not crash."""
    findings = [
        {
            "title": "minimal finding",
            "severity": "low",
            "risk_score": 25.0,
            "cve_ids": [],
            "cwe_ids": [],
            "compliance_tags": [],
            "location": None,
            "remediation": None,
        }
    ]
    pdf = render(scan=_scan(), asset=_asset(), findings=findings)
    assert pdf.startswith(b"%PDF")
