"""Compliance tag mapping smoke test."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cyberscan_worker.compliance import compliance_tags as _compliance_tags  # noqa: E402


def test_xss_maps_to_owasp_a03():
    tags = _compliance_tags(["CWE-79"])
    assert any("OWASP A03" in t for t in tags)
    assert any("PCI-DSS" in t for t in tags)


def test_weak_tls_maps_to_crypto_failures_and_pci():
    tags = _compliance_tags(["CWE-327"])
    assert any("OWASP A02" in t for t in tags)
    assert any("PCI-DSS 4.2" in t for t in tags)
    assert any("NIST" in t for t in tags)


def test_unknown_cwe_yields_no_tags():
    assert _compliance_tags(["CWE-99999"]) == []


def test_dedup_when_multiple_cwes_share_a_framework():
    tags = _compliance_tags(["CWE-310", "CWE-319", "CWE-327"])
    # All three map to OWASP A02 — should appear only once
    assert sum("OWASP A02" in t for t in tags) == 1
