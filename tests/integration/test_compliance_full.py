"""Comprehensive compliance-tag mapping coverage."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cyberscan_worker.compliance import compliance_tags  # noqa: E402


# ---------- OWASP Top 10 ------------------------------------------------------


@pytest.mark.parametrize(
    "cwe,expected_owasp",
    [
        ("CWE-79", "OWASP A03"),
        ("CWE-89", "OWASP A03"),
        ("CWE-94", "OWASP A03"),
        ("CWE-352", "OWASP A01"),
        ("CWE-285", "OWASP A01"),
        ("CWE-22", "OWASP A01"),
        ("CWE-287", "OWASP A07"),
        ("CWE-200", "OWASP A04"),
        ("CWE-918", "OWASP A10"),
        ("CWE-502", "OWASP A08"),
        ("CWE-310", "OWASP A02"),
        ("CWE-319", "OWASP A02"),
        ("CWE-327", "OWASP A02"),
        ("CWE-693", "OWASP A05"),
        ("CWE-1004", "OWASP A05"),
    ],
)
def test_each_known_cwe_maps_to_expected_owasp_category(cwe: str, expected_owasp: str):
    tags = compliance_tags([cwe])
    assert any(expected_owasp in t for t in tags)


# ---------- PCI ---------------------------------------------------------------


@pytest.mark.parametrize(
    "cwe,expected_pci",
    [
        ("CWE-79", "PCI-DSS 6.5.7"),
        ("CWE-89", "PCI-DSS 6.5.1"),
        ("CWE-310", "PCI-DSS 4.2.1"),
        ("CWE-319", "PCI-DSS 4.2.1"),
        ("CWE-327", "PCI-DSS 4.2.1"),
    ],
)
def test_pci_mapping(cwe: str, expected_pci: str):
    tags = compliance_tags([cwe])
    assert expected_pci in tags


# ---------- NIST 800-53 -------------------------------------------------------


@pytest.mark.parametrize(
    "cwe,expected_nist",
    [
        ("CWE-310", "NIST SC-13"),
        ("CWE-319", "NIST SC-8"),
        ("CWE-327", "NIST SC-13"),
        ("CWE-287", "NIST IA-2"),
        ("CWE-200", "NIST SC-28"),
    ],
)
def test_nist_mapping(cwe: str, expected_nist: str):
    tags = compliance_tags([cwe])
    assert expected_nist in tags


# ---------- general behavior --------------------------------------------------


def test_unknown_cwe_returns_empty():
    assert compliance_tags(["CWE-99999"]) == []


def test_empty_input_returns_empty():
    assert compliance_tags([]) == []


def test_case_insensitive_input():
    tags_upper = compliance_tags(["CWE-79"])
    tags_lower = compliance_tags(["cwe-79"])
    tags_mixed = compliance_tags(["Cwe-79"])
    assert tags_upper == tags_lower == tags_mixed


def test_dedup_preserves_order():
    tags = compliance_tags(["CWE-310", "CWE-319", "CWE-327"])
    # OWASP A02 should appear only once even though all three CWEs map to it
    assert sum("OWASP A02" in t for t in tags) == 1
    # First appearance must come from the first input CWE
    assert tags.index("OWASP A02:2021 Cryptographic Failures") < tags.index("PCI-DSS 4.2.1")


def test_xss_yields_owasp_a03_and_pci_657():
    tags = compliance_tags(["CWE-79"])
    assert "OWASP A03:2021 Injection" in tags
    assert "PCI-DSS 6.5.7" in tags


def test_sqli_yields_owasp_a03_and_pci_651():
    tags = compliance_tags(["CWE-89"])
    assert "OWASP A03:2021 Injection" in tags
    assert "PCI-DSS 6.5.1" in tags


def test_multi_cwe_input_merges_unique_frameworks():
    tags = compliance_tags(["CWE-79", "CWE-89", "CWE-918"])
    # 3 OWASP categories: A03 (twice), A10 (once) -> A03 dedup'd to one
    assert sum(t.startswith("OWASP A03") for t in tags) == 1
    assert sum(t.startswith("OWASP A10") for t in tags) == 1
