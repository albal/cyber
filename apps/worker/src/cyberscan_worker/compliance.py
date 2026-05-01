"""CWE -> compliance-framework tag mapping (OWASP / PCI / NIST).

Pure-python; no DB, no celery. Imported by the pipeline and by tests.
"""
from __future__ import annotations

_OWASP_BY_CWE = {
    "CWE-79": "OWASP A03:2021 Injection",
    "CWE-89": "OWASP A03:2021 Injection",
    "CWE-94": "OWASP A03:2021 Injection",
    "CWE-352": "OWASP A01:2021 Broken Access Control",
    "CWE-285": "OWASP A01:2021 Broken Access Control",
    "CWE-287": "OWASP A07:2021 Identification & Authentication Failures",
    "CWE-200": "OWASP A04:2021 Insecure Design",
    "CWE-22": "OWASP A01:2021 Broken Access Control",
    "CWE-918": "OWASP A10:2021 SSRF",
    "CWE-502": "OWASP A08:2021 Software & Data Integrity",
    "CWE-310": "OWASP A02:2021 Cryptographic Failures",
    "CWE-319": "OWASP A02:2021 Cryptographic Failures",
    "CWE-327": "OWASP A02:2021 Cryptographic Failures",
    "CWE-693": "OWASP A05:2021 Security Misconfiguration",
    "CWE-1004": "OWASP A05:2021 Security Misconfiguration",
}

_PCI_BY_CWE = {
    "CWE-79": "PCI-DSS 6.5.7",
    "CWE-89": "PCI-DSS 6.5.1",
    "CWE-310": "PCI-DSS 4.2.1",
    "CWE-319": "PCI-DSS 4.2.1",
    "CWE-327": "PCI-DSS 4.2.1",
}

_NIST_BY_CWE = {
    "CWE-310": "NIST SC-13",
    "CWE-319": "NIST SC-8",
    "CWE-327": "NIST SC-13",
    "CWE-287": "NIST IA-2",
    "CWE-200": "NIST SC-28",
}


def compliance_tags(cwe_ids: list[str]) -> list[str]:
    """Return de-duplicated compliance tags (preserving insertion order)."""
    tags: list[str] = []
    for c in cwe_ids:
        c_up = c.upper()
        if c_up in _OWASP_BY_CWE:
            tags.append(_OWASP_BY_CWE[c_up])
        if c_up in _PCI_BY_CWE:
            tags.append(_PCI_BY_CWE[c_up])
        if c_up in _NIST_BY_CWE:
            tags.append(_NIST_BY_CWE[c_up])
    seen: set[str] = set()
    out: list[str] = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out
