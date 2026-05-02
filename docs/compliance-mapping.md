# Compliance mapping

How findings are tagged against industry frameworks. Tags appear as
filterable chips in the scan-detail UI and in CSV / JSON / PDF exports.

The mapping is **CWE-driven**: each finding's CWE list is run through four
tables and the union is stored on the row. The tables live in
[`apps/worker/src/cyberscan_worker/compliance.py`](../apps/worker/src/cyberscan_worker/compliance.py).

## Frameworks supported (v1.0)

| Framework | Identifier prefix | Source of truth |
| -- | -- | -- |
| OWASP Top 10:2021 | `OWASP A01:2021` … `A10:2021` | https://owasp.org/Top10/ |
| PCI-DSS v4.0 | `PCI-DSS 4.x` / `6.5.x` | https://docs-prv.pcisecuritystandards.org |
| NIST SP 800-53 r5 | `NIST <family>-<num>` (e.g. `SC-13`) | https://nvd.nist.gov/800-53 |
| CIS Controls v8 | `CIS <ig>.<num>` | https://www.cisecurity.org/controls/v8 |

## CWE → tags

| CWE | OWASP | PCI-DSS | NIST 800-53 | CIS v8 |
| -- | -- | -- | -- | -- |
| CWE-22  Path Traversal | A01 Broken Access Control | — | — | 6.1 |
| CWE-79  XSS | A03 Injection | 6.5.7 | — | 16.10 |
| CWE-89  SQL Injection | A03 Injection | 6.5.1 | — | 16.10 |
| CWE-94  Code Injection | A03 Injection | — | — | 16.10 |
| CWE-200 Information Disclosure | A04 Insecure Design | — | SC-28 | 3.1 |
| CWE-285 Improper Authorization | A01 Broken Access Control | — | — | 6.1 |
| CWE-287 Auth Bypass | A07 Identification & Auth Failures | — | IA-2 | 6.5 |
| CWE-310 Crypto Issues | A02 Cryptographic Failures | 4.2.1 | SC-13 | 3.10 |
| CWE-319 Cleartext Transmission | A02 Cryptographic Failures | 4.2.1 | SC-8 | 3.10 |
| CWE-327 Broken / Risky Crypto | A02 Cryptographic Failures | 4.2.1 | SC-13 | 3.10 |
| CWE-352 CSRF | A01 Broken Access Control | — | — | 6.1 |
| CWE-502 Deserialization | A08 Software & Data Integrity | — | — | 16.10 |
| CWE-693 Protection Mechanism Failure | A05 Security Misconfiguration | — | — | 4.1 |
| CWE-918 SSRF | A10 SSRF | — | — | 13.10 |
| CWE-1004 Insecure Cookie | A05 Security Misconfiguration | — | — | 4.1 |

If a finding has no CWE (some Nuclei templates don't classify, especially
generic exposed-panel templates), no compliance tags are emitted — those
findings still ship with their severity / CVSS / risk score.

## Filtering in the UI

The scan-detail page renders the union of all compliance tags as a row of
chips above the findings table. Clicking a chip filters the table down to
findings that include that tag. The same filter applies to the inline tag
buttons rendered on each finding row.

## Extending the mapping

1. Add the CWE → tag pair to the appropriate table in
   [`compliance.py`](../apps/worker/src/cyberscan_worker/compliance.py).
2. Add a parametrize case to
   [`tests/integration/test_compliance_full.py`](../tests/integration/test_compliance_full.py)
   so a regression in the mapping fails CI.
3. Add a row to the table above so reviewers can see what's covered without
   reading code.

## Limitations

- These are **CWE-level** mappings, not finding-text-level. Two findings
  with the same CWE always get the same tags.
- We don't (yet) annotate compensating controls — a finding tagged
  `PCI-DSS 6.5.1` is the *control reference*, not an assertion that the
  customer has failed PCI.
- Mappings reflect each framework's most common interpretation. For
  audit-grade evidence, ship the raw CWE list (in the JSON / CSV export)
  alongside the tag list and let the auditor map it themselves.
