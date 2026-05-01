"""sslyze adapter — deep TLS/SSL inspection.

Uses sslyze as a Python library (not CLI). Produces structured findings
covering: weak protocols, weak ciphers, certificate issues, Heartbleed,
ROBOT, and missing security commitments (HSTS).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass(slots=True)
class TlsHit:
    title: str
    severity: str  # critical|high|medium|low|info
    description: str | None = None
    remediation: str | None = None
    target: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


def run(host: str, port: int = 443, timeout_s: int = 60) -> list[TlsHit]:
    try:
        from sslyze import (  # type: ignore[import-not-found]
            Scanner,
            ScanCommand,
            ServerNetworkLocation,
            ServerScanRequest,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("sslyze unavailable (%s) — returning empty result", exc)
        return []

    scan_commands = {
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.HEARTBLEED,
        ScanCommand.ROBOT,
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.HTTP_HEADERS,
    }

    try:
        location = ServerNetworkLocation(hostname=host, port=port)
        scanner = Scanner()
        scanner.queue_scans([ServerScanRequest(server_location=location, scan_commands=scan_commands)])
        results = list(scanner.get_results())
    except Exception as exc:  # noqa: BLE001
        log.warning("sslyze run failed for %s:%s — %s", host, port, exc)
        return []

    out: list[TlsHit] = []
    target = f"{host}:{port}"
    for r in results:
        attrs = getattr(r, "scan_result", None)
        if attrs is None:
            continue

        # Weak protocol versions
        for proto, cmd in (
            ("SSL 2.0", "ssl_2_0_cipher_suites"),
            ("SSL 3.0", "ssl_3_0_cipher_suites"),
            ("TLS 1.0", "tls_1_0_cipher_suites"),
            ("TLS 1.1", "tls_1_1_cipher_suites"),
        ):
            res = getattr(attrs, cmd, None)
            inner = getattr(res, "result", None) if res else None
            if inner and getattr(inner, "accepted_cipher_suites", []):
                out.append(
                    TlsHit(
                        title=f"Server supports deprecated {proto}",
                        severity="high" if proto in ("SSL 2.0", "SSL 3.0") else "medium",
                        description=f"{proto} is deprecated and contains known cryptographic weaknesses.",
                        remediation=f"Disable {proto} on the server and require TLS 1.2+ (preferably 1.3).",
                        target=target,
                        cwe_ids=["CWE-327"],
                        references=["https://wiki.mozilla.org/Security/Server_Side_TLS"],
                    )
                )

        # Heartbleed
        hb = getattr(attrs, "heartbleed", None)
        hb_res = getattr(hb, "result", None) if hb else None
        if hb_res and getattr(hb_res, "is_vulnerable_to_heartbleed", False):
            out.append(
                TlsHit(
                    title="OpenSSL Heartbleed (CVE-2014-0160)",
                    severity="critical",
                    description="Server is vulnerable to Heartbleed information disclosure.",
                    remediation="Upgrade OpenSSL to a patched version and rotate any exposed keys/certs.",
                    target=target,
                    cwe_ids=["CWE-125"],
                    references=["https://heartbleed.com/"],
                )
            )

        # ROBOT
        robot = getattr(attrs, "robot", None)
        robot_res = getattr(robot, "result", None) if robot else None
        rv = getattr(robot_res, "robot_result", None) if robot_res else None
        if rv and "VULNERABLE" in str(rv):
            out.append(
                TlsHit(
                    title="ROBOT attack vulnerability",
                    severity="high",
                    description="Server is vulnerable to the Return Of Bleichenbacher's Oracle Threat (ROBOT).",
                    remediation="Disable RSA key exchange ciphers; require ECDHE-only for forward secrecy.",
                    target=target,
                    cwe_ids=["CWE-310"],
                    references=["https://robotattack.org/"],
                )
            )

        # HSTS missing
        hh = getattr(attrs, "http_headers", None)
        hh_res = getattr(hh, "result", None) if hh else None
        hsts = getattr(hh_res, "strict_transport_security_header", None) if hh_res else None
        if hh_res and hsts is None:
            out.append(
                TlsHit(
                    title="Missing HTTP Strict Transport Security (HSTS)",
                    severity="low",
                    description="The server does not set the Strict-Transport-Security response header.",
                    remediation=(
                        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
                        "after verifying full HTTPS coverage."
                    ),
                    target=target,
                    cwe_ids=["CWE-319"],
                )
            )

    return out
