"""sslyze CLI adapter — deep TLS/SSL inspection.

Runs sslyze as a separate process and parses its JSON output. Produces
structured findings covering: weak protocols, weak ciphers, certificate
issues, Heartbleed, ROBOT, and missing security commitments (HSTS).
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
    binary = os.environ.get("SSLYZE_BIN", "sslyze")
    if not _command_available(binary):
        log.warning("sslyze CLI not on PATH — returning empty result")
        return []

    target = f"{host}:{port}"
    with tempfile.NamedTemporaryFile(suffix=".json") as fp:
        cmd = [
            binary,
            "--json_out",
            fp.name,
            "--quiet",
            "--sslv2",
            "--sslv3",
            "--tlsv1",
            "--tlsv1_1",
            "--heartbleed",
            "--robot",
            "--certinfo",
            "--http_headers",
            target,
        ]

        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired:
            log.warning("sslyze timed out for %s", target)
            return []
        except OSError as exc:
            log.warning("sslyze run failed for %s — %s", target, exc)
            return []

        if proc.returncode != 0:
            stderr = proc.stderr.strip() or proc.stdout.strip()
            log.warning("sslyze run failed for %s with exit %s: %s", target, proc.returncode, stderr)
            return []

        try:
            raw = Path(fp.name).read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("sslyze JSON output unavailable for %s — %s", target, exc)
            return []

    return parse(raw, default_target=target)


def parse(raw: str, default_target: str = "") -> list[TlsHit]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        log.warning("sslyze returned malformed JSON (%s)", exc)
        return []

    results = payload.get("server_scan_results") or []
    out: list[TlsHit] = []
    for r in results:
        scan_result = r.get("scan_result") or {}
        if not isinstance(scan_result, dict):
            continue
        target = _target_from_result(r) or default_target

        # Weak protocol versions
        for proto, cmd in (
            ("SSL 2.0", "ssl_2_0_cipher_suites"),
            ("SSL 3.0", "ssl_3_0_cipher_suites"),
            ("TLS 1.0", "tls_1_0_cipher_suites"),
            ("TLS 1.1", "tls_1_1_cipher_suites"),
        ):
            accepted = _get(scan_result, cmd, "result", "accepted_cipher_suites")
            if accepted:
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
        if _get(scan_result, "heartbleed", "result", "is_vulnerable_to_heartbleed"):
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
        rv = _get(scan_result, "robot", "result", "robot_result")
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
        http_headers = _get(scan_result, "http_headers", "result")
        hsts = _get(scan_result, "http_headers", "result", "strict_transport_security_header")
        if http_headers and hsts is None:
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


def _command_available(binary: str) -> bool:
    if os.sep in binary:
        return Path(binary).is_file()
    return shutil.which(binary) is not None


def _get(obj: dict[str, Any], *keys: str) -> Any:
    cur: Any = obj
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _target_from_result(result: dict[str, Any]) -> str:
    location = result.get("server_location") or result.get("network_location") or {}
    if not isinstance(location, dict):
        return ""

    hostname = location.get("hostname")
    port = location.get("port")
    return f"{hostname}:{port}" if hostname and port else ""
