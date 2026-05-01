"""ZAP baseline adapter — passive OWASP scan.

If `zap-baseline.py` is on PATH (provided by the official ZAP container), we
shell out and parse its JSON report. Otherwise we run a lightweight built-in
passive scan that checks security headers + cookie flags so the pipeline still
contributes meaningful findings in dev / minimal images.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx

log = logging.getLogger(__name__)


@dataclass(slots=True)
class PassiveHit:
    title: str
    severity: str  # critical|high|medium|low|info
    description: str | None = None
    remediation: str | None = None
    target: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


def run(url: str, timeout_s: int = 600) -> list[PassiveHit]:
    if shutil.which("zap-baseline.py"):
        return _run_zap(url, timeout_s)
    log.info("ZAP not available — running fallback passive header check on %s", url)
    return _run_fallback(url)


# ---------- ZAP path ---------------------------------------------------------


def _run_zap(url: str, timeout_s: int) -> list[PassiveHit]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        cmd = [
            "zap-baseline.py",
            "-t", url,
            "-J", str(report),
            "-I",  # don't fail on alerts, we collect them
            "-s",  # short scan
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
        except subprocess.TimeoutExpired:
            log.warning("zap-baseline timed out for %s", url)
            return []

        if not report.exists():
            return []
        with report.open() as f:
            data = json.load(f)

    out: list[PassiveHit] = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            sev = (alert.get("riskdesc") or "Informational").split(" ")[0].lower()
            sev = {"informational": "info"}.get(sev, sev)
            cwe = alert.get("cweid")
            cwes = [f"CWE-{cwe}"] if cwe and cwe != "-1" else []
            out.append(
                PassiveHit(
                    title=alert.get("name", "ZAP alert"),
                    severity=sev,
                    description=(alert.get("desc") or "").strip() or None,
                    remediation=(alert.get("solution") or "").strip() or None,
                    target=url,
                    cwe_ids=cwes,
                    references=list(filter(None, (alert.get("reference") or "").split("\n"))),
                )
            )
    return out


# ---------- Fallback passive check (security headers) -----------------------

_REQUIRED_HEADERS = [
    ("Content-Security-Policy", "low",
     "CSP not set — XSS/data-injection mitigations weakened.",
     "Set a Content-Security-Policy header tailored to your app."),
    ("X-Content-Type-Options", "low",
     "X-Content-Type-Options missing — browsers may sniff response types.",
     "Set 'X-Content-Type-Options: nosniff' globally."),
    ("Referrer-Policy", "info",
     "Referrer-Policy missing — referrer leakage to third parties possible.",
     "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter."),
    ("Permissions-Policy", "info",
     "Permissions-Policy missing — browser features not constrained.",
     "Set a Permissions-Policy disabling unused browser features."),
]


def _run_fallback(url: str) -> list[PassiveHit]:
    try:
        r = httpx.get(url, timeout=8.0, follow_redirects=True)
    except httpx.HTTPError as exc:
        log.info("fallback passive check could not reach %s: %s", url, exc)
        return []

    out: list[PassiveHit] = []
    headers = {k.lower(): v for k, v in r.headers.items()}
    for name, sev, desc, fix in _REQUIRED_HEADERS:
        if name.lower() not in headers:
            out.append(
                PassiveHit(
                    title=f"Missing security header: {name}",
                    severity=sev,
                    description=desc,
                    remediation=fix,
                    target=url,
                    cwe_ids=["CWE-693"],
                )
            )

    # Cookie flag checks
    for cookie in r.cookies.jar:
        flags_missing: list[str] = []
        if not cookie.secure:
            flags_missing.append("Secure")
        # Python's cookielib uses `_rest` for HttpOnly
        rest = getattr(cookie, "_rest", {}) or {}
        if "HttpOnly" not in {k.title() for k in rest.keys()}:
            flags_missing.append("HttpOnly")
        if flags_missing:
            out.append(
                PassiveHit(
                    title=f"Cookie '{cookie.name}' missing flags: {', '.join(flags_missing)}",
                    severity="low",
                    description="Session cookies should be Secure + HttpOnly to limit theft via XSS / network sniffing.",
                    remediation="Set Secure and HttpOnly attributes on all session cookies.",
                    target=url,
                    cwe_ids=["CWE-1004"],
                )
            )
    return out
