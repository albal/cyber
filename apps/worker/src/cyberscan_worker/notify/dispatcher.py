"""Send scan-completion notifications to enabled channels.

v0.2 supports email (SMTP), Slack incoming webhooks, and MS Teams incoming
webhooks. Channels are filtered by `min_severity` against the highest finding
severity in the scan.
"""
from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.mime.text import MIMEText
from email.utils import formatdate

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(slots=True)
class ScanSummary:
    scan_id: str
    asset_name: str
    target_url: str
    counts: dict[str, int]
    new: int
    fixed: int
    top_findings: list[tuple[str, str, float, list[str]]]  # title, sev, risk, cves


def _max_sev(counts: dict[str, int]) -> str:
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev, 0) > 0:
            return sev
    return "info"


def dispatch(db: Session, *, tenant_id: str, summary: ScanSummary) -> int:
    rows = db.execute(
        text(
            """
            SELECT id, kind, target, min_severity::text AS min_severity
              FROM notification_channels
             WHERE tenant_id = :tid AND enabled = TRUE
            """
        ),
        {"tid": tenant_id},
    ).all()

    max_sev = _max_sev(summary.counts)
    sent = 0
    for ch in rows:
        if _SEV_RANK[max_sev] < _SEV_RANK[ch.min_severity]:
            continue
        try:
            if ch.kind == "email":
                _send_email(ch.target, summary)
            elif ch.kind == "slack":
                _post_slack(ch.target, summary)
            elif ch.kind == "teams":
                _post_teams(ch.target, summary)
            else:
                log.warning("unknown channel kind: %s", ch.kind)
                continue
            sent += 1
        except Exception as exc:  # noqa: BLE001
            log.exception("notification dispatch failed kind=%s id=%s err=%s", ch.kind, ch.id, exc)
    return sent


# ---------- formatters -------------------------------------------------------


def _summary_text(s: ScanSummary) -> str:
    counts = ", ".join(f"{k}: {v}" for k, v in s.counts.items() if v)
    lines = [
        f"Scan complete for {s.asset_name} ({s.target_url})",
        f"Findings — {counts or 'none'}",
        f"New: {s.new}  ·  Fixed: {s.fixed}",
    ]
    if s.top_findings:
        lines.append("\nTop findings:")
        for title, sev, risk, cves in s.top_findings[:5]:
            cve_str = (" " + ", ".join(cves)) if cves else ""
            lines.append(f"  • [{sev}] risk={risk:.1f}  {title}{cve_str}")
    lines.append(f"\nScan ID: {s.scan_id}")
    return "\n".join(lines)


# ---------- senders ----------------------------------------------------------


def _send_email(to_addr: str, s: ScanSummary) -> None:
    from cyberscan_worker.config import get_settings  # lazy: keeps formatters import-light

    cfg = get_settings()
    if not cfg.smtp_host:
        log.info("SMTP not configured; skipping email")
        return
    msg = MIMEText(_summary_text(s))
    msg["Subject"] = f"[cyberscan] {_max_sev(s.counts).upper()} findings for {s.asset_name}"
    msg["From"] = cfg.smtp_from
    msg["To"] = to_addr
    msg["Date"] = formatdate(localtime=True)

    with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=15) as server:
        if cfg.smtp_starttls:
            server.starttls()
        if cfg.smtp_user:
            server.login(cfg.smtp_user, cfg.smtp_password)
        server.sendmail(cfg.smtp_from, [to_addr], msg.as_string())


def _post_slack(webhook_url: str, s: ScanSummary) -> None:
    color = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
             "low": "#3b82f6", "info": "#6b7280"}[_max_sev(s.counts)]
    payload = {
        "text": f"Scan complete: {s.asset_name}",
        "attachments": [
            {
                "color": color,
                "title": f"{s.asset_name} — {s.target_url}",
                "text": _summary_text(s),
                "footer": "cyberscan",
            }
        ],
    }
    httpx.post(webhook_url, json=payload, timeout=10).raise_for_status()


def _post_teams(webhook_url: str, s: ScanSummary) -> None:
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"cyberscan: {s.asset_name}",
        "themeColor": {"critical": "ef4444", "high": "f97316", "medium": "eab308",
                       "low": "3b82f6", "info": "6b7280"}[_max_sev(s.counts)],
        "title": f"Scan complete: {s.asset_name}",
        "text": _summary_text(s).replace("\n", "  \n"),
    }
    httpx.post(webhook_url, json=payload, timeout=10).raise_for_status()
