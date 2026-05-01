"""End-to-end scan pipeline (v0.1: single task, sequential stages).

Stages later split into Celery chord/chain (v0.2). For MVP we keep one
`run_scan` task so progress reporting is straightforward.
"""
from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from urllib.parse import urlparse

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from cyberscan_worker.celery_app import celery_app
from cyberscan_worker.config import get_settings
from cyberscan_worker.db import SessionLocal
from cyberscan_worker.feeds.store import get_cve, is_kev
from cyberscan_worker.recon import httpx_probe, naabu
from cyberscan_worker.risk import RiskInputs, composite_score, dedupe_key, severity_for
from cyberscan_worker.vuln import nuclei

log = logging.getLogger(__name__)


# ---- raw SQL helpers (decoupling worker from backend ORM) -------------------

_UPDATE_SCAN_SQL = text(
    """
    UPDATE scans
       SET status = :status,
           stage = :stage,
           progress = :progress,
           started_at = COALESCE(started_at, :started_at),
           finished_at = :finished_at,
           error = :error,
           summary = CAST(:summary AS json)
     WHERE id = :id
    """
)

_INSERT_FINDING_SQL = text(
    """
    INSERT INTO findings (
        id, scan_id, asset_id, title, template_id, cve_ids, cwe_ids, severity,
        cvss_score, epss_score, is_kev, risk_score, location, matcher_name,
        request, response_excerpt, remediation, "references", compliance_tags,
        diff_status, dedupe_key
    ) VALUES (
        :id, :scan_id, :asset_id, :title, :template_id,
        CAST(:cve_ids AS json), CAST(:cwe_ids AS json), CAST(:severity AS severity),
        :cvss_score, :epss_score, :is_kev, :risk_score, :location, :matcher_name,
        :request, :response_excerpt, :remediation,
        CAST(:references AS json), CAST(:compliance_tags AS json),
        :diff_status, :dedupe_key
    )
    """
)


def _set_state(
    db: Session,
    scan_id: str,
    *,
    status: str,
    stage: str | None,
    progress: int,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    error: str | None = None,
    summary: dict | None = None,
) -> None:
    import json as _json

    db.execute(
        _UPDATE_SCAN_SQL,
        {
            "id": scan_id,
            "status": status,
            "stage": stage,
            "progress": progress,
            "started_at": started_at,
            "finished_at": finished_at,
            "error": error,
            "summary": _json.dumps(summary) if summary is not None else None,
        },
    )
    db.commit()


def _load_asset(db: Session, scan_id: str) -> tuple[str, str, str]:
    row = db.execute(
        text(
            """
            SELECT a.id::text AS asset_id, a.target_url, a.hostname
              FROM scans s JOIN assets a ON a.id = s.asset_id
             WHERE s.id = :id
            """
        ),
        {"id": scan_id},
    ).first()
    if not row:
        raise RuntimeError(f"scan {scan_id} not found")
    return row.asset_id, row.target_url, row.hostname


def _previous_dedupe_keys(db: Session, asset_id: str, current_scan_id: str) -> set[str]:
    rows = db.execute(
        text(
            """
            SELECT DISTINCT f.dedupe_key
              FROM findings f
              JOIN scans s ON s.id = f.scan_id
             WHERE f.asset_id = :asset_id
               AND s.id <> :current
               AND s.status IN ('completed', 'partial')
            """
        ),
        {"asset_id": asset_id, "current": current_scan_id},
    ).all()
    return {r.dedupe_key for r in rows}


# ---- main task --------------------------------------------------------------


@celery_app.task(name="cyberscan_worker.pipeline.run_scan", queue="recon", bind=True)
def run_scan(self, scan_id: str) -> dict:  # type: ignore[no-untyped-def]
    s = get_settings()
    log.info("run_scan start scan_id=%s", scan_id)

    with SessionLocal() as db:
        asset_id, target_url, hostname = _load_asset(db, scan_id)
        _set_state(
            db, scan_id,
            status="running", stage="recon", progress=5,
            started_at=datetime.now(UTC),
        )

        try:
            # Stage 1: port discovery + service fingerprint
            ports = naabu.run(hostname, top_ports="1000", timeout_s=120)
            _set_state(db, scan_id, status="running", stage="recon", progress=20)

            host_port_targets = [f"{p.host}:{p.port}" for p in ports]
            # Always include the original URL host as a fallback target
            services = httpx_probe.run(host_port_targets or [hostname], timeout_s=120)
            if not services:
                # MVP: at minimum probe the asset URL itself
                services = httpx_probe.run([target_url], timeout_s=60)

            _set_state(db, scan_id, status="running", stage="vuln", progress=40)

            # Stage 2: nuclei (sharded)
            urls = [svc.url for svc in services] or [target_url]
            shards = nuclei.shard(urls, s.nuclei_shards)
            all_hits: list[nuclei.NucleiHit] = []
            for i, bucket in enumerate(shards):
                progress = 40 + int(40 * (i + 1) / max(len(shards), 1))
                _set_state(db, scan_id, status="running", stage=f"vuln/shard{i+1}", progress=progress)
                all_hits.extend(nuclei.run(bucket, timeout_s=600))

            _set_state(db, scan_id, status="running", stage="consolidate", progress=85)

            # Stage 3: enrich + score + persist
            prev_keys = _previous_dedupe_keys(db, asset_id, scan_id)
            current_keys: set[str] = set()
            findings_summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            for hit in all_hits:
                cvss = hit.cvss_score
                kev_flag = False
                # Take the highest-severity CVE for scoring
                for cve in hit.cve_ids:
                    cve_row = get_cve(db, cve)
                    if cve_row and cve_row.get("cvss_v3"):
                        if cvss is None or cve_row["cvss_v3"] > cvss:
                            cvss = float(cve_row["cvss_v3"])
                    if is_kev(db, cve):
                        kev_flag = True

                exposure = "internet"  # MVP assumption
                inputs = RiskInputs(
                    cvss=cvss,
                    epss_percentile=None,  # v0.2 adds EPSS
                    is_kev=kev_flag,
                    exposure=exposure,
                    exploit_available="public" if kev_flag else "none",
                )
                score = composite_score(inputs)
                # Honor nuclei's severity if no CVSS at all (template-only finding)
                sev = severity_for(score, is_kev=kev_flag) if cvss is not None or kev_flag else hit.severity
                findings_summary[sev] = findings_summary.get(sev, 0) + 1

                key = dedupe_key(
                    asset_id=asset_id,
                    template_id=hit.template_id,
                    cve_ids=hit.cve_ids,
                    location=hit.matched_at,
                )
                current_keys.add(key)
                diff = "new" if key not in prev_keys else "unchanged"

                import json as _json
                db.execute(
                    _INSERT_FINDING_SQL,
                    {
                        "id": str(uuid.uuid4()),
                        "scan_id": scan_id,
                        "asset_id": asset_id,
                        "title": hit.name,
                        "template_id": hit.template_id,
                        "cve_ids": _json.dumps(hit.cve_ids),
                        "cwe_ids": _json.dumps(hit.cwe_ids),
                        "severity": sev,
                        "cvss_score": cvss,
                        "epss_score": None,
                        "is_kev": kev_flag,
                        "risk_score": round(score, 2),
                        "location": hit.matched_at,
                        "matcher_name": hit.matcher_name,
                        "request": hit.request,
                        "response_excerpt": hit.response_excerpt,
                        "remediation": hit.remediation,
                        "references": _json.dumps(hit.references),
                        "compliance_tags": _json.dumps(_compliance_tags(hit.cwe_ids)),
                        "diff_status": diff,
                        "dedupe_key": key,
                    },
                )
            db.commit()

            # Synthesize "fixed" findings for items present last scan but missing now
            for key in (prev_keys - current_keys):
                # Lightweight marker row: title only; UI shows them as fixed.
                import json as _json
                db.execute(
                    _INSERT_FINDING_SQL,
                    {
                        "id": str(uuid.uuid4()),
                        "scan_id": scan_id,
                        "asset_id": asset_id,
                        "title": "(previously detected, no longer present)",
                        "template_id": None,
                        "cve_ids": _json.dumps([]),
                        "cwe_ids": _json.dumps([]),
                        "severity": "info",
                        "cvss_score": None,
                        "epss_score": None,
                        "is_kev": False,
                        "risk_score": 0.0,
                        "location": None,
                        "matcher_name": None,
                        "request": None,
                        "response_excerpt": None,
                        "remediation": None,
                        "references": _json.dumps([]),
                        "compliance_tags": _json.dumps([]),
                        "diff_status": "fixed",
                        "dedupe_key": key,
                    },
                )
            db.commit()

            summary = {
                "ports_open": len(ports),
                "services_seen": len(services),
                "findings": findings_summary,
                "new": sum(1 for k in current_keys if k not in prev_keys),
                "fixed": len(prev_keys - current_keys),
                "unchanged": sum(1 for k in current_keys if k in prev_keys),
            }
            _set_state(
                db, scan_id,
                status="completed", stage="done", progress=100,
                finished_at=datetime.now(UTC), summary=summary,
            )
            log.info("run_scan done scan_id=%s summary=%s", scan_id, summary)
            return summary

        except Exception as exc:  # noqa: BLE001
            log.exception("scan failed: %s", exc)
            _set_state(
                db, scan_id,
                status="failed", stage="error", progress=100,
                finished_at=datetime.now(UTC), error=str(exc),
            )
            raise


# ---- compliance tagging (CWE -> framework chips) ----------------------------

# Trimmed v0.1 mapping; expanded set lives in packages/compliance-map/data.
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
}


def _compliance_tags(cwe_ids: list[str]) -> list[str]:
    tags: list[str] = []
    for c in cwe_ids:
        c_up = c.upper()
        if c_up in _OWASP_BY_CWE:
            tags.append(_OWASP_BY_CWE[c_up])
    return tags
