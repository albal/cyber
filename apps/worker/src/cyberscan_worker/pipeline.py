"""End-to-end scan pipeline.

v0.1: single task, recon -> nuclei -> consolidate.
v0.2: adds TLS (sslyze) + passive (ZAP/header fallback) stages run alongside
      vuln, EPSS enrichment, tenant-aware persistence, and notifications.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from urllib.parse import urlparse

from sqlalchemy import text
from sqlalchemy.orm import Session

from cyberscan_worker.celery_app import celery_app
from cyberscan_worker.compliance import compliance_tags as _compliance_tags
from cyberscan_worker.config import get_settings
from cyberscan_worker.db import SessionLocal
from cyberscan_worker.feeds import epss
from cyberscan_worker.feeds.store import get_cve, is_kev
from cyberscan_worker.notify.dispatcher import ScanSummary, dispatch
from cyberscan_worker.passive import zap_baseline
from cyberscan_worker.recon import httpx_probe, katana, naabu, subfinder
from cyberscan_worker.risk import RiskInputs, composite_score, dedupe_key, severity_for
from cyberscan_worker.tls import sslyze_runner
from cyberscan_worker.vuln import nuclei

log = logging.getLogger(__name__)

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
        id, tenant_id, scan_id, asset_id, title, template_id, cve_ids, cwe_ids, severity,
        cvss_score, epss_score, is_kev, risk_score, location, matcher_name,
        request, response_excerpt, remediation, "references", compliance_tags,
        diff_status, dedupe_key, source
    ) VALUES (
        :id, :tenant_id, :scan_id, :asset_id, :title, :template_id,
        CAST(:cve_ids AS json), CAST(:cwe_ids AS json), CAST(:severity AS severity),
        :cvss_score, :epss_score, :is_kev, :risk_score, :location, :matcher_name,
        :request, :response_excerpt, :remediation,
        CAST(:references AS json), CAST(:compliance_tags AS json),
        :diff_status, :dedupe_key, :source
    )
    """
)


def _set_tenant(db: Session, tenant_id: str) -> None:
    """Pin the per-session GUC so RLS policies allow tenant-scoped reads/writes.

    Postgres SET doesn't accept bind parameters; set_config('...', value, true)
    is the parameter-friendly equivalent of SET LOCAL.
    """
    db.execute(
        text("SELECT set_config('app.tenant_id', :tid, true)"),
        {"tid": tenant_id or ""},
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
            "summary": json.dumps(summary) if summary is not None else None,
        },
    )
    db.commit()


class ScanCancelled(Exception):
    """Raised between stages when the scans row has been flipped to 'cancelled'."""


def _load_scan_meta(db: Session, scan_id: str):
    """Returns a 9-tuple: tenant_id, asset_id, asset_name, target_url,
    hostname, cred_kind, cred_ciphertext, enumerate_subdomains, current_status."""
    row = db.execute(
        text(
            """
            SELECT s.tenant_id::text AS tenant_id,
                   s.status::text AS status,
                   a.id::text AS asset_id,
                   a.name AS asset_name,
                   a.target_url,
                   a.hostname,
                   a.enumerate_subdomains,
                   c.kind AS cred_kind,
                   c.secret_ciphertext AS cred_ciphertext
              FROM scans s
              JOIN assets a ON a.id = s.asset_id
              LEFT JOIN asset_credentials c ON c.asset_id = a.id
             WHERE s.id = :id
            """
        ),
        {"id": scan_id},
    ).first()
    if not row:
        raise RuntimeError(f"scan {scan_id} not found")
    return (
        row.tenant_id,
        row.asset_id,
        row.asset_name,
        row.target_url,
        row.hostname,
        row.cred_kind,
        row.cred_ciphertext,
        bool(row.enumerate_subdomains),
        row.status,
    )


def _check_cancelled(db: Session, scan_id: str) -> None:
    """Re-read scan status. If a user has flipped it to 'cancelled', bail out
    by raising ScanCancelled — the outer task handler marks the scan and
    finishes cleanly without trying to set status back to 'failed'."""
    row = db.execute(
        text("SELECT status::text FROM scans WHERE id = :id"), {"id": scan_id}
    ).first()
    if row and row.status == "cancelled":
        raise ScanCancelled()


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
def run_scan(  # type: ignore[no-untyped-def]
    self, scan_id: str, tenant_id: str | None = None, intrusive: bool = False
) -> dict:
    s = get_settings()
    log.info("run_scan start scan_id=%s tenant_id=%s intrusive=%s", scan_id, tenant_id, intrusive)

    with SessionLocal() as db:
        # First load happens with admin GUC so we can read scans across tenants.
        _set_tenant(db, "")
        (
            meta_tenant,
            asset_id,
            asset_name,
            target_url,
            hostname,
            cred_kind,
            cred_ciphertext,
            enumerate_subdomains,
            current_status,
        ) = _load_scan_meta(db, scan_id)
        tid = tenant_id or meta_tenant

        # The user may have already cancelled before the worker picked up.
        if current_status == "cancelled":
            log.info("scan %s was cancelled before recon started", scan_id)
            return {"cancelled": True}

        # Decrypt asset credentials (if any) into ScannerAuth. Decryption
        # failures are logged and treated as "no auth" — never fatal.
        from cyberscan_worker.auth.credentials import load_for_asset

        scanner_auth = load_for_asset(
            ciphertext=cred_ciphertext,
            kind=cred_kind,
            secret_key=get_settings().api_secret_key,
        )
        if not scanner_auth.is_empty():
            log.info("scan %s: using stored %s credentials for authenticated scan", scan_id, cred_kind)
        _set_tenant(db, tid)

        _set_state(
            db, scan_id,
            status="running", stage="recon", progress=5,
            started_at=datetime.now(UTC),
        )

        try:
            # Stage 0: subdomain enumeration (opt-in per asset). Discovered
            # subdomains are added as additional crawl seeds for the next stage.
            subdomains: list[str] = [hostname]
            if enumerate_subdomains:
                _set_state(db, scan_id, status="running", stage="subfinder", progress=4)
                _check_cancelled(db, scan_id)
                subdomains = subfinder.run(hostname, timeout_s=60)
                log.info("subfinder: discovered %d subdomain(s) for %s", len(subdomains), hostname)

            # Stage 1: port discovery + service fingerprint
            _check_cancelled(db, scan_id)
            ports = naabu.run(hostname, top_ports="1000", timeout_s=120)
            _set_state(db, scan_id, status="running", stage="recon", progress=15)
            _check_cancelled(db, scan_id)

            host_port_targets = [f"{p.host}:{p.port}" for p in ports]
            httpx_targets = host_port_targets or list(subdomains)
            services = httpx_probe.run(httpx_targets, timeout_s=120)
            if not services:
                services = httpx_probe.run([target_url], timeout_s=60)

            # Stage 1b: crawl. Without this Nuclei only ever hits the homepage,
            # which on SPAs (Angular/React) misses every API endpoint. Katana
            # walks links, parses JS bundles + source maps, and follows
            # known-files (robots.txt, sitemap.xml).
            _check_cancelled(db, scan_id)
            _set_state(db, scan_id, status="running", stage="crawl", progress=22)
            crawl_seeds = [svc.url for svc in services if svc.url.startswith("http")] or [target_url]
            # When subdomain enum ran, also seed the crawler with each discovered host.
            if enumerate_subdomains and len(subdomains) > 1:
                scheme = "https://" if any(svc.tls for svc in services) else "http://"
                for sub in subdomains:
                    seed = f"{scheme}{sub}"
                    if seed not in crawl_seeds:
                        crawl_seeds.append(seed)
            depth = s.crawl_depth_intrusive if intrusive else s.crawl_depth
            crawled = katana.run(
                crawl_seeds,
                depth=depth,
                max_urls=s.crawl_max_urls,
                timeout_s=s.crawl_timeout_s,
                headers=scanner_auth.headers or None,
                cookie_header=scanner_auth.cookie_header,
            )
            log.info("crawl: %d url(s) discovered (seeds=%d)", len(crawled), len(crawl_seeds))

            _check_cancelled(db, scan_id)
            _set_state(db, scan_id, status="running", stage="vuln", progress=30)

            # Stage 2a: nuclei (sharded). Default tag set covers CVEs, exposures,
            # misconfigs, default logins, exposed tokens / panels, JS-file analysis.
            # Intrusive mode adds -as (automatic scan: enables fuzz / brute / dast).
            urls = [c.url for c in crawled] or [target_url]
            shards = nuclei.shard(urls, s.nuclei_shards)
            all_hits: list[nuclei.NucleiHit] = []
            severities = ("critical", "high", "medium", "low", "info")
            if intrusive:
                # -as enables the full template set (fuzz, intrusive, dast).
                extra_args = ["-as"]
                tags: tuple[str, ...] = ()  # let -as drive selection
            else:
                extra_args = None
                tags = (
                    "cve", "exposure", "misconfig", "tech", "exposed-panel",
                    "default-login", "exposed-tokens", "js", "config",
                )
            for i, bucket in enumerate(shards):
                progress = 30 + int(30 * (i + 1) / max(len(shards), 1))
                _set_state(db, scan_id, status="running", stage=f"vuln/shard{i+1}", progress=progress)
                all_hits.extend(
                    nuclei.run(
                        bucket,
                        severities=severities,
                        tags=tags,
                        extra_args=extra_args,
                        timeout_s=900 if intrusive else 600,
                        headers=scanner_auth.headers or None,
                        cookie_header=scanner_auth.cookie_header,
                    )
                )

            # Stage 2b: TLS deep inspection on each TLS endpoint
            _check_cancelled(db, scan_id)
            _set_state(db, scan_id, status="running", stage="tls", progress=70)
            tls_hits: list[sslyze_runner.TlsHit] = []
            tls_targets = {(p.host, p.port) for p in ports if p.port in (443, 8443)} or {(hostname, 443)}
            for host, port in tls_targets:
                tls_hits.extend(sslyze_runner.run(host, port=port, timeout_s=60))

            # Stage 2c: passive (ZAP baseline / fallback header check)
            _check_cancelled(db, scan_id)
            _set_state(db, scan_id, status="running", stage="passive", progress=80)
            passive_hits: list[zap_baseline.PassiveHit] = []
            passive_targets = list({svc.url for svc in services if svc.url.startswith("http")})
            if not passive_targets:
                passive_targets = [target_url]
            for url in passive_targets[:3]:  # cap fan-out for the 15-min SLA
                passive_hits.extend(
                    zap_baseline.run(url, timeout_s=600 if intrusive else 300, intrusive=intrusive)
                )

            _check_cancelled(db, scan_id)
            _set_state(db, scan_id, status="running", stage="consolidate", progress=90)

            # Stage 3: enrich + score + persist
            prev_keys = _previous_dedupe_keys(db, asset_id, scan_id)
            current_keys: set[str] = set()
            findings_summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            top: list[tuple[str, str, float, list[str]]] = []

            def _persist(
                *, source: str, title: str, sev: str, risk: float,
                template_id: str | None, cve_ids: list[str], cwe_ids: list[str],
                cvss_score: float | None, epss_pct: float | None, is_kev_flag: bool,
                location: str | None, matcher_name: str | None,
                request: str | None, response_excerpt: str | None,
                remediation: str | None, references: list[str],
                compliance_tags: list[str],
            ) -> None:
                key = dedupe_key(
                    asset_id=asset_id, template_id=template_id,
                    cve_ids=cve_ids, location=location,
                )
                current_keys.add(key)
                diff = "new" if key not in prev_keys else "unchanged"
                findings_summary[sev] = findings_summary.get(sev, 0) + 1
                top.append((title, sev, risk, cve_ids))
                db.execute(
                    _INSERT_FINDING_SQL,
                    {
                        "id": str(uuid.uuid4()),
                        "tenant_id": tid,
                        "scan_id": scan_id,
                        "asset_id": asset_id,
                        "title": title,
                        "template_id": template_id,
                        "cve_ids": json.dumps(cve_ids),
                        "cwe_ids": json.dumps(cwe_ids),
                        "severity": sev,
                        "cvss_score": cvss_score,
                        "epss_score": epss_pct,
                        "is_kev": is_kev_flag,
                        "risk_score": round(risk, 2),
                        "location": location,
                        "matcher_name": matcher_name,
                        "request": request,
                        "response_excerpt": response_excerpt,
                        "remediation": remediation,
                        "references": json.dumps(references),
                        "compliance_tags": json.dumps(compliance_tags),
                        "diff_status": diff,
                        "dedupe_key": key,
                        "source": source,
                    },
                )

            # Nuclei findings
            for hit in all_hits:
                cvss = hit.cvss_score
                kev_flag = False
                epss_pct: float | None = None
                for cve in hit.cve_ids:
                    cve_row = get_cve(db, cve)
                    if cve_row and cve_row.get("cvss_v3"):
                        if cvss is None or cve_row["cvss_v3"] > cvss:
                            cvss = float(cve_row["cvss_v3"])
                    if is_kev(db, cve):
                        kev_flag = True
                    e = epss.lookup(db, cve)
                    if e and (epss_pct is None or e[1] > epss_pct):
                        epss_pct = e[1]

                inputs = RiskInputs(
                    cvss=cvss,
                    epss_percentile=epss_pct,
                    is_kev=kev_flag,
                    exposure="internet",
                    exploit_available="public" if kev_flag else "none",
                )
                score = composite_score(inputs)
                sev = severity_for(score, is_kev=kev_flag) if (cvss is not None or kev_flag) else hit.severity
                _persist(
                    source="nuclei",
                    title=hit.name,
                    sev=sev,
                    risk=score,
                    template_id=hit.template_id,
                    cve_ids=hit.cve_ids,
                    cwe_ids=hit.cwe_ids,
                    cvss_score=cvss,
                    epss_pct=epss_pct,
                    is_kev_flag=kev_flag,
                    location=hit.matched_at,
                    matcher_name=hit.matcher_name,
                    request=hit.request,
                    response_excerpt=hit.response_excerpt,
                    remediation=hit.remediation,
                    references=hit.references,
                    compliance_tags=_compliance_tags(hit.cwe_ids),
                )

            # TLS findings
            for th in tls_hits:
                # No CVSS for these in v0.2 — score off severity floor.
                sev = th.severity
                # rough numeric per band so risk_score is meaningful in the UI
                risk = {"critical": 90.0, "high": 75.0, "medium": 55.0, "low": 25.0, "info": 5.0}[sev]
                _persist(
                    source="sslyze",
                    title=th.title,
                    sev=sev,
                    risk=risk,
                    template_id=None,
                    cve_ids=[],
                    cwe_ids=th.cwe_ids,
                    cvss_score=None,
                    epss_pct=None,
                    is_kev_flag=False,
                    location=th.target,
                    matcher_name=None,
                    request=None,
                    response_excerpt=None,
                    remediation=th.remediation,
                    references=th.references,
                    compliance_tags=_compliance_tags(th.cwe_ids),
                )

            # Passive (ZAP / fallback) findings
            for ph in passive_hits:
                sev = ph.severity
                risk = {"critical": 90.0, "high": 75.0, "medium": 55.0, "low": 25.0, "info": 5.0}.get(sev, 5.0)
                _persist(
                    source="zap",
                    title=ph.title,
                    sev=sev,
                    risk=risk,
                    template_id=None,
                    cve_ids=[],
                    cwe_ids=ph.cwe_ids,
                    cvss_score=None,
                    epss_pct=None,
                    is_kev_flag=False,
                    location=ph.target,
                    matcher_name=None,
                    request=None,
                    response_excerpt=None,
                    remediation=ph.remediation,
                    references=ph.references,
                    compliance_tags=_compliance_tags(ph.cwe_ids),
                )

            db.commit()

            # Synthesize "fixed" markers for items present last scan but missing now
            for key in (prev_keys - current_keys):
                db.execute(
                    _INSERT_FINDING_SQL,
                    {
                        "id": str(uuid.uuid4()),
                        "tenant_id": tid,
                        "scan_id": scan_id,
                        "asset_id": asset_id,
                        "title": "(previously detected, no longer present)",
                        "template_id": None,
                        "cve_ids": json.dumps([]),
                        "cwe_ids": json.dumps([]),
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
                        "references": json.dumps([]),
                        "compliance_tags": json.dumps([]),
                        "diff_status": "fixed",
                        "dedupe_key": key,
                        "source": "diff",
                    },
                )
            db.commit()

            summary = {
                "ports_open": len(ports),
                "services_seen": len(services),
                "urls_crawled": len(crawled),
                "authenticated": not scanner_auth.is_empty(),
                "auth_kind": cred_kind if not scanner_auth.is_empty() else None,
                "tls_findings": len(tls_hits),
                "passive_findings": len(passive_hits),
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

            # Notifications (best-effort; failures don't fail the scan)
            top.sort(key=lambda t: t[2], reverse=True)
            try:
                dispatch(
                    db,
                    tenant_id=tid,
                    summary=ScanSummary(
                        scan_id=scan_id,
                        asset_name=asset_name,
                        target_url=target_url,
                        counts=findings_summary,
                        new=summary["new"],
                        fixed=summary["fixed"],
                        top_findings=top[:5],
                    ),
                )
            except Exception:  # noqa: BLE001
                log.exception("notification dispatch failed (non-fatal)")

            log.info("run_scan done scan_id=%s summary=%s", scan_id, summary)
            return summary

        except ScanCancelled:
            log.info("scan %s cancelled by user", scan_id)
            _set_state(
                db, scan_id,
                status="cancelled", stage="cancelled", progress=100,
                finished_at=datetime.now(UTC), error=None,
            )
            return {"cancelled": True}
        except Exception as exc:  # noqa: BLE001
            log.exception("scan failed: %s", exc)
            _set_state(
                db, scan_id,
                status="failed", stage="error", progress=100,
                finished_at=datetime.now(UTC), error=str(exc),
            )
            raise


# compliance tagging now lives in cyberscan_worker.compliance (pure-python module)
