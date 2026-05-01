"""NVD CVE 2.0 ingestion. Live mode hits NVD; fixture mode reads bundled JSON."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from cyberscan_worker.feeds.store import upsert_cve

log = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "nvd_sample.json"


def ingest(db: Session, *, use_fixture: bool, api_key: str = "", limit: int = 200) -> int:
    if use_fixture:
        return _ingest_fixture(db)
    return _ingest_live(db, api_key=api_key, limit=limit)


def _ingest_fixture(db: Session) -> int:
    if not FIXTURE_PATH.exists():
        log.warning("NVD fixture %s missing", FIXTURE_PATH)
        return 0
    with FIXTURE_PATH.open() as f:
        data = json.load(f)
    return _persist(db, data.get("vulnerabilities", []))


def _ingest_live(db: Session, *, api_key: str, limit: int) -> int:
    headers = {"apiKey": api_key} if api_key else {}
    params = {"resultsPerPage": limit}
    r = httpx.get(NVD_API, params=params, headers=headers, timeout=30.0)
    r.raise_for_status()
    return _persist(db, r.json().get("vulnerabilities", []))


def _persist(db: Session, vulns: list[dict]) -> int:
    n = 0
    for v in vulns:
        cve = v.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descs = cve.get("descriptions") or []
        summary = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")

        cvss_v3: float | None = None
        cvss_vector: str | None = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metrics = (cve.get("metrics") or {}).get(metric_key) or []
            if metrics:
                cvss = metrics[0].get("cvssData") or {}
                cvss_v3 = cvss.get("baseScore")
                cvss_vector = cvss.get("vectorString")
                break

        upsert_cve(db, cve_id=cve_id, summary=summary, cvss_v3=cvss_v3, cvss_vector=cvss_vector)
        n += 1
    db.commit()
    log.info("NVD: persisted %d CVEs", n)
    return n
