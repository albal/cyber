"""CISA KEV ingestion."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from cyberscan_worker.feeds.store import upsert_kev

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kev_sample.json"


def ingest(db: Session, *, use_fixture: bool) -> int:
    if use_fixture:
        if not FIXTURE_PATH.exists():
            log.warning("KEV fixture %s missing", FIXTURE_PATH)
            return 0
        with FIXTURE_PATH.open() as f:
            data = json.load(f)
    else:
        r = httpx.get(KEV_URL, timeout=30.0)
        r.raise_for_status()
        data = r.json()

    n = 0
    for item in data.get("vulnerabilities", []):
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        upsert_kev(db, cve_id=cve_id)
        n += 1
    db.commit()
    log.info("KEV: persisted %d entries", n)
    return n
