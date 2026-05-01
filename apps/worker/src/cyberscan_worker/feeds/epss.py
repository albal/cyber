"""EPSS (Exploit Prediction Scoring System) ingestion.

Live source: https://api.first.org/data/v1/epss?cve=...  (per-CVE, slow)
Bulk source: https://epss.cyentia.com/epss_scores-current.csv.gz (preferred)

For MVP fixture mode we ship a small CSV sample.
"""
from __future__ import annotations

import csv
import gzip
import io
import logging
from pathlib import Path

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

EPSS_BULK_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "epss_sample.csv"


def ingest(db: Session, *, use_fixture: bool) -> int:
    rows = _fixture_rows() if use_fixture else _live_rows()
    n = 0
    for cve_id, score, percentile in rows:
        db.execute(
            text(
                """
                INSERT INTO epss (cve_id, score, percentile)
                VALUES (:id, :score, :percentile)
                ON CONFLICT (cve_id) DO UPDATE
                  SET score = EXCLUDED.score,
                      percentile = EXCLUDED.percentile
                """
            ),
            {"id": cve_id.upper(), "score": score, "percentile": percentile},
        )
        n += 1
    db.commit()
    log.info("EPSS: persisted %d rows", n)
    return n


def lookup(db: Session, cve_id: str) -> tuple[float, float] | None:
    row = db.execute(
        text("SELECT score, percentile FROM epss WHERE cve_id = :id"),
        {"id": cve_id.upper()},
    ).first()
    if not row:
        return None
    return float(row.score), float(row.percentile)


def _fixture_rows() -> list[tuple[str, float, float]]:
    if not FIXTURE_PATH.exists():
        log.warning("EPSS fixture %s missing", FIXTURE_PATH)
        return []
    with FIXTURE_PATH.open() as f:
        return _parse_csv(f.read())


def _live_rows() -> list[tuple[str, float, float]]:
    r = httpx.get(EPSS_BULK_URL, timeout=60.0)
    r.raise_for_status()
    raw = gzip.decompress(r.content).decode("utf-8", errors="replace")
    return _parse_csv(raw)


def _parse_csv(raw: str) -> list[tuple[str, float, float]]:
    out: list[tuple[str, float, float]] = []
    # FIRST.org's bulk file leads with a `#` comment line; csv reader handles fine.
    reader = csv.DictReader(line for line in io.StringIO(raw) if not line.startswith("#"))
    for row in reader:
        cve = row.get("cve") or row.get("CVE") or ""
        try:
            score = float(row.get("epss") or row.get("score") or 0)
            percentile = float(row.get("percentile") or 0)
        except ValueError:
            continue
        if cve:
            out.append((cve, score, percentile))
    return out
