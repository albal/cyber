"""OSV.dev advisory ingestion.

Live source: https://osv-vulnerabilities.storage.googleapis.com/all.zip
  (zip of per-ecosystem JSON files; a few hundred MB).

For dev / fixture mode we ship a tiny JSON-Lines sample with the same
shape as OSV records.

Lookups are by alias (CVE → OSV record). The aliases column has a GIN
index using jsonb_path_ops.
"""
from __future__ import annotations

import io
import json
import logging
import zipfile
from pathlib import Path

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

OSV_BULK_URL = "https://osv-vulnerabilities.storage.googleapis.com/all.zip"
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "osv_sample.jsonl"

# Ecosystems we care about for web app scanning. Limit ingestion size for
# dev / single-tenant deployments. Live ingest can override via env.
DEFAULT_ECOSYSTEMS = ("npm", "PyPI", "Maven", "Go", "RubyGems", "crates.io", "Packagist")


def ingest(db: Session, *, use_fixture: bool, ecosystems: tuple[str, ...] = DEFAULT_ECOSYSTEMS) -> int:
    rows = _fixture_rows() if use_fixture else _live_rows(ecosystems)
    n = 0
    for record in rows:
        try:
            _persist(db, record)
            n += 1
        except Exception as exc:  # noqa: BLE001
            log.warning("OSV: skipping malformed record (%s): %s", record.get("id"), exc)
    db.commit()
    log.info("OSV: persisted %d advisories", n)
    return n


def lookup_by_cve(db: Session, cve_id: str) -> dict | None:
    """Return the highest-severity OSV record that aliases the given CVE, if any."""
    row = db.execute(
        text(
            """
            SELECT osv_id, summary, aliases, severity
              FROM osv_advisories
             WHERE aliases @> CAST(:alias AS jsonb)
             LIMIT 1
            """
        ),
        {"alias": json.dumps([cve_id.upper()])},
    ).first()
    if not row:
        return None
    return {
        "osv_id": row.osv_id,
        "summary": row.summary,
        "aliases": row.aliases,
        "severity": row.severity,
    }


# ---- internals --------------------------------------------------------------


def _persist(db: Session, record: dict) -> None:
    osv_id = record.get("id")
    if not osv_id:
        return
    summary = record.get("summary") or ""
    aliases = [a.upper() for a in (record.get("aliases") or [])]
    affected = record.get("affected") or []
    severity = (record.get("database_specific") or {}).get("severity")
    modified = record.get("modified")

    db.execute(
        text(
            """
            INSERT INTO osv_advisories (osv_id, summary, aliases, affected, severity, modified_at)
            VALUES (:osv_id, :summary, CAST(:aliases AS jsonb), CAST(:affected AS jsonb), :severity, :modified)
            ON CONFLICT (osv_id) DO UPDATE
              SET summary = EXCLUDED.summary,
                  aliases = EXCLUDED.aliases,
                  affected = EXCLUDED.affected,
                  severity = EXCLUDED.severity,
                  modified_at = EXCLUDED.modified_at
            """
        ),
        {
            "osv_id": osv_id,
            "summary": summary,
            "aliases": json.dumps(aliases),
            "affected": json.dumps(affected),
            "severity": severity,
            "modified": modified,
        },
    )


def _fixture_rows() -> list[dict]:
    if not FIXTURE_PATH.exists():
        log.warning("OSV fixture %s missing", FIXTURE_PATH)
        return []
    out: list[dict] = []
    with FIXTURE_PATH.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _live_rows(ecosystems: tuple[str, ...]) -> list[dict]:
    """Fetch the OSV bulk zip and yield records for the requested ecosystems."""
    log.info("Fetching OSV bulk zip from %s", OSV_BULK_URL)
    r = httpx.get(OSV_BULK_URL, timeout=180.0)
    r.raise_for_status()
    out: list[dict] = []
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            top = name.split("/", 1)[0]
            if ecosystems and top not in ecosystems:
                continue
            try:
                with zf.open(name) as f:
                    out.append(json.loads(f.read()))
            except Exception:  # noqa: BLE001
                continue
    return out
