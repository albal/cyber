"""Lookup helpers against the cves / kev tables."""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session


def get_cve(db: Session, cve_id: str) -> dict | None:
    row = db.execute(
        text("SELECT cve_id, summary, cvss_v3, cvss_vector FROM cves WHERE cve_id = :id"),
        {"id": cve_id.upper()},
    ).first()
    if not row:
        return None
    return {
        "cve_id": row.cve_id,
        "summary": row.summary,
        "cvss_v3": row.cvss_v3,
        "cvss_vector": row.cvss_vector,
    }


def is_kev(db: Session, cve_id: str) -> bool:
    row = db.execute(
        text("SELECT 1 FROM kev WHERE cve_id = :id LIMIT 1"),
        {"id": cve_id.upper()},
    ).first()
    return row is not None


def upsert_cve(db: Session, *, cve_id: str, summary: str, cvss_v3: float | None, cvss_vector: str | None) -> None:
    db.execute(
        text(
            """
            INSERT INTO cves (cve_id, summary, cvss_v3, cvss_vector, cwe_ids, "references")
            VALUES (:id, :summary, :cvss, :vector, '[]'::json, '[]'::json)
            ON CONFLICT (cve_id) DO UPDATE
              SET summary = EXCLUDED.summary,
                  cvss_v3 = EXCLUDED.cvss_v3,
                  cvss_vector = EXCLUDED.cvss_vector
            """
        ),
        {"id": cve_id.upper(), "summary": summary, "cvss": cvss_v3, "vector": cvss_vector},
    )


def upsert_kev(db: Session, *, cve_id: str) -> None:
    db.execute(
        text(
            """
            INSERT INTO kev (cve_id, ransomware_use)
            VALUES (:id, FALSE)
            ON CONFLICT (cve_id) DO NOTHING
            """
        ),
        {"id": cve_id.upper()},
    )
