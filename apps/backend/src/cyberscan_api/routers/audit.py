"""Tenant-scoped audit-log export.

Append-only `audit_log` rows are exposed via paged GET (handy for the UI)
plus streaming CSV / JSONL endpoints suitable for SOC 2 evidence ingest.
"""
from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberscan_api.core.db import get_db
from cyberscan_api.models import AuditLog, Role, User
from cyberscan_api.services.auth_dep import get_current_user_or_token, require_role

router = APIRouter(prefix="/api/v1/audit-log", tags=["audit"])

_COLUMNS = (
    "id",
    "created_at",
    "actor_user_id",
    "actor_ip",
    "action",
    "target_type",
    "target_id",
    "details",
)


def _serialize(row: AuditLog) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for col in _COLUMNS:
        v = getattr(row, col)
        if isinstance(v, datetime):
            out[col] = v.isoformat()
        elif col == "details":
            out[col] = v  # already a dict / None
        elif v is None:
            out[col] = None
        else:
            out[col] = str(v)
    return out


@router.get("")
def list_audit(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user_or_token),
) -> dict:
    rows = list(
        db.scalars(
            select(AuditLog)
            .order_by(AuditLog.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
    )
    return {"limit": limit, "offset": offset, "items": [_serialize(r) for r in rows]}


@router.get("/export.csv")
def export_csv(
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin)),
) -> StreamingResponse:
    def _gen() -> Iterator[str]:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(_COLUMNS)
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)

        # Stream — don't materialize the whole table in memory.
        for row in db.scalars(
            select(AuditLog).order_by(AuditLog.created_at.asc()).execution_options(yield_per=500)
        ):
            data = _serialize(row)
            writer.writerow(
                [
                    json.dumps(data[c]) if c == "details" and data[c] is not None else (data[c] or "")
                    for c in _COLUMNS
                ]
            )
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    return StreamingResponse(
        _gen(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="audit-log.csv"'},
    )


@router.get("/export.jsonl")
def export_jsonl(
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin)),
) -> StreamingResponse:
    """JSON Lines — one JSON object per line. Friendlier for SIEM / Loki ingest."""

    def _gen() -> Iterator[bytes]:
        for row in db.scalars(
            select(AuditLog).order_by(AuditLog.created_at.asc()).execution_options(yield_per=500)
        ):
            yield (json.dumps(_serialize(row), default=str) + "\n").encode()

    return StreamingResponse(
        _gen(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="audit-log.jsonl"'},
    )
