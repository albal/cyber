import asyncio
import csv
import io
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from cyberscan_api.core.celery_client import celery_app
from cyberscan_api.core.db import SessionLocal, get_db
from cyberscan_api.models import Asset, AuditLog, Finding, Role, Scan, User, VerificationStatus
from cyberscan_api.schemas import FindingOut, ScanCreate, ScanOut
from cyberscan_api.services.auth_dep import get_current_user_or_token, require_role

router = APIRouter(prefix="/api/v1", tags=["scans"])

# Intrusive scans require ownership re-verified within the last N days.
INTRUSIVE_VERIFICATION_DAYS = 7


@router.post("/scans", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.analyst)),
) -> Scan:
    asset = db.get(Asset, payload.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="asset not found")
    if asset.verification_status != VerificationStatus.verified:
        raise HTTPException(
            status_code=400,
            detail="asset is not verified — verify ownership before scanning",
        )

    if payload.intrusive:
        if asset.verified_at is None or (
            datetime.now(UTC) - asset.verified_at > timedelta(days=INTRUSIVE_VERIFICATION_DAYS)
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"intrusive scans require ownership re-verification within "
                    f"the last {INTRUSIVE_VERIFICATION_DAYS} days — re-run verification first"
                ),
            )

    scan = Scan(
        tenant_id=user.tenant_id,
        asset_id=asset.id,
        created_by=user.id,
        intrusive=payload.intrusive,
    )
    db.add(scan)
    db.add(
        AuditLog(
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action="scan.create",
            target_type="scan",
            target_id=str(scan.id),
            details={
                "asset_id": str(asset.id),
                "target": asset.target_url,
                "intrusive": payload.intrusive,
            },
        )
    )
    db.commit()
    db.refresh(scan)

    celery_app.send_task(
        "cyberscan_worker.pipeline.run_scan",
        kwargs={
            "scan_id": str(scan.id),
            "tenant_id": str(user.tenant_id),
            "intrusive": payload.intrusive,
        },
        queue="recon",
    )
    return scan


@router.get("/scans", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db), user: User = Depends(get_current_user_or_token)) -> list[Scan]:
    return list(db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(100)))


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user_or_token),
) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_findings(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user_or_token),
) -> list[Finding]:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    return list(
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.risk_score.desc(), Finding.severity)
        )
    )


_EXPORT_COLUMNS = (
    "id", "title", "severity", "risk_score", "cvss_score", "epss_score", "is_kev",
    "cve_ids", "cwe_ids", "compliance_tags", "location", "source", "diff_status",
    "remediation", "created_at",
)


@router.get("/scans/{scan_id}/findings.csv")
def export_findings_csv(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user_or_token),
) -> StreamingResponse:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")

    def _gen() -> "Iterator[str]":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(_EXPORT_COLUMNS)
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)

        for f in db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.risk_score.desc(), Finding.severity)
        ):
            row = []
            for col in _EXPORT_COLUMNS:
                val = getattr(f, col)
                if isinstance(val, list):
                    val = "; ".join(map(str, val))
                row.append("" if val is None else val)
            writer.writerow(row)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    filename = f"cyberscan-{scan_id}.csv"
    return StreamingResponse(
        _gen(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/findings.json")
def export_findings_json(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user_or_token),
) -> StreamingResponse:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")

    def _serialize(f: Finding) -> dict:
        return {
            col: (v.isoformat() if isinstance((v := getattr(f, col)), datetime) else v)
            for col in _EXPORT_COLUMNS
        }

    def _gen() -> "Iterator[bytes]":
        first = True
        yield b'{"scan_id":"' + str(scan_id).encode() + b'","findings":['
        for f in db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.risk_score.desc(), Finding.severity)
        ):
            sep = b"" if first else b","
            first = False
            yield sep + json.dumps(_serialize(f), default=str).encode()
        yield b"]}"

    filename = f"cyberscan-{scan_id}.json"
    return StreamingResponse(
        _gen(),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/findings.pdf")
def export_findings_pdf(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user_or_token),
) -> StreamingResponse:
    from cyberscan_api.services.pdf_report import render as render_pdf

    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    asset = db.get(Asset, scan.asset_id)

    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.risk_score.desc(), Finding.severity)
        )
    )

    pdf_bytes = render_pdf(
        scan={
            "id": str(scan.id),
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "created_at": scan.created_at,
            "summary": scan.summary,
        },
        asset={
            "name": getattr(asset, "name", ""),
            "target_url": getattr(asset, "target_url", ""),
        },
        findings=[
            {
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                "risk_score": f.risk_score,
                "cve_ids": f.cve_ids or [],
                "cwe_ids": f.cwe_ids or [],
                "compliance_tags": f.compliance_tags or [],
                "location": f.location,
                "remediation": f.remediation,
            }
            for f in findings
        ],
    )

    filename = f"cyberscan-{scan_id}.pdf"
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(
    websocket: WebSocket,
    scan_id: uuid.UUID,
    token: str | None = None,
) -> None:
    """Push scan-progress updates until the scan is terminal.

    Auth: the bearer token (JWT or API token) is passed as ?token=...
    because browsers can't set Authorization on the WebSocket open. We
    resolve the user, pin the tenant GUC, and reject if the scan belongs
    to a different tenant or doesn't exist.
    """
    user = _ws_authenticate(token)
    if user is None:
        await websocket.close(code=4401)  # 4xxx = application close codes
        return

    await websocket.accept()
    try:
        last_payload: dict | None = None
        terminal = {"completed", "failed", "partial"}
        while True:
            with SessionLocal() as db:
                db.execute(
                    text("SELECT set_config('app.tenant_id', :tid, true)"),
                    {"tid": str(user.tenant_id)},
                )
                scan = db.get(Scan, scan_id)
                if not scan or scan.tenant_id != user.tenant_id:
                    await websocket.send_json({"error": "scan not found"})
                    break
                payload = {
                    "id": str(scan.id),
                    "status": scan.status.value,
                    "stage": scan.stage,
                    "progress": scan.progress,
                }
            if payload != last_payload:
                await websocket.send_json(payload)
                last_payload = payload
            if payload["status"] in terminal:
                break
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass


def _ws_authenticate(token: str | None) -> User | None:
    """Resolve a websocket-supplied token into a User, or None if invalid.

    Mirrors get_current_user_or_token but without FastAPI's Depends() chain
    (which doesn't apply to websockets). Returns None on any failure so the
    caller can close the socket; never raises.
    """
    if not token:
        return None

    import hashlib
    import jwt as pyjwt

    from cyberscan_api.core.security import decode_token
    from cyberscan_api.models import ApiToken
    from cyberscan_api.services.auth_dep import API_TOKEN_PREFIX

    try:
        with SessionLocal() as db:
            if token.startswith(API_TOKEN_PREFIX):
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                api_tok = (
                    db.query(ApiToken).filter(ApiToken.token_hash == token_hash).one_or_none()
                )
                if not api_tok or api_tok.revoked_at is not None:
                    return None
                return db.get(User, api_tok.created_by)

            payload = decode_token(token)
            sub = payload.get("sub")
            if not sub:
                return None
            return db.get(User, uuid.UUID(sub))
    except (pyjwt.PyJWTError, ValueError, Exception):  # noqa: BLE001
        return None
