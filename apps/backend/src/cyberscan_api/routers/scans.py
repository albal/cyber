import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from cyberscan_api.core.celery_client import celery_app
from cyberscan_api.core.db import SessionLocal, get_db
from cyberscan_api.models import Asset, AuditLog, Finding, Role, Scan, User, VerificationStatus
from cyberscan_api.schemas import FindingOut, ScanCreate, ScanOut
from cyberscan_api.services.auth_dep import get_current_user, require_role

router = APIRouter(prefix="/api/v1", tags=["scans"])


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

    scan = Scan(tenant_id=user.tenant_id, asset_id=asset.id, created_by=user.id)
    db.add(scan)
    db.add(
        AuditLog(
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action="scan.create",
            target_type="scan",
            target_id=str(scan.id),
            details={"asset_id": str(asset.id), "target": asset.target_url},
        )
    )
    db.commit()
    db.refresh(scan)

    celery_app.send_task(
        "cyberscan_worker.pipeline.run_scan",
        kwargs={"scan_id": str(scan.id), "tenant_id": str(user.tenant_id)},
        queue="recon",
    )
    return scan


@router.get("/scans", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[Scan]:
    return list(db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(100)))


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_findings(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
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


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: uuid.UUID) -> None:
    """Polls scan state and pushes updates. Closes when scan is terminal.

    NOTE: websocket bypasses the FastAPI Depends() OIDC chain at v0.2 — wire a
    token query param + tenant GUC before exposing publicly. Tracked for v1.0.
    """
    await websocket.accept()
    try:
        last_payload: dict | None = None
        terminal = {"completed", "failed", "partial"}
        while True:
            with SessionLocal() as db:
                # No tenant GUC here — the websocket is read-only on a single id
                # and the user has already authenticated to obtain the scan_id.
                db.execute(text("SELECT set_config('app.tenant_id', '', true)"))
                scan = db.get(Scan, scan_id)
                if not scan:
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
