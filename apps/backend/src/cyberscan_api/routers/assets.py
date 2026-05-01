import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberscan_api.core.db import get_db
from cyberscan_api.models import Asset, AuditLog, User, VerificationStatus
from cyberscan_api.schemas import AssetCreate, AssetOut, VerificationInstructions
from cyberscan_api.services import verification
from cyberscan_api.services.auth_dep import get_current_user

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


@router.get("", response_model=list[AssetOut])
def list_assets(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[Asset]:
    return list(db.scalars(select(Asset).order_by(Asset.created_at.desc())))


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: AssetCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Asset:
    target_url = str(payload.target_url)
    hostname = verification.hostname_from_url(target_url)
    asset = Asset(
        name=payload.name,
        target_url=target_url,
        hostname=hostname,
        verification_method=payload.verification_method,
        verification_token=verification.new_token(),
        verification_status=VerificationStatus.pending,
        created_by=user.id,
    )
    db.add(asset)
    db.add(
        AuditLog(
            actor_user_id=user.id,
            action="asset.create",
            target_type="asset",
            target_id=str(asset.id),
            details={"hostname": hostname, "method": payload.verification_method},
        )
    )
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Asset:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="asset not found")
    return asset


@router.get("/{asset_id}/verify", response_model=VerificationInstructions)
def get_verification_instructions(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> VerificationInstructions:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="asset not found")
    return VerificationInstructions(
        method=asset.verification_method,
        token=asset.verification_token,
        instructions=verification.instructions_for(
            asset.verification_method, asset.hostname, asset.verification_token
        ),
    )


@router.post("/{asset_id}/verify", response_model=AssetOut)
def run_verification(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Asset:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="asset not found")

    ok, reason = verification.verify(
        asset.verification_method, asset.hostname, asset.verification_token
    )
    asset.verification_status = (
        VerificationStatus.verified if ok else VerificationStatus.failed
    )
    if ok:
        asset.verified_at = datetime.now(UTC)
    db.add(
        AuditLog(
            actor_user_id=user.id,
            action="asset.verify",
            target_type="asset",
            target_id=str(asset.id),
            details={"ok": ok, "reason": reason},
        )
    )
    db.commit()
    db.refresh(asset)
    if not ok:
        raise HTTPException(status_code=400, detail=f"verification failed: {reason}")
    return asset
