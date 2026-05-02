import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberscan_api.core.config import get_settings
from cyberscan_api.core.crypto import encrypt_json
from cyberscan_api.core.db import get_db
from cyberscan_api.models import Asset, AssetCredential, AuditLog, Role, User, VerificationStatus
from cyberscan_api.schemas import (
    AssetCreate,
    AssetCredentialBasic,
    AssetCredentialBearer,
    AssetCredentialCookie,
    AssetCredentialHeader,
    AssetCredentialMeta,
    AssetOut,
    AssetSchedule,
    AssetUpdate,
    VerificationInstructions,
)
from cyberscan_api.services import verification
from cyberscan_api.services.auth_dep import get_current_user_or_token, require_role

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


@router.get("", response_model=list[AssetOut])
def list_assets(db: Session = Depends(get_db), user: User = Depends(get_current_user_or_token)) -> list[Asset]:
    return list(db.scalars(select(Asset).order_by(Asset.created_at.desc())))


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: AssetCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.analyst)),
) -> Asset:
    target_url = str(payload.target_url)
    hostname = verification.hostname_from_url(target_url)
    asset = Asset(
        tenant_id=user.tenant_id,
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
            tenant_id=user.tenant_id,
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
    user: User = Depends(get_current_user_or_token),
) -> Asset:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="asset not found")
    return asset


@router.get("/{asset_id}/verify", response_model=VerificationInstructions)
def get_verification_instructions(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user_or_token),
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


@router.patch("/{asset_id}", response_model=AssetOut)
def patch_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.analyst)),
) -> Asset:
    """Partial-update an asset's settings (currently only enumerate_subdomains)."""
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="asset not found")
    changed: dict[str, object] = {}
    if payload.enumerate_subdomains is not None:
        asset.enumerate_subdomains = payload.enumerate_subdomains
        changed["enumerate_subdomains"] = payload.enumerate_subdomains
    if changed:
        db.add(
            AuditLog(
                tenant_id=user.tenant_id,
                actor_user_id=user.id,
                action="asset.update",
                target_type="asset",
                target_id=str(asset.id),
                details=changed,
            )
        )
    db.commit()
    db.refresh(asset)
    return asset


@router.put("/{asset_id}/schedule", response_model=AssetOut)
def set_schedule(
    asset_id: uuid.UUID,
    payload: AssetSchedule,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.analyst)),
) -> Asset:
    """Set or update a per-asset cron schedule for recurring scans.

    The cron expression is validated with croniter. Setting schedule_enabled=False
    or schedule_cron=null disables the schedule.
    """
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="asset not found")

    if payload.schedule_cron:
        try:
            from croniter import croniter

            croniter(payload.schedule_cron)
        except (ImportError, ValueError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=f"invalid cron: {exc}") from exc

    asset.schedule_cron = payload.schedule_cron
    asset.schedule_enabled = bool(payload.schedule_cron) and payload.schedule_enabled
    db.add(
        AuditLog(
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action="asset.schedule",
            target_type="asset",
            target_id=str(asset.id),
            details={"cron": payload.schedule_cron, "enabled": asset.schedule_enabled},
        )
    )
    db.commit()
    db.refresh(asset)
    return asset


@router.post("/{asset_id}/verify", response_model=AssetOut)
def run_verification(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.analyst)),
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
            tenant_id=user.tenant_id,
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


# ---------- Asset credentials (authenticated scans) --------------------------

CredentialPayload = (
    AssetCredentialCookie | AssetCredentialBearer | AssetCredentialBasic | AssetCredentialHeader
)


def _payload_to_secret(payload: CredentialPayload) -> dict:
    """Strip metadata fields and return only the secret-bearing fields."""
    if isinstance(payload, AssetCredentialCookie):
        return {"cookie_header": payload.cookie_header}
    if isinstance(payload, AssetCredentialBearer):
        return {"token": payload.token}
    if isinstance(payload, AssetCredentialBasic):
        return {"username": payload.username, "password": payload.password}
    return {"name": payload.name, "value": payload.value}


@router.put("/{asset_id}/credentials", response_model=AssetCredentialMeta)
def set_credentials(
    asset_id: uuid.UUID,
    payload: CredentialPayload,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.analyst)),
) -> AssetCredential:
    """Store (or replace) authentication credentials for an asset.

    The plaintext secret is encrypted with the application's secret key
    (Fernet) before reaching the DB. Only the metadata (`kind`, `label`,
    timestamps) is ever returned by GET.
    """
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="asset not found")

    secret = _payload_to_secret(payload)
    cipher = encrypt_json(secret, secret=get_settings().api_secret_key)

    existing = db.scalar(select(AssetCredential).where(AssetCredential.asset_id == asset_id))
    if existing:
        existing.kind = payload.kind
        existing.label = payload.label
        existing.secret_ciphertext = cipher
        existing.created_by = user.id
        cred = existing
    else:
        cred = AssetCredential(
            tenant_id=user.tenant_id,
            asset_id=asset_id,
            created_by=user.id,
            kind=payload.kind,
            label=payload.label,
            secret_ciphertext=cipher,
        )
        db.add(cred)

    db.add(
        AuditLog(
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action="asset.credentials.set",
            target_type="asset",
            target_id=str(asset_id),
            # Never log the secret. Kind + label only.
            details={"kind": payload.kind, "label": payload.label},
        )
    )
    db.commit()
    db.refresh(cred)
    return cred


@router.get("/{asset_id}/credentials", response_model=AssetCredentialMeta | None)
def get_credentials_meta(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user_or_token),
) -> AssetCredential | None:
    """Return metadata only (kind, label, created_at). Never the secret."""
    cred = db.scalar(select(AssetCredential).where(AssetCredential.asset_id == asset_id))
    return cred  # may be None — Pydantic Optional handles it


@router.delete("/{asset_id}/credentials", status_code=status.HTTP_204_NO_CONTENT)
def delete_credentials(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.analyst)),
) -> None:
    cred = db.scalar(select(AssetCredential).where(AssetCredential.asset_id == asset_id))
    if cred is not None:
        db.delete(cred)
        db.add(
            AuditLog(
                tenant_id=user.tenant_id,
                actor_user_id=user.id,
                action="asset.credentials.delete",
                target_type="asset",
                target_id=str(asset_id),
            )
        )
        db.commit()
