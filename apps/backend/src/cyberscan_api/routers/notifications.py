import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberscan_api.core.db import get_db
from cyberscan_api.models import AuditLog, NotificationChannel, Role, Severity, User
from cyberscan_api.schemas import NotificationChannelCreate, NotificationChannelOut
from cyberscan_api.services.auth_dep import get_current_user, require_role

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])


@router.get("/channels", response_model=list[NotificationChannelOut])
def list_channels(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> list[NotificationChannel]:
    return list(
        db.scalars(
            select(NotificationChannel).order_by(NotificationChannel.created_at.desc())
        )
    )


@router.post(
    "/channels", response_model=NotificationChannelOut, status_code=status.HTTP_201_CREATED
)
def create_channel(
    payload: NotificationChannelCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin)),
) -> NotificationChannel:
    ch = NotificationChannel(
        tenant_id=user.tenant_id,
        kind=payload.kind,
        target=payload.target,
        min_severity=Severity(payload.min_severity),
        enabled=payload.enabled,
    )
    db.add(ch)
    db.add(
        AuditLog(
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action="notification.create",
            target_type="notification_channel",
            target_id=str(ch.id),
            details={"kind": payload.kind},
        )
    )
    db.commit()
    db.refresh(ch)
    return ch


@router.delete("/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_channel(
    channel_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin)),
) -> None:
    ch = db.get(NotificationChannel, channel_id)
    if not ch:
        raise HTTPException(status_code=404, detail="channel not found")
    db.delete(ch)
    db.add(
        AuditLog(
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action="notification.delete",
            target_type="notification_channel",
            target_id=str(channel_id),
        )
    )
    db.commit()
