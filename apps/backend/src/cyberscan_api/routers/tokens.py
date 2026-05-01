"""API tokens for CI/CD and other automation.

Tokens are returned in plaintext exactly once at creation. We store
sha256(token) so a compromised DB doesn't yield usable tokens. Token
format: cyb_<32 url-safe random bytes>.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberscan_api.core.db import get_db
from cyberscan_api.models import ApiToken, AuditLog, Role, User
from cyberscan_api.schemas import ApiTokenCreate, ApiTokenCreated, ApiTokenOut
from cyberscan_api.services.auth_dep import API_TOKEN_PREFIX, require_role

router = APIRouter(prefix="/api/v1/tokens", tags=["tokens"])


@router.get("", response_model=list[ApiTokenOut])
def list_tokens(
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin)),
) -> list[ApiToken]:
    return list(db.scalars(select(ApiToken).order_by(ApiToken.created_at.desc())))


@router.post("", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED)
def create_token(
    payload: ApiTokenCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin)),
) -> ApiTokenCreated:
    plaintext = f"{API_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
    token = ApiToken(
        tenant_id=user.tenant_id,
        created_by=user.id,
        name=payload.name,
        token_hash=hashlib.sha256(plaintext.encode()).hexdigest(),
        token_prefix=plaintext[: len(API_TOKEN_PREFIX) + 6],
    )
    db.add(token)
    db.add(
        AuditLog(
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action="token.create",
            target_type="api_token",
            target_id=str(token.id),
            details={"name": payload.name},
        )
    )
    db.commit()
    db.refresh(token)
    return ApiTokenCreated(
        id=token.id,
        name=token.name,
        token_prefix=token.token_prefix,
        revoked_at=None,
        last_used_at=None,
        created_at=token.created_at,
        token=plaintext,
    )


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(
    token_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin)),
) -> None:
    token = db.get(ApiToken, token_id)
    if not token:
        raise HTTPException(status_code=404, detail="token not found")
    if token.revoked_at is None:
        token.revoked_at = datetime.now(UTC)
    db.add(
        AuditLog(
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action="token.revoke",
            target_type="api_token",
            target_id=str(token.id),
        )
    )
    db.commit()
