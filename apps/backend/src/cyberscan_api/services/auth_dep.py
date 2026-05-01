import hashlib
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import text
from sqlalchemy.orm import Session

from cyberscan_api.core.db import get_db
from cyberscan_api.core.roles import RANK as _RANK
from cyberscan_api.core.security import decode_token
from cyberscan_api.models import ApiToken, Role, User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

API_TOKEN_PREFIX = "cyb_"


def _pin_tenant(db: Session, tenant_id: uuid.UUID) -> None:
    db.execute(
        text("SELECT set_config('app.tenant_id', :tid, true)"),
        {"tid": str(tenant_id)},
    )


def get_current_user(token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Strict JWT-only path (used by login-flow endpoints)."""
    creds_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise creds_exc
    try:
        payload = decode_token(token)
        sub = payload.get("sub")
        if not sub:
            raise creds_exc
        user_id = uuid.UUID(sub)
    except (jwt.PyJWTError, ValueError):
        raise creds_exc from None
    user = db.get(User, user_id)
    if not user:
        raise creds_exc
    _pin_tenant(db, user.tenant_id)
    return user


def get_current_user_or_token(
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Accepts either a session JWT or an API token (prefix '%s').

    API tokens map to the user that created them (creator's role applies).
    """
    creds_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise creds_exc

    if token.startswith(API_TOKEN_PREFIX):
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        api_tok = db.query(ApiToken).filter(ApiToken.token_hash == token_hash).one_or_none()
        if not api_tok or api_tok.revoked_at is not None:
            raise creds_exc
        user = db.get(User, api_tok.created_by)
        if not user:
            raise creds_exc
        api_tok.last_used_at = datetime.now(UTC)
        db.commit()
        _pin_tenant(db, user.tenant_id)
        return user

    return get_current_user(token=token, db=db)


# substitute the docstring placeholder
get_current_user_or_token.__doc__ = (get_current_user_or_token.__doc__ or "").replace(
    "%s", API_TOKEN_PREFIX
)


def require_role(min_role: Role) -> Callable[[User], User]:
    def _check(user: User = Depends(get_current_user_or_token)) -> User:
        if _RANK[user.role] < _RANK[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role >= {min_role.value}",
            )
        return user

    return _check
