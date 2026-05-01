import uuid
from collections.abc import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import text
from sqlalchemy.orm import Session

from cyberscan_api.core.db import get_db
from cyberscan_api.core.roles import RANK as _RANK
from cyberscan_api.core.security import decode_token
from cyberscan_api.models import Role, User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    creds_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
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
    # Pin the per-session GUC so RLS scopes every subsequent query to this tenant.
    # Postgres SET doesn't accept bind parameters; use set_config() which does.
    # The third arg 'true' = LOCAL (transaction-scoped, like SET LOCAL).
    db.execute(
        text("SELECT set_config('app.tenant_id', :tid, true)"),
        {"tid": str(user.tenant_id)},
    )
    return user


def require_role(min_role: Role) -> Callable[[User], User]:
    def _check(user: User = Depends(get_current_user)) -> User:
        if _RANK[user.role] < _RANK[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role >= {min_role.value}",
            )
        return user

    return _check
