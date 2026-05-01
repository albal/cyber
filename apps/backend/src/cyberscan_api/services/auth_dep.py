import uuid

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from cyberscan_api.core.db import get_db
from cyberscan_api.core.security import decode_token
from cyberscan_api.models import User

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
    return user
