from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from passlib.context import CryptContext

from cyberscan_api.core.config import get_settings

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


def create_access_token(subject: str, extra: dict[str, Any] | None = None) -> str:
    s = get_settings()
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=s.jwt_expires_min)).timestamp()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, s.api_secret_key, algorithm=s.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    s = get_settings()
    return jwt.decode(token, s.api_secret_key, algorithms=[s.jwt_algorithm])
