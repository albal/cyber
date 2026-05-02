from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberscan_api.core.config import get_settings
from cyberscan_api.core.db import get_db
from cyberscan_api.core.security import create_access_token, verify_password
from cyberscan_api.models import User
from cyberscan_api.schemas import Token, UserOut
from cyberscan_api.services import rate_limit
from cyberscan_api.services.auth_dep import get_current_user

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _client_ip(req: Request) -> str:
    """Best-effort caller IP. Honors X-Forwarded-For when behind ingress."""
    xff = req.headers.get("x-forwarded-for")
    if xff:
        # First entry is the original client; subsequent ones are proxies.
        return xff.split(",")[0].strip()
    return req.client.host if req.client else "unknown"


@router.post("/login", response_model=Token)
def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> Token:
    s = get_settings()
    # Bucket is per-IP+email so credential stuffing locks the attacker, not
    # an unrelated victim coming in from a different network.
    rl_key = f"login:{_client_ip(request)}:{form.username.lower()}"
    decision = rate_limit.check(
        key=rl_key,
        max_attempts=s.login_rate_max_attempts,
        window_s=s.login_rate_window_s,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"too many login attempts; retry in {decision.retry_after_s}s"
            ),
            headers={"Retry-After": str(decision.retry_after_s)},
        )

    user = db.scalar(select(User).where(User.email == form.username))
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    # Successful login wipes the failure counter so the next bad password
    # doesn't lock the user out immediately.
    rate_limit.reset(key=rl_key)
    return Token(access_token=create_access_token(str(user.id), {"email": user.email}))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user
