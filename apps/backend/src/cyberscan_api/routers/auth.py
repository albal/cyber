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
from cyberscan_api.services.audit import write_audit
from cyberscan_api.services.auth_dep import get_current_user
from cyberscan_api.services.client_ip import client_ip as _client_ip

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=Token)
def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> Token:
    s = get_settings()
    email = form.username.lower()
    ip = _client_ip(request)

    # Two buckets, both must pass:
    #   - per-(IP+email) catches single-source brute force
    #   - per-account catches distributed credential stuffing
    ip_key = f"login:ip:{ip}:{email}"
    acct_key = f"login:acct:{email}"

    ip_decision = rate_limit.check(
        key=ip_key,
        max_attempts=s.login_rate_max_attempts,
        window_s=s.login_rate_window_s,
    )
    acct_decision = rate_limit.check(
        key=acct_key,
        max_attempts=s.login_account_max_attempts,
        window_s=s.login_account_window_s,
    )
    if not (ip_decision.allowed and acct_decision.allowed):
        # Take the more conservative of the two retry-afters so we don't
        # advertise the bucket the caller just tripped.
        retry = max(ip_decision.retry_after_s, acct_decision.retry_after_s)
        write_audit(
            db,
            request=request,
            action="auth.login.rate_limited",
            target_type="user",
            details={
                "email": email,
                "bucket": "ip" if not ip_decision.allowed else "account",
            },
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"too many login attempts; retry in {retry}s",
            headers={"Retry-After": str(retry)},
        )

    user = db.scalar(select(User).where(User.email == email))
    if not user or not verify_password(form.password, user.password_hash):
        write_audit(
            db,
            request=request,
            action="auth.login.failure",
            target_type="user",
            actor_user_id=user.id if user else None,
            tenant_id=user.tenant_id if user else None,
            details={"email": email},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    # Successful login: wipe both failure counters so the next bad password
    # doesn't lock the user out immediately, and audit the event.
    rate_limit.reset(key=ip_key)
    rate_limit.reset(key=acct_key)
    write_audit(
        db,
        request=request,
        user=user,
        action="auth.login.success",
        target_type="user",
        target_id=str(user.id),
    )
    db.commit()
    return Token(access_token=create_access_token(str(user.id), {"email": user.email}))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user
