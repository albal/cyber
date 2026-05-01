"""OIDC bearer-token verification.

When `OIDC_ISSUER` is configured, the backend accepts JWTs signed by that
issuer in addition to its own JWTs and the `cyb_*` API tokens. The issuer's
public keys are fetched from `<issuer>/.well-known/jwks.json` (or the
explicit `jwks_uri` discovered via `<issuer>/.well-known/openid-configuration`).

Users are auto-provisioned on first sign-in into the tenant whose slug
matches `OIDC_DEFAULT_TENANT`. The role from the configured claim is
respected if present and recognized; otherwise the user is created as a
`viewer`.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt as pyjwt
from jwt import PyJWKClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberscan_api.core.config import get_settings
from cyberscan_api.models import Role, Tenant, User

log = logging.getLogger(__name__)


@dataclass(slots=True)
class _JwksCache:
    client: PyJWKClient | None = None
    issuer: str = ""
    fetched_at: float = 0.0


_cache = _JwksCache()
_CACHE_TTL_S = 3600  # 1 hour


def is_enabled() -> bool:
    return bool(get_settings().oidc_issuer)


def verify_and_get_user(token: str, db: Session) -> User | None:
    """Validate `token` against the configured OIDC issuer and return a User
    (creating one on first use). Returns None if OIDC is not enabled, the
    issuer doesn't match, or the token is invalid."""
    s = get_settings()
    if not s.oidc_issuer:
        return None

    try:
        unverified = pyjwt.get_unverified_header(token)
    except pyjwt.PyJWTError:
        return None

    # Cheap rejection: token must reference an algorithm we support.
    alg = unverified.get("alg")
    if alg in (None, "none"):
        return None

    try:
        client = _get_jwks_client(s.oidc_issuer)
        signing_key = client.get_signing_key_from_jwt(token).key
        claims = pyjwt.decode(
            token,
            signing_key,
            algorithms=[alg],
            issuer=s.oidc_issuer.rstrip("/"),
            audience=s.oidc_audience or None,
            options={"require": ["exp", "iat"]},
        )
    except pyjwt.PyJWTError as exc:
        log.info("OIDC token rejected: %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001
        log.warning("OIDC verification failed: %s", exc)
        return None

    return _provision_user(db, claims)


def _get_jwks_client(issuer: str) -> PyJWKClient:
    now = time.time()
    if _cache.client is not None and _cache.issuer == issuer and now - _cache.fetched_at < _CACHE_TTL_S:
        return _cache.client

    jwks_uri = _discover_jwks_uri(issuer)
    _cache.client = PyJWKClient(jwks_uri, cache_keys=True)
    _cache.issuer = issuer
    _cache.fetched_at = now
    return _cache.client


def _discover_jwks_uri(issuer: str) -> str:
    """Resolve the JWKS endpoint via OIDC discovery, with a /jwks.json fallback."""
    base = issuer.rstrip("/")
    try:
        r = httpx.get(f"{base}/.well-known/openid-configuration", timeout=10.0)
        r.raise_for_status()
        data = r.json()
        if "jwks_uri" in data:
            return str(data["jwks_uri"])
    except (httpx.HTTPError, ValueError):
        log.info("OIDC discovery failed; falling back to %s/.well-known/jwks.json", base)
    return f"{base}/.well-known/jwks.json"


def _provision_user(db: Session, claims: dict[str, Any]) -> User | None:
    s = get_settings()
    email = claims.get(s.oidc_email_claim) or claims.get("preferred_username")
    if not email:
        log.info("OIDC token missing email/preferred_username claim")
        return None

    existing = db.scalar(select(User).where(User.email == email))
    if existing is not None:
        # Update role from claims if it changed (and is recognized).
        new_role = _role_from_claims(claims)
        if new_role and existing.role != new_role:
            existing.role = new_role
            db.commit()
        return existing

    tenant = db.scalar(select(Tenant).where(Tenant.slug == s.oidc_default_tenant))
    if tenant is None:
        log.warning("OIDC default tenant '%s' not found — refusing auto-provision", s.oidc_default_tenant)
        return None

    user = User(
        tenant_id=tenant.id,
        email=email,
        password_hash="!oidc",  # never used; OIDC users sign in via IdP
        role=_role_from_claims(claims) or Role.viewer,
        is_admin=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log.info("OIDC: provisioned user %s in tenant %s", email, tenant.slug)
    return user


def _role_from_claims(claims: dict[str, Any]) -> Role | None:
    s = get_settings()
    raw = claims.get(s.oidc_role_claim)
    if raw is None:
        return None
    if isinstance(raw, list):
        for r in raw:
            try:
                return Role(str(r).lower())
            except ValueError:
                continue
        return None
    try:
        return Role(str(raw).lower())
    except ValueError:
        return None
