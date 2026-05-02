"""Audit-log helper.

The schema's been carrying an unused ``actor_ip`` column since v0.1; this
helper makes it the default path so every router gets the caller IP for
free. ``request`` is optional so we can also audit from background-ish
flows (e.g. token verification) where there's no FastAPI request handle.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from cyberscan_api.models import AuditLog, User
from cyberscan_api.services.client_ip import client_ip


def write_audit(
    db: Session,
    *,
    action: str,
    user: User | None = None,
    request: Request | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
    tenant_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    actor_ip: str | None = None,
) -> AuditLog:
    """Add an AuditLog row to ``db``. Caller is responsible for commit.

    ``user`` is the convenient case (logged-in caller). For login
    failure / rate-limit you may pass ``tenant_id`` / ``actor_user_id``
    explicitly (or leave both None for an anonymous-attempt row).

    ``actor_ip`` is auto-filled from ``request`` (respecting the
    ``trusted_proxies`` allowlist) when not given explicitly.
    """
    if actor_ip is None and request is not None:
        actor_ip = client_ip(request)

    if tenant_id is None and user is not None:
        tenant_id = user.tenant_id
    if actor_user_id is None and user is not None:
        actor_user_id = user.id

    row = AuditLog(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_ip=actor_ip,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details,
    )
    db.add(row)
    return row
