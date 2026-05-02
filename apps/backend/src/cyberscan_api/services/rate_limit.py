"""Lightweight rate limiter for the login endpoint.

Backed by Redis (`INCR` + `EXPIRE` on a per-key bucket). Falls back to an
in-process dict when no Redis is configured — fine for tests, single-pod
dev, or when Redis is briefly unreachable.

The keying intentionally combines IP **and** username so a credential
stuffer can't burn a victim's account by attempting one bad password from
many IPs (would need both axes to align). The window resets on success
via `reset()`.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

import redis

from cyberscan_api.core.config import get_settings

log = logging.getLogger(__name__)


@dataclass(slots=True)
class LimitDecision:
    allowed: bool
    remaining: int
    retry_after_s: int


_LOCAL_LOCK = threading.Lock()
_LOCAL_BUCKETS: dict[str, tuple[int, float]] = {}


def _redis_client() -> redis.Redis | None:
    s = get_settings()
    if not s.redis_url:
        return None
    try:
        c = redis.Redis.from_url(s.redis_url, decode_responses=True)
        c.ping()
        return c
    except Exception as exc:  # noqa: BLE001
        log.warning("rate-limit Redis unavailable, falling back to in-process: %s", exc)
        return None


def check(*, key: str, max_attempts: int, window_s: int, now: float | None = None) -> LimitDecision:
    """Increment the counter under `key`. Returns a LimitDecision."""
    client = _redis_client()
    if client is not None:
        return _check_redis(client, key, max_attempts, window_s)
    return _check_local(key, max_attempts, window_s, now)


def reset(*, key: str) -> None:
    """Clear the counter (e.g., on successful login)."""
    client = _redis_client()
    if client is not None:
        try:
            client.delete(_redis_key(key))
            return
        except Exception:  # noqa: BLE001
            pass
    with _LOCAL_LOCK:
        _LOCAL_BUCKETS.pop(key, None)


# ---------- backends ---------------------------------------------------------


def _redis_key(key: str) -> str:
    return f"cyberscan:ratelimit:{key}"


def _check_redis(client: redis.Redis, key: str, max_attempts: int, window_s: int) -> LimitDecision:
    rkey = _redis_key(key)
    pipe = client.pipeline()
    pipe.incr(rkey)
    pipe.ttl(rkey)
    count, ttl = pipe.execute()
    if ttl is None or ttl < 0:
        # First hit — set the window.
        client.expire(rkey, window_s)
        ttl = window_s
    remaining = max(0, max_attempts - int(count))
    return LimitDecision(allowed=int(count) <= max_attempts, remaining=remaining, retry_after_s=int(ttl))


def _check_local(key: str, max_attempts: int, window_s: int, now: float | None) -> LimitDecision:
    t = now if now is not None else time.monotonic()
    with _LOCAL_LOCK:
        count, expires_at = _LOCAL_BUCKETS.get(key, (0, 0.0))
        if t >= expires_at:
            count, expires_at = 0, t + window_s
        count += 1
        _LOCAL_BUCKETS[key] = (count, expires_at)
        ttl = max(0, int(expires_at - t))
    remaining = max(0, max_attempts - count)
    return LimitDecision(allowed=count <= max_attempts, remaining=remaining, retry_after_s=ttl)


def _clear_local() -> None:
    """Test helper — wipe the in-process bucket."""
    with _LOCAL_LOCK:
        _LOCAL_BUCKETS.clear()
