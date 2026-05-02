"""Login rate-limiter — in-process backend (Redis path is integration-only)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure no Redis is attempted during these tests.
os.environ["REDIS_URL"] = ""

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.core.config import get_settings  # noqa: E402

get_settings.cache_clear()  # type: ignore[attr-defined]

from cyberscan_api.services import rate_limit  # noqa: E402


@pytest.fixture(autouse=True)
def _wipe_local_buckets():
    rate_limit._clear_local()
    yield
    rate_limit._clear_local()


def test_first_attempt_is_allowed():
    d = rate_limit.check(key="k", max_attempts=3, window_s=60, now=1000.0)
    assert d.allowed is True
    assert d.remaining == 2
    assert d.retry_after_s == 60


def test_blocks_after_max_attempts():
    for _ in range(3):
        rate_limit.check(key="k", max_attempts=3, window_s=60, now=1000.0)
    d = rate_limit.check(key="k", max_attempts=3, window_s=60, now=1000.5)
    assert d.allowed is False
    assert d.remaining == 0
    assert d.retry_after_s > 0


def test_window_resets_after_expiry():
    for _ in range(5):
        rate_limit.check(key="k", max_attempts=3, window_s=60, now=1000.0)
    # 61s later, the window should have rolled over.
    d = rate_limit.check(key="k", max_attempts=3, window_s=60, now=1061.0)
    assert d.allowed is True
    assert d.remaining == 2


def test_distinct_keys_have_independent_buckets():
    for _ in range(5):
        rate_limit.check(key="alice", max_attempts=3, window_s=60, now=1000.0)
    d = rate_limit.check(key="bob", max_attempts=3, window_s=60, now=1000.0)
    assert d.allowed is True


def test_reset_clears_the_counter():
    for _ in range(3):
        rate_limit.check(key="k", max_attempts=3, window_s=60, now=1000.0)
    blocked = rate_limit.check(key="k", max_attempts=3, window_s=60, now=1000.5)
    assert blocked.allowed is False
    rate_limit.reset(key="k")
    after = rate_limit.check(key="k", max_attempts=3, window_s=60, now=1001.0)
    assert after.allowed is True
    assert after.remaining == 2


def test_remaining_counts_down_correctly():
    a = rate_limit.check(key="k", max_attempts=5, window_s=60, now=1000.0)
    b = rate_limit.check(key="k", max_attempts=5, window_s=60, now=1000.0)
    c = rate_limit.check(key="k", max_attempts=5, window_s=60, now=1000.0)
    assert (a.remaining, b.remaining, c.remaining) == (4, 3, 2)


def test_max_attempts_one_blocks_immediately_on_second_try():
    a = rate_limit.check(key="k", max_attempts=1, window_s=60, now=1000.0)
    b = rate_limit.check(key="k", max_attempts=1, window_s=60, now=1000.5)
    assert a.allowed is True
    assert b.allowed is False
