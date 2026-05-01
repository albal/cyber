"""Cron 'is due' helper for the scheduler — pure logic, no DB."""
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

import pytest

try:
    from cyberscan_worker.scheduler import _is_due  # noqa: E402
except ModuleNotFoundError:  # croniter not installed in CI host venv
    pytest.skip("croniter unavailable", allow_module_level=True)


def _now(year=2026, month=5, day=4, hour=6, minute=0):
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def test_due_when_cron_matches_minute_and_no_prior_run():
    now = _now()  # Mon 2026-05-04 06:00 UTC
    assert _is_due("0 6 * * 1", now, last_at=None) is True


def test_not_due_when_already_fired_in_same_minute():
    now = _now()
    assert _is_due("0 6 * * 1", now, last_at=now) is False


def test_not_due_when_cron_does_not_match_minute():
    now = _now(hour=7)  # 07:00 — cron asks for 06:00
    assert _is_due("0 6 * * 1", now, last_at=None) is False


def test_due_again_in_a_later_minute_with_old_last_at():
    now = _now()
    last = now - timedelta(days=7)  # last fire was a week ago
    assert _is_due("0 6 * * 1", now, last_at=last) is True


def test_invalid_cron_returns_false():
    assert _is_due("not-a-cron", _now(), last_at=None) is False
