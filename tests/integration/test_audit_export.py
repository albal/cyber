"""Audit-log row serializer — unit-level, no DB."""
from __future__ import annotations

import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.routers.audit import _COLUMNS, _serialize  # noqa: E402


class _Row:
    def __init__(self, **kwargs):
        for k in _COLUMNS:
            setattr(self, k, kwargs.get(k))


def test_serializer_includes_every_column():
    row = _Row(
        id=uuid.uuid4(),
        created_at=datetime(2026, 5, 1, 12, 0, tzinfo=UTC),
        actor_user_id=uuid.uuid4(),
        actor_ip="10.0.0.1",
        action="asset.create",
        target_type="asset",
        target_id=str(uuid.uuid4()),
        details={"hostname": "x.example"},
    )
    out = _serialize(row)
    assert set(out.keys()) == set(_COLUMNS)


def test_serializer_renders_datetime_as_iso():
    row = _Row(
        created_at=datetime(2026, 5, 1, 12, 0, tzinfo=UTC),
        action="x",
        details=None,
    )
    out = _serialize(row)
    assert out["created_at"] == "2026-05-01T12:00:00+00:00"


def test_serializer_passes_details_through_as_dict():
    row = _Row(action="x", details={"k": 1, "list": [1, 2]})
    out = _serialize(row)
    assert out["details"] == {"k": 1, "list": [1, 2]}


def test_serializer_keeps_none_for_missing_optional_fields():
    row = _Row(action="x", details=None)
    out = _serialize(row)
    assert out["actor_user_id"] is None
    assert out["actor_ip"] is None
    assert out["details"] is None


def test_serializer_stringifies_uuids():
    user_id = uuid.uuid4()
    row = _Row(action="x", actor_user_id=user_id, details=None)
    out = _serialize(row)
    assert out["actor_user_id"] == str(user_id)
