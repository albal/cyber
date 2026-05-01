"""Pydantic schema validation — positive and negative cases."""
import sys
import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "backend" / "src"))

from cyberscan_api.schemas import (  # noqa: E402
    ApiTokenCreate,
    AssetCreate,
    AssetSchedule,
    NotificationChannelCreate,
    ScanCreate,
)


# ---------- AssetCreate -------------------------------------------------------


def test_asset_create_accepts_http_url():
    a = AssetCreate(name="x", target_url="http://example.com")
    assert str(a.target_url).startswith("http://")
    assert a.verification_method == "http_file"


def test_asset_create_accepts_https_with_port_and_path():
    a = AssetCreate(name="x", target_url="https://app.example.com:8443/health")
    assert "app.example.com" in str(a.target_url)


def test_asset_create_accepts_single_label_with_port():
    AssetCreate(name="x", target_url="http://juice-shop:3000")


def test_asset_create_rejects_non_url():
    with pytest.raises(ValidationError):
        AssetCreate(name="x", target_url="not-a-url")


def test_asset_create_rejects_blank_name():
    with pytest.raises(ValidationError):
        AssetCreate(name="", target_url="http://e.com")


def test_asset_create_default_verification_method():
    a = AssetCreate(name="x", target_url="http://e.com")
    assert a.verification_method == "http_file"


def test_asset_create_accepts_known_methods():
    for m in ("http_file", "dns_txt", "http_header"):
        AssetCreate(name="x", target_url="http://e.com", verification_method=m)


def test_asset_create_rejects_unknown_method():
    with pytest.raises(ValidationError):
        AssetCreate(name="x", target_url="http://e.com", verification_method="carrier-pigeon")


# ---------- AssetSchedule -----------------------------------------------------


def test_asset_schedule_default_disabled():
    s = AssetSchedule()
    assert s.schedule_cron is None
    assert s.schedule_enabled is False


def test_asset_schedule_accepts_cron_string():
    s = AssetSchedule(schedule_cron="0 6 * * 1", schedule_enabled=True)
    assert s.schedule_enabled is True


# ---------- ScanCreate --------------------------------------------------------


def test_scan_create_requires_asset_id_uuid():
    s = ScanCreate(asset_id=uuid.uuid4())
    assert isinstance(s.asset_id, uuid.UUID)
    assert s.intrusive is False  # default


def test_scan_create_rejects_non_uuid():
    with pytest.raises(ValidationError):
        ScanCreate(asset_id="not-a-uuid")


def test_scan_create_intrusive_optional():
    s = ScanCreate(asset_id=uuid.uuid4(), intrusive=True)
    assert s.intrusive is True


# ---------- NotificationChannelCreate ----------------------------------------


@pytest.mark.parametrize("kind", ["email", "slack", "teams"])
def test_notification_kind_accepts_valid(kind: str):
    c = NotificationChannelCreate(kind=kind, target="x@example.com")
    assert c.kind == kind


def test_notification_kind_rejects_invalid():
    with pytest.raises(ValidationError):
        NotificationChannelCreate(kind="discord", target="x")


@pytest.mark.parametrize("sev", ["critical", "high", "medium", "low", "info"])
def test_notification_min_severity_accepts(sev: str):
    NotificationChannelCreate(kind="email", target="x@example.com", min_severity=sev)


def test_notification_min_severity_rejects_unknown():
    with pytest.raises(ValidationError):
        NotificationChannelCreate(kind="email", target="x@e.com", min_severity="urgent")


def test_notification_min_severity_default_high():
    c = NotificationChannelCreate(kind="email", target="x@e.com")
    assert c.min_severity == "high"


# ---------- ApiTokenCreate ----------------------------------------------------


def test_api_token_create_name_required():
    with pytest.raises(ValidationError):
        ApiTokenCreate(name="")


def test_api_token_create_name_max_len():
    with pytest.raises(ValidationError):
        ApiTokenCreate(name="x" * 200)


def test_api_token_create_accepts_normal_name():
    t = ApiTokenCreate(name="github-actions")
    assert t.name == "github-actions"
