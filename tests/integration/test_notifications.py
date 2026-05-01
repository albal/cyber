"""Notification dispatcher — formatting, severity filtering, channel routing."""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cyberscan_worker.notify import dispatcher  # noqa: E402
from cyberscan_worker.notify.dispatcher import ScanSummary, _max_sev, _summary_text  # noqa: E402


# ---------- _max_sev ----------------------------------------------------------


def test_max_sev_picks_critical_over_others():
    assert _max_sev({"critical": 1, "high": 2, "medium": 5}) == "critical"


def test_max_sev_picks_high_when_no_critical():
    assert _max_sev({"critical": 0, "high": 2, "medium": 5}) == "high"


def test_max_sev_falls_back_to_info_when_all_zero():
    assert _max_sev({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}) == "info"


def test_max_sev_handles_partial_dict():
    assert _max_sev({"low": 3}) == "low"


# ---------- _summary_text -----------------------------------------------------


def _summary(**counts):
    base = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    base.update(counts)
    return ScanSummary(
        scan_id="abc-123",
        asset_name="main-site",
        target_url="https://example.com",
        counts=base,
        new=base.get("critical", 0) + base.get("high", 0),
        fixed=0,
        top_findings=[
            ("Log4Shell", "critical", 99.7, ["CVE-2021-44228"]),
            ("Weak TLS", "medium", 55.0, []),
        ],
    )


def test_summary_text_includes_asset_url_and_id():
    text = _summary_text(_summary(critical=1, high=2))
    assert "main-site" in text
    assert "https://example.com" in text
    assert "abc-123" in text


def test_summary_text_includes_top_findings_with_cves():
    text = _summary_text(_summary(critical=1))
    assert "Log4Shell" in text
    assert "CVE-2021-44228" in text
    assert "[critical]" in text


def test_summary_text_renders_zero_counts_as_none():
    text = _summary_text(_summary())
    assert "none" in text  # "Findings — none"


def test_summary_text_truncates_top_findings_to_5():
    s = _summary(critical=1)
    s.top_findings = [(f"finding-{i}", "high", 80.0 - i, []) for i in range(20)]
    text = _summary_text(s)
    for i in range(5):
        assert f"finding-{i}" in text
    assert "finding-5" not in text


# ---------- dispatch() severity filter ---------------------------------------


class _StubResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _ChannelRow:
    def __init__(self, kind, target, min_severity, _id="ch-1"):
        self.id = _id
        self.kind = kind
        self.target = target
        self.min_severity = min_severity


class _StubDB:
    def __init__(self, channels):
        self.channels = channels

    def execute(self, *_args, **_kwargs):
        return _StubResult(self.channels)


def test_dispatch_skips_channel_below_min_severity():
    db = _StubDB([_ChannelRow("slack", "https://hooks/x", "critical")])
    summary = _summary(high=2)
    with patch.object(dispatcher, "_post_slack") as slack:
        n = dispatcher.dispatch(db, tenant_id="t", summary=summary)
    assert n == 0
    assert slack.called is False


def test_dispatch_routes_only_to_eligible_channels():
    db = _StubDB(
        [
            _ChannelRow("slack", "https://hooks/x", "high"),
            _ChannelRow("email", "ops@example.com", "critical"),
        ]
    )
    with (
        patch.object(dispatcher, "_post_slack") as slack,
        patch.object(dispatcher, "_send_email") as email,
    ):
        n = dispatcher.dispatch(db, tenant_id="t", summary=_summary(high=1))
    assert n == 1
    assert slack.called is True
    assert email.called is False


def test_dispatch_swallows_send_errors_per_channel():
    db = _StubDB(
        [
            _ChannelRow("slack", "bad-url", "info"),
            _ChannelRow("teams", "https://hooks/teams", "info"),
        ]
    )

    def boom(*args, **kwargs):
        raise RuntimeError("network blew up")

    with (
        patch.object(dispatcher, "_post_slack", side_effect=boom),
        patch.object(dispatcher, "_post_teams") as teams,
    ):
        n = dispatcher.dispatch(db, tenant_id="t", summary=_summary(high=1))
    assert n == 1
    assert teams.called is True


def test_dispatch_skips_unknown_channel_kind():
    db = _StubDB([_ChannelRow("smoke-signal", "x", "info")])
    n = dispatcher.dispatch(db, tenant_id="t", summary=_summary(critical=1))
    assert n == 0


@pytest.mark.parametrize(
    "scan_max,channel_min,should_send",
    [
        ("critical", "critical", True),
        ("critical", "high", True),
        ("critical", "info", True),
        ("high", "critical", False),
        ("high", "high", True),
        ("medium", "high", False),
        ("low", "info", True),
        ("info", "low", False),
    ],
)
def test_dispatch_threshold_matrix(scan_max: str, channel_min: str, should_send: bool):
    summary = _summary(**{scan_max: 1})
    db = _StubDB([_ChannelRow("slack", "https://hooks/x", channel_min)])
    with patch.object(dispatcher, "_post_slack") as mock_post:
        n = dispatcher.dispatch(db, tenant_id="t", summary=summary)
    assert (n == 1) is should_send
    assert mock_post.called is should_send
