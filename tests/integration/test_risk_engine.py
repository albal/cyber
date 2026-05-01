"""Risk engine: composite score, severity bands, dedupe, diff."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cyberscan_worker.risk import (  # noqa: E402
    RiskInputs,
    composite_score,
    dedupe_key,
    diff_status,
    severity_for,
)


# ---------- composite_score ---------------------------------------------------


def test_score_clamps_to_max():
    s = composite_score(
        RiskInputs(cvss=10.0, epss_percentile=1.0, is_kev=True, exposure="internet", exploit_available="weaponized")
    )
    assert s == pytest.approx(100.0, abs=1.0)


def test_score_clamps_to_min():
    s = composite_score(
        RiskInputs(cvss=None, epss_percentile=None, is_kev=False, exposure="internal")
    )
    assert s == pytest.approx(1.0, abs=2.0)


def test_score_kev_only_floor_high():
    """KEV with low CVSS still maps to High via severity_for floor."""
    s = composite_score(RiskInputs(cvss=2.0, epss_percentile=0.0, is_kev=True))
    assert severity_for(s, is_kev=True) in {"high", "critical"}


def test_score_no_kev_low_cvss_is_low():
    s = composite_score(RiskInputs(cvss=2.0, epss_percentile=0.0, is_kev=False, exposure="internal"))
    assert severity_for(s, is_kev=False) in {"info", "low"}


def test_score_increases_with_kev():
    base = RiskInputs(cvss=7.5, epss_percentile=0.5, is_kev=False)
    bumped = RiskInputs(cvss=7.5, epss_percentile=0.5, is_kev=True)
    assert composite_score(bumped) > composite_score(base)


def test_score_increases_with_higher_cvss():
    a = composite_score(RiskInputs(cvss=4.0, epss_percentile=0.0, is_kev=False))
    b = composite_score(RiskInputs(cvss=9.0, epss_percentile=0.0, is_kev=False))
    assert b > a


def test_score_increases_with_higher_epss():
    a = composite_score(RiskInputs(cvss=5.0, epss_percentile=0.05, is_kev=False))
    b = composite_score(RiskInputs(cvss=5.0, epss_percentile=0.95, is_kev=False))
    assert b > a


def test_exposure_factor_internet_higher_than_internal():
    a = composite_score(RiskInputs(cvss=5.0, epss_percentile=0.5, is_kev=False, exposure="internet"))
    b = composite_score(RiskInputs(cvss=5.0, epss_percentile=0.5, is_kev=False, exposure="internal"))
    assert a > b


def test_exposure_factor_unknown_falls_back():
    s = composite_score(RiskInputs(cvss=5.0, epss_percentile=0.5, is_kev=False, exposure="bogus"))
    assert 0.0 <= s <= 100.0


def test_exploit_available_bumps_score():
    base = RiskInputs(cvss=5.0, epss_percentile=0.5, is_kev=False, exploit_available="none")
    pub = RiskInputs(cvss=5.0, epss_percentile=0.5, is_kev=False, exploit_available="public")
    weap = RiskInputs(cvss=5.0, epss_percentile=0.5, is_kev=False, exploit_available="weaponized")
    assert composite_score(weap) > composite_score(pub) > composite_score(base)


# ---------- severity_for ------------------------------------------------------


@pytest.mark.parametrize(
    "score,expected",
    [
        (100.0, "critical"),
        (85.0, "critical"),
        (84.99, "high"),
        (70.0, "high"),
        (69.99, "medium"),
        (40.0, "medium"),
        (39.99, "low"),
        (15.0, "low"),
        (14.99, "info"),
        (0.0, "info"),
    ],
)
def test_severity_bands_non_kev(score: float, expected: str):
    assert severity_for(score, is_kev=False) == expected


def test_severity_kev_floor_at_high():
    """Even a tiny score is at least High for KEV CVEs."""
    assert severity_for(0.0, is_kev=True) == "high"
    assert severity_for(50.0, is_kev=True) == "high"
    assert severity_for(70.0, is_kev=True) == "high"


def test_severity_kev_can_still_be_critical():
    assert severity_for(95.0, is_kev=True) == "critical"


# ---------- dedupe_key --------------------------------------------------------


def test_dedupe_stable_under_cve_reorder():
    a = dedupe_key(asset_id="a", template_id="t", cve_ids=["CVE-1", "CVE-2"], location="L")
    b = dedupe_key(asset_id="a", template_id="t", cve_ids=["CVE-2", "CVE-1"], location="L")
    assert a == b


def test_dedupe_changes_on_template_id():
    a = dedupe_key(asset_id="a", template_id="t1", cve_ids=[], location="L")
    b = dedupe_key(asset_id="a", template_id="t2", cve_ids=[], location="L")
    assert a != b


def test_dedupe_changes_on_location():
    a = dedupe_key(asset_id="a", template_id="t", cve_ids=[], location="/admin")
    b = dedupe_key(asset_id="a", template_id="t", cve_ids=[], location="/login")
    assert a != b


def test_dedupe_changes_across_assets():
    a = dedupe_key(asset_id="asset-1", template_id="t", cve_ids=[], location="L")
    b = dedupe_key(asset_id="asset-2", template_id="t", cve_ids=[], location="L")
    assert a != b


def test_dedupe_handles_none_template_and_location():
    k = dedupe_key(asset_id="a", template_id=None, cve_ids=[], location=None)
    assert isinstance(k, str) and len(k) == 32


def test_dedupe_returns_32_char_hex():
    k = dedupe_key(asset_id="a", template_id="t", cve_ids=["CVE-1"], location="L")
    assert len(k) == 32
    int(k, 16)  # well-formed hex


# ---------- diff_status -------------------------------------------------------


def test_diff_status_new():
    assert diff_status(prev_keys=set(), current_keys={"k"}, key="k") == "new"


def test_diff_status_unchanged():
    assert diff_status(prev_keys={"k"}, current_keys={"k"}, key="k") == "unchanged"


def test_diff_status_fixed():
    assert diff_status(prev_keys={"k"}, current_keys=set(), key="k") == "fixed"
