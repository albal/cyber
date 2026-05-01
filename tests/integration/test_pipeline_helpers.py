"""Pipeline-adjacent helpers: dedupe collisions and severity bands matrix."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cyberscan_worker.risk import (  # noqa: E402
    RiskInputs,
    composite_score,
    dedupe_key,
    severity_for,
)


def test_dedupe_does_not_collide_on_unique_inputs():
    """Generate 1000 unique (asset, template, location) tuples and verify
    every dedupe key is distinct."""
    keys = set()
    for i in range(1000):
        keys.add(
            dedupe_key(
                asset_id=f"asset-{i % 100}",
                template_id=f"tpl-{i // 100}",
                cve_ids=[f"CVE-{2026}-{i:05d}"],
                location=f"https://example.com/path-{i}",
            )
        )
    assert len(keys) == 1000


def test_dedupe_repeats_on_identical_inputs():
    a = dict(asset_id="a", template_id="t", cve_ids=["CVE-1"], location="L")
    assert dedupe_key(**a) == dedupe_key(**a)


def test_dedupe_changes_on_cve_set_change():
    a = dedupe_key(asset_id="a", template_id="t", cve_ids=["CVE-1"], location="L")
    b = dedupe_key(asset_id="a", template_id="t", cve_ids=["CVE-1", "CVE-2"], location="L")
    assert a != b


def test_severity_for_full_band_matrix_no_kev():
    bands = {0: "info", 14: "info", 15: "low", 39: "low", 40: "medium",
             69: "medium", 70: "high", 84: "high", 85: "critical", 100: "critical"}
    for score, expected in bands.items():
        assert severity_for(float(score), is_kev=False) == expected, score


def test_severity_for_kev_floor_matrix():
    """Below the High band, KEV pulls everything up to High; at or above High,
    the natural band applies."""
    cases = {
        0.0: "high",
        14.99: "high",
        50.0: "high",
        70.0: "high",
        84.99: "high",
        85.0: "critical",
        100.0: "critical",
    }
    for score, expected in cases.items():
        assert severity_for(score, is_kev=True) == expected


def test_composite_score_monotonic_in_cvss():
    last = -1.0
    for cvss in (0.0, 2.0, 4.0, 6.0, 8.0, 10.0):
        s = composite_score(RiskInputs(cvss=cvss, epss_percentile=0.0, is_kev=False))
        assert s >= last
        last = s


def test_composite_score_monotonic_in_epss():
    last = -1.0
    for pct in (0.0, 0.1, 0.5, 0.9, 1.0):
        s = composite_score(RiskInputs(cvss=5.0, epss_percentile=pct, is_kev=False))
        assert s >= last
        last = s


def test_composite_score_internet_exposure_dominates_internal():
    a = composite_score(RiskInputs(cvss=5.0, epss_percentile=0.5, is_kev=False, exposure="internet"))
    b = composite_score(RiskInputs(cvss=5.0, epss_percentile=0.5, is_kev=False, exposure="internal"))
    # 0.10 * (100 - 10) / 100 = 9 point swing
    assert (a - b) > 5.0
