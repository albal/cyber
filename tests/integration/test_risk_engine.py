"""Pure-python tests for the risk engine — no infra needed."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cyberscan_worker.risk import (  # noqa: E402
    RiskInputs,
    composite_score,
    dedupe_key,
    severity_for,
)


def test_score_critical_kev():
    s = composite_score(RiskInputs(cvss=10.0, epss_percentile=0.99, is_kev=True, exposure="internet", exploit_available="weaponized"))
    assert s >= 85
    assert severity_for(s, is_kev=True) == "critical"


def test_score_low_internal():
    s = composite_score(RiskInputs(cvss=3.5, epss_percentile=0.05, is_kev=False, exposure="internal"))
    assert s < 40
    # KEV floors to High; non-KEV stays low
    assert severity_for(s, is_kev=False) in {"low", "info", "medium"}


def test_kev_floors_to_high():
    s = composite_score(RiskInputs(cvss=2.0, epss_percentile=0.0, is_kev=True, exposure="internal"))
    # KEV inputs always map to at least High
    assert severity_for(s, is_kev=True) in {"high", "critical"}


def test_dedupe_key_stable():
    a = dedupe_key(asset_id="a1", template_id="t1", cve_ids=["CVE-2023-0001", "CVE-2024-0002"], location="https://x/y")
    b = dedupe_key(asset_id="a1", template_id="t1", cve_ids=["CVE-2024-0002", "CVE-2023-0001"], location="https://x/y")
    assert a == b
    c = dedupe_key(asset_id="a1", template_id="t1", cve_ids=[], location="https://x/y")
    assert a != c
