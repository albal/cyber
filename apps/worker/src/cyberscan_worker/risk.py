"""Risk scoring + dedupe + diffing.

Composite score 0..100 = 0.45*cvss_norm + 0.25*epss_pct + 0.15*kev_bonus
                      + 0.10*exposure_factor + 0.05*exploit_avail_bonus

Severity bands: Critical>=85, High>=70, Medium>=40, Low>=15, else Info.
KEV findings are floored to High.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(slots=True)
class RiskInputs:
    cvss: float | None         # 0..10
    epss_percentile: float | None  # 0..1
    is_kev: bool
    exposure: str = "internet"  # "internet"|"auth"|"internal"
    exploit_available: str = "none"  # "weaponized"|"public"|"none"


def _exposure_factor(exposure: str) -> float:
    return {"internet": 100.0, "auth": 40.0, "internal": 10.0}.get(exposure, 60.0)


def _exploit_bonus(level: str) -> float:
    return {"weaponized": 100.0, "public": 70.0, "none": 0.0}.get(level, 0.0)


def composite_score(r: RiskInputs) -> float:
    cvss_norm = (r.cvss or 0.0) * 10.0  # 0..100
    epss_pct = (r.epss_percentile or 0.0) * 100.0
    kev_bonus = 100.0 if r.is_kev else 0.0
    score = (
        0.45 * cvss_norm
        + 0.25 * epss_pct
        + 0.15 * kev_bonus
        + 0.10 * _exposure_factor(r.exposure)
        + 0.05 * _exploit_bonus(r.exploit_available)
    )
    return max(0.0, min(100.0, score))


def severity_for(score: float, *, is_kev: bool) -> str:
    if is_kev:
        # KEV is at minimum High
        if score >= 85:
            return "critical"
        return "high"
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def dedupe_key(*, asset_id: str, template_id: str | None, cve_ids: list[str], location: str | None) -> str:
    """Stable key so re-scans don't multiply findings."""
    payload = "|".join(
        [
            asset_id,
            (template_id or ""),
            ",".join(sorted(cve_ids)),
            (location or ""),
        ]
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def diff_status(prev_keys: set[str], current_keys: set[str], key: str) -> str:
    if key in prev_keys and key in current_keys:
        return "unchanged"
    if key not in prev_keys and key in current_keys:
        return "new"
    return "fixed"
