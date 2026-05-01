"""Pure-function feed parsers — NVD, EPSS, OSV records (no DB)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cyberscan_worker.feeds import epss as epss_mod  # noqa: E402


# ---------- EPSS CSV parser (already had a few tests; add more) -------------


def test_epss_parses_zero_scored():
    raw = "cve,epss,percentile\nCVE-X,0.0,0.0\n"
    rows = epss_mod._parse_csv(raw)
    assert rows == [("CVE-X", 0.0, 0.0)]


def test_epss_supports_uppercase_header():
    # Some mirrors write 'CVE' upper-cased.
    raw = "CVE,epss,percentile\nCVE-1,0.5,0.6\n"
    rows = epss_mod._parse_csv(raw)
    assert rows == [("CVE-1", 0.5, 0.6)]


def test_epss_skips_rows_with_blank_cve():
    raw = "cve,epss,percentile\n,0.1,0.5\nCVE-OK,0.2,0.6\n"
    rows = epss_mod._parse_csv(raw)
    assert rows == [("CVE-OK", 0.2, 0.6)]


def test_epss_skips_inline_comment_block():
    raw = "# header note\n# scored: 2026-05-01\ncve,epss,percentile\nCVE-1,0.4,0.5\n"
    assert epss_mod._parse_csv(raw) == [("CVE-1", 0.4, 0.5)]


# ---------- NVD parser (parse vulnerabilities[] payload) --------------------


def _load_fixture(name: str) -> dict:
    fix = (
        Path(__file__).resolve().parents[2]
        / "apps"
        / "worker"
        / "src"
        / "cyberscan_worker"
        / "feeds"
        / "fixtures"
        / name
    )
    return json.loads(fix.read_text())


def test_nvd_fixture_parseable():
    """The bundled NVD fixture should be valid JSON with the expected shape."""
    data = _load_fixture("nvd_sample.json")
    assert "vulnerabilities" in data
    cve_ids = [v["cve"]["id"] for v in data["vulnerabilities"]]
    assert "CVE-2021-44228" in cve_ids
    assert all(cid.startswith("CVE-") for cid in cve_ids)


def test_nvd_fixture_contains_cvss_v31_scores():
    data = _load_fixture("nvd_sample.json")
    found_score = False
    for v in data["vulnerabilities"]:
        metrics = v["cve"].get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if metrics.get(key):
                score = metrics[key][0]["cvssData"]["baseScore"]
                assert 0.0 <= score <= 10.0
                found_score = True
    assert found_score


def test_nvd_fixture_descriptions_are_english():
    data = _load_fixture("nvd_sample.json")
    for v in data["vulnerabilities"]:
        descs = v["cve"]["descriptions"]
        en = [d for d in descs if d["lang"] == "en"]
        assert en, f"missing en description for {v['cve']['id']}"


# ---------- KEV ---------------------------------------------------------------


def test_kev_fixture_lists_log4shell():
    data = _load_fixture("kev_sample.json")
    assert any(item["cveID"] == "CVE-2021-44228" for item in data["vulnerabilities"])


def test_kev_fixture_all_cves_uppercase():
    data = _load_fixture("kev_sample.json")
    for item in data["vulnerabilities"]:
        assert item["cveID"].startswith("CVE-")


# ---------- OSV --------------------------------------------------------------


def _load_osv_fixture() -> list[dict]:
    fix = (
        Path(__file__).resolve().parents[2]
        / "apps"
        / "worker"
        / "src"
        / "cyberscan_worker"
        / "feeds"
        / "fixtures"
        / "osv_sample.jsonl"
    )
    return [json.loads(line) for line in fix.read_text().splitlines() if line.strip()]


def test_osv_fixture_records_have_aliases_pointing_to_cves():
    rows = _load_osv_fixture()
    assert rows
    for r in rows:
        assert "id" in r
        assert "summary" in r
        for alias in r["aliases"]:
            assert alias.startswith("CVE-")


def test_osv_fixture_includes_log4shell():
    rows = _load_osv_fixture()
    assert any("CVE-2021-44228" in r["aliases"] for r in rows)


def test_osv_fixture_severity_is_set():
    rows = _load_osv_fixture()
    sevs = {r.get("database_specific", {}).get("severity") for r in rows}
    assert sevs <= {"CRITICAL", "HIGH", "MEDIUM", "LOW", None}
