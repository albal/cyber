"""ZAP fallback header/cookie audit — pure logic, no network."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cyberscan_worker.passive.zap_baseline import check_response  # noqa: E402


URL = "https://example.com"
GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "interest-cohort=()",
}


def _titles(hits):
    return {h.title for h in hits}


# ---------- headers -----------------------------------------------------------


def test_no_findings_when_all_headers_present():
    assert check_response(url=URL, headers=GOOD_HEADERS, cookies=[]) == []


def test_missing_csp_flagged_as_low():
    headers = dict(GOOD_HEADERS)
    headers.pop("Content-Security-Policy")
    hits = check_response(url=URL, headers=headers, cookies=[])
    assert any("Content-Security-Policy" in h.title for h in hits)
    csp_hit = next(h for h in hits if "Content-Security-Policy" in h.title)
    assert csp_hit.severity == "low"
    assert "CWE-693" in csp_hit.cwe_ids


def test_missing_xcto_flagged_as_low():
    headers = dict(GOOD_HEADERS)
    headers.pop("X-Content-Type-Options")
    hits = check_response(url=URL, headers=headers, cookies=[])
    assert any("X-Content-Type-Options" in h.title for h in hits)


def test_missing_optional_headers_are_info():
    headers = dict(GOOD_HEADERS)
    headers.pop("Referrer-Policy")
    headers.pop("Permissions-Policy")
    hits = check_response(url=URL, headers=headers, cookies=[])
    sevs = {h.severity for h in hits}
    assert sevs == {"info"}


def test_header_check_is_case_insensitive():
    headers = {k.lower(): v for k, v in GOOD_HEADERS.items()}
    assert check_response(url=URL, headers=headers, cookies=[]) == []


def test_all_headers_missing_yields_one_per_required():
    hits = check_response(url=URL, headers={}, cookies=[])
    assert len(hits) == 4
    assert all(h.target == URL for h in hits)


# ---------- cookies -----------------------------------------------------------


def test_secure_httponly_cookie_clean():
    hits = check_response(
        url=URL, headers=GOOD_HEADERS, cookies=[{"name": "sid", "secure": True, "httponly": True}]
    )
    assert hits == []


def test_cookie_missing_secure_flagged():
    hits = check_response(
        url=URL,
        headers=GOOD_HEADERS,
        cookies=[{"name": "sid", "secure": False, "httponly": True}],
    )
    assert any("Secure" in h.title for h in hits)


def test_cookie_missing_httponly_flagged():
    hits = check_response(
        url=URL,
        headers=GOOD_HEADERS,
        cookies=[{"name": "sid", "secure": True, "httponly": False}],
    )
    assert any("HttpOnly" in h.title for h in hits)


def test_cookie_missing_both_flags_listed_once_with_both_flags():
    hits = check_response(
        url=URL,
        headers=GOOD_HEADERS,
        cookies=[{"name": "sid", "secure": False, "httponly": False}],
    )
    assert len(hits) == 1
    assert "Secure" in hits[0].title and "HttpOnly" in hits[0].title
    assert "CWE-1004" in hits[0].cwe_ids


def test_multiple_cookies_each_yield_their_own_hit():
    hits = check_response(
        url=URL,
        headers=GOOD_HEADERS,
        cookies=[
            {"name": "a", "secure": False, "httponly": False},
            {"name": "b", "secure": False, "httponly": False},
        ],
    )
    assert len(hits) == 2
    assert {h.title.split("'")[1] for h in hits} == {"a", "b"}


def test_no_cookies_no_cookie_hits():
    hits = check_response(url=URL, headers=GOOD_HEADERS, cookies=None)
    assert all("Cookie" not in h.title for h in hits)
