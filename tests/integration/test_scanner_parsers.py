"""Pure-function parsers for naabu / httpx / nuclei JSONL output."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "worker" / "src"))

from cyberscan_worker.recon import httpx_probe, katana, naabu  # noqa: E402
from cyberscan_worker.vuln import nuclei  # noqa: E402


# ---------- naabu -------------------------------------------------------------


def test_naabu_parses_multiple_lines():
    raw = "\n".join(
        [
            json.dumps({"host": "example.com", "ip": "1.2.3.4", "port": 80}),
            json.dumps({"host": "example.com", "ip": "1.2.3.4", "port": 443}),
            "",
            json.dumps({"host": "example.com", "ip": "1.2.3.4", "port": 8080}),
        ]
    )
    ports = naabu.parse(raw, fallback_host="example.com")
    assert [(p.host, p.port) for p in ports] == [
        ("example.com", 80),
        ("example.com", 443),
        ("example.com", 8080),
    ]


def test_naabu_skips_malformed_lines():
    raw = "{not json}\n" + json.dumps({"host": "h", "port": 80}) + "\nbadtail"
    ports = naabu.parse(raw, fallback_host="h")
    assert len(ports) == 1
    assert ports[0].port == 80


def test_naabu_falls_back_to_provided_host_when_missing():
    raw = json.dumps({"port": 22})
    ports = naabu.parse(raw, fallback_host="default.example")
    assert ports[0].host == "default.example"


def test_naabu_skips_rows_without_int_port():
    raw = json.dumps({"host": "h", "port": "twenty-two"})
    assert naabu.parse(raw) == []


def test_naabu_empty_input():
    assert naabu.parse("") == []


# ---------- httpx -------------------------------------------------------------


def test_httpx_parses_full_record():
    raw = json.dumps(
        {
            "url": "https://example.com/",
            "status_code": 200,
            "title": "Example",
            "tech": ["nginx", "react"],
            "webserver": "nginx/1.27",
        }
    )
    services = httpx_probe.parse(raw)
    assert len(services) == 1
    s = services[0]
    assert s.url == "https://example.com/"
    assert s.status == 200
    assert s.title == "Example"
    assert s.tech == ["nginx", "react"]
    assert s.webserver == "nginx/1.27"
    assert s.tls is True


def test_httpx_treats_http_as_non_tls():
    raw = json.dumps({"url": "http://example.com", "status_code": 200})
    services = httpx_probe.parse(raw)
    assert services[0].tls is False


def test_httpx_handles_dashed_status_field():
    raw = json.dumps({"url": "http://e", "status-code": 301})
    assert httpx_probe.parse(raw)[0].status == 301


def test_httpx_handles_technologies_alias():
    raw = json.dumps({"url": "http://e", "technologies": ["express"]})
    assert httpx_probe.parse(raw)[0].tech == ["express"]


def test_httpx_skips_rows_missing_url():
    raw = json.dumps({"status_code": 200})
    assert httpx_probe.parse(raw) == []


def test_httpx_uses_input_when_url_missing():
    raw = json.dumps({"input": "http://fallback.example/", "status_code": 200})
    assert httpx_probe.parse(raw)[0].url == "http://fallback.example/"


# ---------- nuclei ------------------------------------------------------------


def test_nuclei_parses_minimal_hit():
    raw = json.dumps(
        {
            "template-id": "exposed-panel/admin",
            "info": {"name": "Exposed Admin Panel", "severity": "medium"},
            "matched-at": "https://example.com/admin",
        }
    )
    hits = nuclei.parse(raw)
    assert len(hits) == 1
    h = hits[0]
    assert h.template_id == "exposed-panel/admin"
    assert h.name == "Exposed Admin Panel"
    assert h.severity == "medium"
    assert h.matched_at == "https://example.com/admin"
    assert h.cve_ids == []


def test_nuclei_extracts_cve_and_cwe():
    raw = json.dumps(
        {
            "template-id": "log4shell",
            "info": {
                "name": "Log4Shell",
                "severity": "critical",
                "classification": {
                    "cve-id": ["cve-2021-44228"],
                    "cwe-id": ["cwe-502"],
                    "cvss-score": 10.0,
                },
            },
            "matched-at": "https://example.com",
        }
    )
    h = nuclei.parse(raw)[0]
    assert h.cve_ids == ["CVE-2021-44228"]
    assert h.cwe_ids == ["CWE-502"]
    assert h.cvss_score == 10.0


def test_nuclei_promotes_string_cve_to_list():
    raw = json.dumps(
        {
            "template-id": "x",
            "info": {
                "name": "x",
                "severity": "high",
                "classification": {"cve-id": "cve-2024-0001", "cwe-id": "cwe-79"},
            },
        }
    )
    h = nuclei.parse(raw)[0]
    assert h.cve_ids == ["CVE-2024-0001"]
    assert h.cwe_ids == ["CWE-79"]


def test_nuclei_falls_back_severity_to_info():
    raw = json.dumps({"template-id": "x", "info": {"name": "x"}})
    assert nuclei.parse(raw)[0].severity == "info"


def test_nuclei_truncates_response_excerpt_to_2000_bytes():
    raw = json.dumps({"template-id": "x", "info": {"name": "x"}, "response": "A" * 5000})
    h = nuclei.parse(raw)[0]
    assert h.response_excerpt is not None
    assert len(h.response_excerpt) == 2000


def test_nuclei_handles_empty_input():
    assert nuclei.parse("") == []


def test_nuclei_skips_malformed_lines():
    good = json.dumps({"template-id": "x", "info": {"name": "x", "severity": "low"}})
    raw = "garbage\n" + good + "\n{also bad"
    assert len(nuclei.parse(raw)) == 1


# ---------- shard helper ------------------------------------------------------


def test_shard_returns_single_bucket_when_below_threshold():
    assert nuclei.shard(["a", "b"], shards=4) == [["a", "b"]]


def test_shard_distributes_round_robin():
    buckets = nuclei.shard(["a", "b", "c", "d", "e"], shards=2)
    assert {tuple(b) for b in buckets} == {("a", "c", "e"), ("b", "d")}


def test_shard_skips_empty_buckets():
    """If shards exceeds targets, only non-empty lists come back."""
    out = nuclei.shard(["x", "y"], shards=10)
    assert out == [["x", "y"]] or all(len(b) > 0 for b in out)


# ---------- katana ------------------------------------------------------------


def test_katana_parses_request_endpoint_field():
    raw = "\n".join(
        [
            json.dumps(
                {
                    "request": {"endpoint": "https://example.com/api/Users", "method": "GET"},
                    "response": {"status_code": 200},
                }
            ),
            json.dumps(
                {
                    "request": {"endpoint": "https://example.com/rest/products", "method": "POST"},
                    "response": {"status_code": 405},
                }
            ),
        ]
    )
    found = katana.parse(raw)
    urls = [c.url for c in found]
    methods = {(c.url, c.method) for c in found}
    assert "https://example.com/api/Users" in urls
    assert ("https://example.com/rest/products", "POST") in methods


def test_katana_dedupes_repeated_urls():
    line = json.dumps({"request": {"endpoint": "https://x/y", "method": "GET"}})
    raw = "\n".join([line, line, line])
    assert len(katana.parse(raw)) == 1


def test_katana_includes_seeds_even_when_jsonl_is_empty():
    out = katana.parse("", seeds=["https://example.com/", "https://example.com/login"])
    urls = [c.url for c in out]
    assert urls == ["https://example.com/", "https://example.com/login"]


def test_katana_skips_malformed_lines_and_missing_endpoints():
    raw = "garbage\n" + json.dumps({"timestamp": "now"}) + "\n" + json.dumps(
        {"request": {"endpoint": "https://x/ok"}}
    )
    assert [c.url for c in katana.parse(raw)] == ["https://x/ok"]


def test_katana_exposes_response_status_when_present():
    raw = json.dumps(
        {"request": {"endpoint": "https://x/y"}, "response": {"status_code": "404"}}
    )
    out = katana.parse(raw)
    assert out[0].status == 404


def test_katana_seeds_come_first_in_output():
    raw = json.dumps({"request": {"endpoint": "https://x/discovered"}})
    out = katana.parse(raw, seeds=["https://x/seed"])
    assert [c.url for c in out] == ["https://x/seed", "https://x/discovered"]


# ---------- nuclei coverage knobs --------------------------------------------


def test_nuclei_run_signature_accepts_tags():
    """Calling shape — make sure callers can pass tags=() through to the CLI builder."""
    import inspect

    sig = inspect.signature(nuclei.run)
    assert "tags" in sig.parameters
    assert "severities" in sig.parameters


def test_nuclei_default_severities_now_include_info():
    """Info-level templates (tech detection, fingerprinting) help triage even
    when no high-severity vulns are found, so they should be on by default."""
    import inspect

    default = inspect.signature(nuclei.run).parameters["severities"].default
    assert "info" in default


def test_nuclei_default_tags_cover_common_categories():
    import inspect

    default = inspect.signature(nuclei.run).parameters["tags"].default
    expected = {"cve", "exposure", "misconfig", "tech", "default-login"}
    assert expected.issubset(set(default))
