import csv
import io
import json

from conftest import result

from intelscope.export import infer_format, stix_pattern, to_csv, to_html, to_json, to_stix
from intelscope.models import IOC, EnrichedIOC, IOCType, Verdict


def item(value, kind, verdict, score=0, original=None, results=None):
    return EnrichedIOC(IOC(value, kind, original or value), results or [], score, verdict,
                       [f"vt: {verdict.value}"])


ITEMS = [
    item("1.2.3.4", IOCType.IPV4, Verdict.MALICIOUS, 95, results=[result("virustotal", 95)]),
    item("evil.test", IOCType.DOMAIN, Verdict.SUSPICIOUS, 45),
    item("8.8.8.8", IOCType.IPV4, Verdict.BENIGN),
]


def test_stix_patterns():
    assert stix_pattern(ITEMS[0]) == "[ipv4-addr:value = '1.2.3.4']"
    sha = item("a" * 64, IOCType.SHA256, Verdict.MALICIOUS)
    assert stix_pattern(sha) == f"[file:hashes.'SHA-256' = '{'a' * 64}']"
    md5 = item("b" * 32, IOCType.MD5, Verdict.MALICIOUS)
    assert stix_pattern(md5) == f"[file:hashes.MD5 = '{'b' * 32}']"
    tricky = item("http://x.test/a'b\\c", IOCType.URL, Verdict.MALICIOUS)
    assert stix_pattern(tricky) == "[url:value = 'http://x.test/a\\'b\\\\c']"


def test_stix_bundle_only_actionable_and_deterministic_ids():
    bundle = json.loads(to_stix(ITEMS))
    assert bundle["type"] == "bundle"
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 2
    assert indicators[0]["indicator_types"] == ["malicious-activity"]
    assert indicators[1]["indicator_types"] == ["anomalous-activity"]
    assert indicators[0]["created"].endswith("Z") and len(indicators[0]["created"]) == 24
    again = json.loads(to_stix(ITEMS))
    assert again["objects"][1]["id"] == bundle["objects"][1]["id"]


def test_csv_neutralises_formula_injection():
    evil = item("=cmd|' /C calc'!A0", IOCType.DOMAIN, Verdict.UNKNOWN)
    rows = list(csv.reader(io.StringIO(to_csv([evil, *ITEMS]))))
    assert rows[0][:4] == ["indicator", "type", "verdict", "score"]
    assert rows[1][0].startswith("'=")
    assert rows[2][-1] == "x"  # per-provider summary column


def test_json_round_trip():
    doc = json.loads(to_json(ITEMS))
    assert doc["count"] == 3
    assert doc["results"][0]["sources"]["virustotal"]["score"] == 95


def test_html_escapes_attacker_controlled_values():
    evil = item("evil.test", IOCType.DOMAIN, Verdict.MALICIOUS, 90,
                original="<script>alert(1)</script>")
    page = to_html([evil])
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert "#c5a56e" in page and "#099197" in page and "#b5b1d8" in page


def test_infer_format():
    assert infer_format("out.stix.json") == "stix"
    assert infer_format("OUT.JSON") == "json"
    assert infer_format("r.htm") == "html"
    assert infer_format("r.txt") is None
