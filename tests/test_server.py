import json
import threading
import urllib.error
import urllib.request

import pytest

from intelscope.export import to_html
from intelscope.models import IOC, EnrichedIOC, IOCType, Verdict
from intelscope.palette import VERDICT_GLYPHS
from intelscope.server import serve


@pytest.fixture()
def demo_server():
    httpd = serve(port=0, demo=True)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, r.read()


def _post(url, body, token):
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "X-Intelscope-Token": token},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def test_dashboard_is_served(demo_server):
    status, body = _get(demo_server + "/")
    assert status == 200
    assert b"intelscope" in body and b'id="v-triage"' in body


def test_health_exposes_token_and_providers(demo_server):
    _, raw = _get(demo_server + "/api/health")
    doc = json.loads(raw)
    assert doc["tool"] == "intelscope" and doc["demo"] is True and doc["token"]
    assert {p["name"] for p in doc["providers"]} >= {"virustotal", "shodan", "asn"}


def test_enrich_roundtrip(demo_server):
    token = json.loads(_get(demo_server + "/api/health")[1])["token"]
    doc = _post(demo_server + "/api/enrich", {"iocs": ["198.51.100[.]23", "not an ioc"]}, token)
    assert doc["count"] == 1 and doc["rejected"] == ["not", "an", "ioc"]
    assert doc["results"][0]["verdict"] == "malicious"


def test_enrich_requires_token(demo_server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(demo_server + "/api/enrich", {"iocs": ["198.51.100.23"]}, "wrong")
    assert exc.value.code == 403


def test_foreign_host_header_is_rejected(demo_server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(demo_server + "/api/health", {"Host": "evil.example"})
    assert exc.value.code == 403


def test_malicious_is_a_single_glyph_and_an_svg_in_html():
    assert len(VERDICT_GLYPHS["malicious"]) == 1
    item = EnrichedIOC(
        IOC("198.51.100.23", IOCType.IPV4, "198.51.100.23"), [], 90, Verdict.MALICIOUS, ["x"]
    )
    page = to_html([item])
    assert 'class="tf"' in page and "▲▲▲" not in page
