from conftest import FakeResponse, FakeSession, ioc

from iocscope.models import IOCType
from iocscope.providers import build_providers, resolve_names
from iocscope.providers.abuseipdb import AbuseIPDB
from iocscope.providers.greynoise import GreyNoise
from iocscope.providers.shodan import ShodanInternetDB
from iocscope.providers.urlhaus import URLhaus
from iocscope.providers.virustotal import VirusTotal, url_id

VT_FILE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 0,
                                    "undetected": 62, "type-unsupported": 4},
            "popular_threat_classification": {"suggested_threat_label": "trojan.agenttesla"},
            "meaningful_name": "invoice.exe",
        }
    }
}


def test_virustotal_file_lookup():
    session = FakeSession({"https://www.virustotal.com/api/v3/files/": FakeResponse(200, VT_FILE)})
    r = VirusTotal("key", session).lookup(ioc("a" * 64, IOCType.SHA256))
    assert r.ok and r.found
    assert r.score == 7 * 12 + 4
    assert r.summary == "7/70 engines malicious, 1 suspicious · trojan.agenttesla"
    assert session.calls[0][2]["headers"]["x-apikey"] == "key"


def test_virustotal_url_uses_base64_id():
    session = FakeSession()
    VirusTotal("key", session).lookup(ioc("http://evil.test/x", IOCType.URL))
    assert session.calls[0][1].endswith("/urls/" + url_id("http://evil.test/x"))
    assert "=" not in url_id("http://evil.test/x")


def test_virustotal_404_is_not_found():
    r = VirusTotal("key", FakeSession()).lookup(ioc("1.2.3.4"))
    assert r.ok and not r.found


def test_auth_failure_is_reported_not_raised():
    session = FakeSession({"https://www.virustotal.com": FakeResponse(401, {})})
    r = VirusTotal("bad", session).lookup(ioc("1.2.3.4"))
    assert not r.ok and r.error == "authentication failed (check API key)"


def test_rate_limit_message():
    session = FakeSession({"https://api.abuseipdb.com": FakeResponse(429, {})})
    r = AbuseIPDB("k", session).lookup(ioc("1.2.3.4"))
    assert r.error == "rate limited / quota exhausted"


def test_malformed_json_is_an_error():
    session = FakeSession({"https://api.abuseipdb.com": FakeResponse(200, None)})
    r = AbuseIPDB("k", session).lookup(ioc("1.2.3.4"))
    assert not r.ok and "unexpected response" in r.error


def test_abuseipdb():
    payload = {"data": {"abuseConfidenceScore": 87, "totalReports": 1234, "isp": "Host Ltd",
                        "countryCode": "NL", "isWhitelisted": False}}
    session = FakeSession({"https://api.abuseipdb.com": FakeResponse(200, payload)})
    r = AbuseIPDB("k", session).lookup(ioc("1.2.3.4"))
    assert r.score == 87 and r.found and not r.benign
    assert r.summary == "87% abuse confidence, 1,234 reports (90d) · Host Ltd / NL"
    assert session.calls[0][2]["params"]["ipAddress"] == "1.2.3.4"


def test_urlhaus_no_results():
    session = FakeSession({"https://urlhaus-api.abuse.ch/v1/host/":
                           FakeResponse(200, {"query_status": "no_results"})})
    r = URLhaus("k", session).lookup(ioc("evil.test", IOCType.DOMAIN))
    assert r.ok and not r.found
    assert session.calls[0][2]["headers"]["Auth-Key"] == "k"


def test_urlhaus_host_with_online_urls():
    body = {"query_status": "ok", "url_count": "2", "urls": [
        {"url_status": "online", "threat": "malware_download", "tags": ["Emotet"]},
        {"url_status": "offline", "threat": "malware_download", "tags": ["exe"]},
    ]}
    session = FakeSession({"https://urlhaus-api.abuse.ch/v1/host/": FakeResponse(200, body)})
    r = URLhaus("k", session).lookup(ioc("evil.test", IOCType.DOMAIN))
    assert r.score == 90
    assert r.summary == "2 malware URLs hosted (1 online) · Emotet, exe"


def test_urlhaus_payload_by_md5():
    body = {"query_status": "ok", "signature": "AgentTesla", "file_type": "exe"}
    session = FakeSession({"https://urlhaus-api.abuse.ch/v1/payload/": FakeResponse(200, body)})
    r = URLhaus("k", session).lookup(ioc("a" * 32, IOCType.MD5))
    assert r.summary == "malware payload: AgentTesla (exe)"
    assert session.calls[0][2]["data"] == {"md5_hash": "a" * 32}


def test_greynoise_riot_is_benign():
    body = {"noise": False, "riot": True, "classification": "benign", "name": "Google"}
    session = FakeSession({"https://api.greynoise.io": FakeResponse(200, body)})
    r = GreyNoise(None, session).lookup(ioc("8.8.8.8"))
    assert r.benign and r.score == 0
    assert "key" not in session.calls[0][2]["headers"]


def test_greynoise_malicious():
    body = {"noise": True, "riot": False, "classification": "malicious"}
    session = FakeSession({"https://api.greynoise.io": FakeResponse(200, body)})
    assert GreyNoise("k", session).lookup(ioc("1.2.3.4")).score == 70


def test_shodan_exposure_is_context_unless_hostile():
    body = {"ports": [443, 22], "vulns": ["CVE-2024-1"], "tags": ["vpn"]}
    session = FakeSession({"https://internetdb.shodan.io": FakeResponse(200, body)})
    r = ShodanInternetDB(None, session).lookup(ioc("1.2.3.4"))
    assert r.score is None
    assert r.summary == "ports 22, 443 · 1 CVE · tags: vpn"

    body["tags"] = ["c2"]
    assert ShodanInternetDB(None, session).lookup(ioc("1.2.3.4")).score == 60


def test_provider_selection_and_aliases():
    assert resolve_names("vt, gn,vt") == ["virustotal", "greynoise"]
    assert [p.name for p in build_providers("shodan", session=object())] == ["shodan"]


def test_configured_status(monkeypatch):
    assert not VirusTotal.from_env(object()).configured
    monkeypatch.setenv("VT_API_KEY", "abc")
    assert VirusTotal.from_env(object()).configured
    assert GreyNoise.from_env(object()).configured  # key optional
