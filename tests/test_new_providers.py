"""Censys, urlscan.io, Intel 471 and OpenCTI, against canned responses (no network)."""

from conftest import FakeResponse, FakeSession, ioc

from intelscope.models import IOCType
from intelscope.providers import REGISTRY, resolve_names
from intelscope.providers.censys import Censys
from intelscope.providers.intel471 import Intel471
from intelscope.providers.opencti import OpenCTI
from intelscope.providers.urlscan import URLscan, build_query

# --------------------------------------------------------------------------- Censys

CENSYS_V3 = {"result": {"resource": {
    "ip": "198.51.100.23",
    "services": [{"port": 22, "protocol": "SSH"}, {"port": 8443, "protocol": "HTTP"}],
    "autonomous_system": {"asn": 64500, "name": "EXAMPLE-NET"},
    "location": {"country_code": "NL"},
    "labels": [{"value": "c2"}],
}}}
CENSYS_V2 = {"result": {"ip": "192.0.2.10", "services": [{"port": 80, "service_name": "HTTP"}],
                        "autonomous_system": {"asn": 64502, "name": "EXAMPLE-HOSTING"}, "labels": ["tor"]}}


def test_censys_platform_token_is_sent_as_bearer():
    session = FakeSession({"https://api.platform.censys.io/v3/global/asset/host/": FakeResponse(200, CENSYS_V3)})
    r = Censys("pat_123", session, {"org": "org-1"}).lookup(ioc("198.51.100.23"))
    assert r.ok and r.found
    assert r.score == 60 and "threat label c2" in r.summary and "ports 22, 8443" in r.summary
    assert r.data["asn"] == 64500 and r.data["country"] == "NL"
    _, url, kwargs = session.calls[0]
    assert url.endswith("/host/198.51.100.23")
    assert kwargs["headers"]["Authorization"] == "Bearer pat_123"
    assert kwargs["params"] == {"organization_id": "org-1"}


def test_censys_legacy_id_secret_uses_basic_auth():
    session = FakeSession({"https://search.censys.io/api/v2/hosts/": FakeResponse(200, CENSYS_V2)})
    r = Censys("myid:mysecret", session).lookup(ioc("192.0.2.10"))
    assert r.ok and r.found and r.score is None  # context only, not an accusation
    assert session.calls[0][2]["auth"] == ("myid", "mysecret")
    assert "ports 80" in r.summary


def test_censys_unknown_host_and_auth_failure():
    assert not Censys("k", FakeSession()).lookup(ioc("203.0.113.9")).found
    bad = Censys("k", FakeSession({"https://api.platform.censys.io": FakeResponse(403, {})}))
    r = bad.lookup(ioc("203.0.113.9"))
    assert not r.ok and "authentication" in r.error


# --------------------------------------------------------------------------- urlscan

SEARCH = {"total": 4, "results": [{
    "_id": "abc-123",
    "task": {"time": "2026-11-20T10:00:00Z", "uuid": "abc-123"},
    "page": {"ip": "198.51.100.5", "country": "NL", "server": "nginx"},
}]}
RESULT = {"verdicts": {"overall": {"malicious": True, "score": 100, "brands": [{"name": "Microsoft"}],
                                   "tags": ["phishing"]}}}


def test_urlscan_with_key_reads_the_verdict():
    session = FakeSession({"https://urlscan.io/api/v1/search/": FakeResponse(200, SEARCH),
                           "https://urlscan.io/api/v1/result/abc-123/": FakeResponse(200, RESULT)})
    r = URLscan("key", session).lookup(ioc("evil.test", IOCType.DOMAIN))
    assert r.ok and r.found and r.score == 100
    assert "4 public scans" in r.summary and "verdict: malicious" in r.summary and "Microsoft" in r.summary
    assert r.data["report"] == "https://urlscan.io/result/abc-123/"
    assert session.calls[0][2]["headers"]["API-Key"] == "key"
    assert session.calls[0][2]["params"]["q"] == 'page.domain:"evil.test"'


def test_urlscan_without_key_searches_anonymously_and_does_not_open_results():
    session = FakeSession({"https://urlscan.io/api/v1/search/": FakeResponse(200, SEARCH)})
    r = URLscan(None, session).lookup(ioc("evil.test", IOCType.DOMAIN))
    assert URLscan(None).configured  # no key needed
    assert r.ok and r.found and r.score is None
    assert len(session.calls) == 1 and "API-Key" not in session.calls[0][2]["headers"]


def test_urlscan_verdict_failure_keeps_the_search_result():
    session = FakeSession({"https://urlscan.io/api/v1/search/": FakeResponse(200, SEARCH),
                           "https://urlscan.io/api/v1/result/": FakeResponse(403, {})})
    r = URLscan("key", session).lookup(ioc("evil.test", IOCType.DOMAIN))
    assert r.ok and r.found and "4 public scans" in r.summary


def test_urlscan_no_scans_and_query_quoting():
    r = URLscan("k", FakeSession({"https://urlscan.io/api/v1/search/": FakeResponse(200, {"results": []})})
                ).lookup(ioc("quiet.test", IOCType.DOMAIN))
    assert r.ok and not r.found
    assert build_query(ioc('http://x.test/a"b', IOCType.URL)) == 'page.url:"http://x.test/a\\"b"'
    assert build_query(ioc("a" * 64, IOCType.SHA256)) == "hash:" + "a" * 64
    assert build_query(ioc("198.51.100.1")) == 'page.ip:"198.51.100.1"'


# --------------------------------------------------------------------------- Intel 471

# Shaped like the Verity471 SDK's IndicatorsStream: confidence is 0-100, the value sits under
# data.ipv4 / data.url / data.domain / data.file, and activity carries first_seen_ts / last_seen_ts.
VERITY = {"count": 4, "cursor_next": "abc", "indicators": [
    {"id": "i1", "type": "ipv4", "confidence": 90, "data": {"ipv4": {"ip_address": "198.51.100.23"}},
     "threat": {"type": "malware", "data": {"malware_family": {"name": "ExampleLoader"}}},
     "activity": {"first_seen_ts": "2026-10-01T00:00:00Z", "last_seen_ts": "2026-11-18T12:00:00Z"}},
    {"id": "i2", "type": "ipv4", "confidence": 99, "data": {"ipv4": {"ip_address": "198.51.100.23"}},
     "revocation": {"revoked": True}, "activity": {"last_seen_ts": "2026-09-01T00:00:00Z"}},
    {"id": "i3", "type": "ipv4", "confidence": 95, "data": {"ipv4": {"ip_address": "198.51.100.230"}}},
    {"id": "i4", "type": "file", "confidence": 80, "data": {"file": {"md5": "44d88612fea8a8f36de82e1278abb02f"}}},
]}
VERITY_URL = "https://api.intel471.cloud/integrations/indicators/v1/indicators/stream"
TITAN = {"indicators": [
    {"data": {"confidence": "high", "threat": {"type": "malware", "data": {"family": "ExampleLoader"}},
              "indicator_data": {"address": "198.51.100.23"}}, "activity": {"last": "2026-11-18"}},
    {"data": {"confidence": "low", "indicator_data": {"address": "198.51.100.23"}}, "last_updated": "2026-10-01"},
]}


def test_intel471_needs_client_id_and_secret():
    assert not Intel471("secret").configured
    assert not Intel471(None, extra={"client_id": "abc"}).configured
    assert Intel471("secret", extra={"client_id": "abc"}).configured


def test_intel471_verity_is_the_default_and_uses_basic_auth_with_text_filter():
    session = FakeSession({VERITY_URL: FakeResponse(200, VERITY)})
    r = Intel471("the-secret", session, {"client_id": "app-id"}).lookup(ioc("198.51.100.23"))
    assert r.ok and r.found
    _, url, kwargs = session.calls[0]
    assert url == VERITY_URL
    assert kwargs["auth"] == ("app-id", "the-secret")
    assert kwargs["params"]["text_filter"] == "198.51.100.23"


def test_intel471_verity_matches_exactly_and_ignores_revoked_for_the_score():
    session = FakeSession({VERITY_URL: FakeResponse(200, VERITY)})
    r = Intel471("s", session, {"client_id": "c"}).lookup(ioc("198.51.100.23"))
    # i3 is 198.51.100.230 (a free-text neighbour) and must not count; i2 is revoked at 99 and must not score
    assert r.score == 90
    assert "2 Intel 471 indicators" in r.summary and "1 revoked or expired" in r.summary
    assert "ExampleLoader" in r.summary and r.data["active"] == 1
    assert r.data["last_seen"] == "2026-11-18"


def test_intel471_verity_file_hash_and_free_text_miss():
    session = FakeSession({VERITY_URL: FakeResponse(200, VERITY)})
    p = Intel471("s", session, {"client_id": "c"})
    assert p.lookup(ioc("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5)).score == 80
    miss = p.lookup(ioc("203.0.113.9"))
    assert miss.ok and not miss.found


def test_intel471_only_revoked_indicators_are_found_but_do_not_score():
    doc = {"indicators": [{"id": "x", "confidence": 99, "data": {"domain": "evil.test"},
                           "revocation": {"revoked": True}}]}
    r = Intel471("s", FakeSession({VERITY_URL: FakeResponse(200, doc)}), {"client_id": "c"}
                 ).lookup(ioc("evil.test", IOCType.DOMAIN))
    assert r.ok and r.found and r.score is None


def test_intel471_expired_indicator_does_not_score():
    doc = {"indicators": [{"id": "x", "confidence": 99, "data": {"url": "http://evil.test/a"},
                           "expiration_ts": "2020-01-01T00:00:00Z"}]}
    r = Intel471("s", FakeSession({VERITY_URL: FakeResponse(200, doc)}), {"client_id": "c"}
                 ).lookup(ioc("http://evil.test/a", IOCType.URL))
    assert r.ok and r.found and r.score is None and "revoked or expired" in r.summary


def test_intel471_forbidden_says_to_enable_the_api():
    r = Intel471("s", FakeSession({VERITY_URL: FakeResponse(403, {})}), {"client_id": "c"}
                 ).lookup(ioc("198.51.100.23"))
    assert not r.ok and "Indicators API" in r.error
    bad = Intel471("s", FakeSession({VERITY_URL: FakeResponse(401, {})}), {"client_id": "c"}
                   ).lookup(ioc("198.51.100.23"))
    assert not bad.ok and "authentication" in bad.error


def test_intel471_titan_base_url_selects_the_legacy_api():
    session = FakeSession({"https://api.intel471.com/v1/indicators/stream": FakeResponse(200, TITAN)})
    p = Intel471("titan-key", session, {"client_id": "me@example.test", "url": "https://api.intel471.com/v1/"})
    r = p.lookup(ioc("198.51.100.23"))
    assert r.ok and r.found and r.score == 90 and "ExampleLoader" in r.summary
    _, url, kwargs = session.calls[0]
    assert url == "https://api.intel471.com/v1/indicators/stream"
    assert kwargs["params"]["indicator"] == "198.51.100.23" and "text_filter" not in kwargs["params"]
    assert kwargs["auth"] == ("me@example.test", "titan-key")


def test_intel471_custom_verity_host_and_empty_answer():
    session = FakeSession({"https://tenant.example.test/integrations/indicators/v1/indicators/stream":
                           FakeResponse(200, {"indicators": []})})
    p = Intel471("k", session, {"client_id": "c", "url": "https://tenant.example.test/"})
    r = p.lookup(ioc("198.51.100.23"))
    assert r.ok and not r.found


# --------------------------------------------------------------------------- OpenCTI

def _octi(nodes, errors=None):
    doc = {"data": {"stixCyberObservables": {"edges": [{"node": n} for n in nodes]}}}
    if errors:
        doc["errors"] = errors
    return FakeResponse(200, doc)


def test_opencti_needs_url_and_token():
    assert not OpenCTI("tok").configured
    assert not OpenCTI(None, extra={"url": "https://octi.test"}).configured
    assert OpenCTI("tok", extra={"url": "https://octi.test"}).configured


def test_opencti_exact_match_with_score_and_labels():
    node = {"id": "obs-1", "entity_type": "IPv4-Addr", "observable_value": "198.51.100.23",
            "x_opencti_score": 80, "objectLabel": [{"value": "c2"}, {"value": "tlp-amber"}]}
    other = {"id": "obs-2", "entity_type": "IPv4-Addr", "observable_value": "198.51.100.230"}
    session = FakeSession({"https://octi.test/graphql": _octi([other, node])})
    r = OpenCTI("tok", session, {"url": "https://octi.test/"}).lookup(ioc("198.51.100.23"))
    assert r.ok and r.found and r.score == 80
    assert "score 80" in r.summary and "c2" in r.summary
    assert r.data["link"] == "https://octi.test/dashboard/id/obs-1"
    method, url, kwargs = session.calls[0]
    assert method == "POST" and url == "https://octi.test/graphql"
    assert kwargs["headers"]["Authorization"] == "Bearer tok"
    assert kwargs["json"]["variables"] == {"s": "198.51.100.23"}


def test_opencti_only_substring_matches_is_not_found():
    other = {"id": "x", "entity_type": "IPv4-Addr", "observable_value": "198.51.100.230"}
    r = OpenCTI("t", FakeSession({"https://o.test/graphql": _octi([other])}), {"url": "https://o.test"}
                ).lookup(ioc("198.51.100.23"))
    assert r.ok and not r.found


def test_opencti_falls_back_to_the_minimal_query_when_labels_are_rejected():
    class Flaky(FakeSession):
        def post(self, url, **kwargs):
            self.calls.append(("POST", url, kwargs))
            if "objectLabel" in kwargs["json"]["query"]:
                return _octi([], errors=[{"message": "Cannot query field objectLabel"}])
            return _octi([{"id": "o1", "entity_type": "Domain-Name", "observable_value": "evil.test"}])

    session = Flaky()
    r = OpenCTI("t", session, {"url": "https://o.test"}).lookup(ioc("evil.test", IOCType.DOMAIN))
    assert r.ok and r.found and r.score is None and "known observable" in r.summary
    assert len(session.calls) == 2


def test_opencti_graphql_error_is_reported():
    err = [{"message": "You must be logged in"}]
    r = OpenCTI("t", FakeSession({"https://o.test/graphql": _octi([], errors=err)}), {"url": "https://o.test"}
                ).lookup(ioc("198.51.100.23"))
    assert not r.ok


# --------------------------------------------------------------------------- registry

def test_registry_has_all_requested_sources():
    assert {"censys", "urlscan", "intel471", "opencti", "abuseipdb", "greynoise"} <= set(REGISTRY)
    assert resolve_names("i471,octi,urlscan.io") == ["intel471", "opencti", "urlscan"]
