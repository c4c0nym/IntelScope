"""ThreatFox, and the abuse.ch key it shares with URLhaus."""

from conftest import FakeResponse, FakeSession, ioc

from intelscope import settings
from intelscope.models import IOCType
from intelscope.providers import resolve_names
from intelscope.providers.threatfox import ThreatFox
from intelscope.providers.urlhaus import URLhaus

URL = "https://threatfox-api.abuse.ch/api/v1/"

# Shaped like the sample responses on threatfox.abuse.ch/api
HIT = {"query_status": "ok", "data": [
    {"id": "12", "ioc": "139.180.203.104:443", "threat_type": "botnet_cc", "ioc_type": "ip:port",
     "malware": "win.cobalt_strike", "malware_printable": "Cobalt Strike", "confidence_level": 75,
     "first_seen": "2020-12-06 09:10:23 UTC", "last_seen": None, "tags": ["cobaltstrike"], "reporter": "abuse_ch"},
    {"id": "13", "ioc": "139.180.203.104:8080", "threat_type": "botnet_cc", "malware_printable": "Cobalt Strike",
     "confidence_level": 90, "first_seen": "2021-01-02 10:00:00 UTC", "last_seen": "2021-02-01 00:00:00 UTC"},
    {"id": "99", "ioc": "139.180.203.1040:80", "threat_type": "botnet_cc", "confidence_level": 100},
]}


def test_ip_matches_whatever_port_was_recorded_and_ignores_neighbours():
    session = FakeSession({URL: FakeResponse(200, HIT)})
    r = ThreatFox("key", session).lookup(ioc("139.180.203.104"))
    assert r.ok and r.found and r.score == 90  # the highest confidence among the matches
    assert "2 ThreatFox indicators" in r.summary and "Cobalt Strike" in r.summary and "botnet C2" in r.summary
    assert r.data["first_seen"] == "2020-12-06" and r.data["last_seen"] == "2021-02-01"
    assert r.data["reference"] == "https://threatfox.abuse.ch/ioc/12/"
    _, url, kwargs = session.calls[0]
    assert url == URL and kwargs["headers"] == {"Auth-Key": "key"}
    assert kwargs["json"] == {"query": "search_ioc", "search_term": "139.180.203.104", "exact_match": True}


def test_domain_and_url_need_an_exact_match():
    doc = {"query_status": "ok", "data": [
        {"id": "1", "ioc": "evil.test", "threat_type": "payload_delivery", "malware_printable": "AgentTesla"},
        {"id": "2", "ioc": "sub.evil.test", "threat_type": "botnet_cc", "confidence_level": 100}]}
    r = ThreatFox("k", FakeSession({URL: FakeResponse(200, doc)})).lookup(ioc("evil.test", IOCType.DOMAIN))
    assert r.ok and r.score == 75  # no confidence given -> 75; sub.evil.test is not evil.test
    assert "1 ThreatFox indicator " in r.summary and "payload delivery" in r.summary


def test_hash_uses_search_hash_and_says_the_sample_is_linked():
    session = FakeSession({URL: FakeResponse(200, HIT)})
    r = ThreatFox("k", session).lookup(ioc("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5))
    assert session.calls[0][2]["json"] == {"query": "search_hash", "hash": "44d88612fea8a8f36de82e1278abb02f"}
    assert r.ok and r.found and "linked to this sample" in r.summary


def test_no_result_unknown_status_and_filtered_out_results():
    nothing = ThreatFox("k", FakeSession({URL: FakeResponse(200, {"query_status": "no_result",
                                                                   "data": "Your search did not yield any results"})}))
    r = nothing.lookup(ioc("203.0.113.9"))
    assert r.ok and not r.found
    odd = ThreatFox("k", FakeSession({URL: FakeResponse(200, {"query_status": "illegal_search_term"})}))
    r = odd.lookup(ioc("203.0.113.9"))
    assert not r.ok and "illegal_search_term" in r.error  # an unknown answer is shown, not hidden
    none_match = ThreatFox("k", FakeSession({URL: FakeResponse(200, {"query_status": "ok", "data": [
        {"id": "5", "ioc": "203.0.113.99:80"}]})}))
    assert not none_match.lookup(ioc("203.0.113.9")).found


def test_auth_failure_is_reported():
    r = ThreatFox("bad", FakeSession({URL: FakeResponse(401, {})})).lookup(ioc("203.0.113.9"))
    assert not r.ok and "authentication" in r.error


def test_one_abusech_key_serves_both_sources(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "from-env")
    assert ThreatFox.from_env().api_key == "from-env" and URLhaus.from_env().api_key == "from-env"
    monkeypatch.delenv("ABUSECH_AUTH_KEY")
    assert not ThreatFox.from_env().configured
    settings.set_stored("urlhaus", {"api_key": "saved-once"})  # entered on the URLhaus card only
    assert ThreatFox.from_env().api_key == "saved-once" and ThreatFox.from_env().configured
    assert URLhaus.from_env(None, {"urlhaus": {"api_key": "own"}}).api_key == "own"  # a source's own key wins
    settings.remove_stored("urlhaus")
    assert URLhaus.from_env(None, {"threatfox": {"api_key": "session-key"}}).api_key == "session-key"


def test_threatfox_resolves_by_name_and_alias():
    assert resolve_names("threatfox,tf") == ["threatfox"]
