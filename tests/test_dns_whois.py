"""RDAP (WHOIS) domain age and passive DNS, against canned responses."""

from datetime import datetime, timedelta, timezone

from conftest import FakeResponse, FakeSession, ioc

from intelscope.models import IOCType
from intelscope.providers import resolve_names
from intelscope.providers.pdns import PassiveDNS, to_date
from intelscope.providers.rdap import RDAP, age_score, candidates, parse_when


def _stamp(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rdap(days_ago: int | None, registrar: str = "Example Registrar Inc.") -> dict:
    events = [{"eventAction": "last changed", "eventDate": _stamp(1)}]
    if days_ago is not None:
        events.insert(0, {"eventAction": "registration", "eventDate": _stamp(days_ago)})
    return {
        "ldhName": "EVIL.TEST", "events": events, "status": ["client transfer prohibited"],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.TEST"}, {"ldhName": "ns2.example.test"}],
        "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Hidden"]]]},
                     {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                                      ["fn", {}, "text", registrar]]]}],
    }


# --------------------------------------------------------------------------- RDAP

def test_age_bands():
    assert age_score(0) == 70 and age_score(6) == 70
    assert age_score(7) == 55 and age_score(29) == 55
    assert age_score(30) == 30 and age_score(89) == 30
    assert age_score(90) is None and age_score(4000) is None  # an old domain earns no score


def test_young_domain_is_flagged_with_registrar_and_nameservers():
    session = FakeSession({"https://rdap.org/domain/evil.test": FakeResponse(200, _rdap(3))})
    r = RDAP(session=session).lookup(ioc("evil.test", IOCType.DOMAIN))
    assert r.ok and r.found and r.score == 70
    assert "3 days ago" in r.summary and "Example Registrar Inc." in r.summary
    assert "Hidden" not in r.summary  # the registrant is never read, only the registrar
    assert r.data["age_days"] == 3 and r.data["nameservers"] == ["ns1.example.test", "ns2.example.test"]
    assert session.calls[0][2]["headers"]["Accept"] == "application/rdap+json"


def test_old_domain_is_found_but_not_scored():
    session = FakeSession({"https://rdap.org/domain/": FakeResponse(200, _rdap(4000))})
    r = RDAP(session=session).lookup(ioc("old.test", IOCType.DOMAIN))
    assert r.ok and r.found and r.score is None and "registered" in r.summary


def test_missing_registration_date_is_reported_not_guessed():
    session = FakeSession({"https://rdap.org/domain/": FakeResponse(200, _rdap(None))})
    r = RDAP(session=session).lookup(ioc("odd.test", IOCType.DOMAIN))
    assert r.ok and r.found and r.score is None and "not published" in r.summary


def test_subdomain_falls_back_to_the_registered_parent():
    session = FakeSession({"https://rdap.org/domain/evil.test": FakeResponse(200, _rdap(2))})
    r = RDAP(session=session).lookup(ioc("mail.evil.test", IOCType.DOMAIN))
    assert r.ok and r.score == 70 and "parent domain evil.test" in r.summary
    assert [c[1].rsplit("/", 1)[1] for c in session.calls] == ["mail.evil.test", "evil.test"]


def test_registry_that_answers_400_for_a_subdomain_falls_back_to_the_parent():
    class Strict(FakeSession):
        def get(self, url, **kwargs):
            self.calls.append(("GET", url, kwargs))
            if url.endswith("/www.evil.test"):
                return FakeResponse(400, {})
            return FakeResponse(200, _rdap(2))

    r = RDAP(session=Strict()).lookup(ioc("www.evil.test", IOCType.DOMAIN))
    assert r.ok and r.found and "parent domain evil.test" in r.summary


def test_pdns_marks_capped_counts():
    rows = [{"query": f"d{i}.example.test.", "answer": "192.0.2.10", "firstSeenTimestamp": 1700000000000,
             "lastSeenTimestamp": 1764000000000} for i in range(200)]
    doc = {"responseCode": 200, "count": 1000, "data": rows}
    r = PassiveDNS(session=FakeSession({"https://api.mnemonic.no": FakeResponse(200, doc)})).lookup(ioc("192.0.2.10"))
    assert "1,000+ records" in r.summary and "200+ distinct domains" in r.summary and "(+195)" in r.summary


def test_unregistered_domain_and_lookup_limits():
    session = FakeSession()  # every URL answers 404
    r = RDAP(session=session).lookup(ioc("a.b.c.d.e.test", IOCType.DOMAIN))
    assert r.ok and not r.found
    assert len(session.calls) <= 4  # bounded, so a deep name cannot burn the rate limit
    assert candidates("a.b.evil.test") == ["a.b.evil.test", "b.evil.test", "evil.test"]
    assert candidates("evil.test") == ["evil.test"]


def test_rdap_rate_limit_is_reported():
    r = RDAP(session=FakeSession({"https://rdap.org": FakeResponse(429, {})})).lookup(
        ioc("evil.test", IOCType.DOMAIN))
    assert not r.ok and "rate limited" in r.error


def test_parse_when_handles_odd_input():
    assert parse_when("2026-11-20T10:00:00Z").year == 2026
    assert parse_when("2026-11-20T10:00:00+01:00").tzinfo is not None
    assert parse_when("2026-11-20").tzinfo is not None
    assert parse_when("yesterday") is None and parse_when(None) is None and parse_when(5) is None


def test_rdap_needs_no_key_and_has_nothing_to_enter():
    p = RDAP()
    assert p.configured and not RDAP.credential_fields()


# --------------------------------------------------------------------------- passive DNS

PDNS_IP = {"responseCode": 200, "count": 3, "data": [
    {"query": "b.example.test.", "answer": "192.0.2.10", "rrtype": "a",
     "firstSeenTimestamp": 1763000000000, "lastSeenTimestamp": 1764000000000},
    {"query": "a.example.test.", "answer": "192.0.2.10", "rrtype": "a",
     "firstSeenTimestamp": 1700000000000, "lastSeenTimestamp": 1763500000000},
    {"query": "B.example.test", "answer": "192.0.2.10", "rrtype": "a",
     "firstSeenTimestamp": 1750000000000, "lastSeenTimestamp": 1760000000000},
]}


def test_passive_dns_for_an_ip_lists_the_domains_that_pointed_at_it():
    session = FakeSession({"https://api.mnemonic.no/pdns/v3/192.0.2.10": FakeResponse(200, PDNS_IP)})
    r = PassiveDNS(session=session).lookup(ioc("192.0.2.10"))
    assert r.ok and r.found and r.score is None  # context only
    assert "3 records" in r.summary and "2 distinct domains" in r.summary
    assert r.data["examples"] == ["b.example.test", "a.example.test"]  # trailing dot dropped, duplicates merged
    assert r.data["first_seen"] == to_date(1700000000000) and r.data["last_seen"] == to_date(1764000000000)
    assert "Argus-API-Key" not in session.calls[0][2]["headers"]


def test_passive_dns_for_a_domain_lists_the_addresses_it_resolved_to():
    doc = {"responseCode": 200, "data": [
        {"query": "evil.test.", "answer": "198.51.100.23", "firstSeenTimestamp": 1763000000000,
         "lastSeenTimestamp": 1764000000000},
        {"query": "evil.test.", "answer": "198.51.100.24", "firstSeenTimestamp": 1763000000000,
         "lastSeenTimestamp": 1763900000000}]}
    r = PassiveDNS(session=FakeSession({"https://api.mnemonic.no/pdns/v3/evil.test": FakeResponse(200, doc)})
                   ).lookup(ioc("evil.test", IOCType.DOMAIN))
    assert r.ok and "2 distinct addresses" in r.summary and "198.51.100.23" in r.summary


def test_passive_dns_optional_key_is_sent_when_set():
    session = FakeSession({"https://api.mnemonic.no/pdns/v3/": FakeResponse(200, PDNS_IP)})
    PassiveDNS("argus-key", session).lookup(ioc("192.0.2.10"))
    assert session.calls[0][2]["headers"]["Argus-API-Key"] == "argus-key"
    assert PassiveDNS().configured


def test_passive_dns_empty_rate_limit_and_bad_response():
    empty = PassiveDNS(session=FakeSession({"https://api.mnemonic.no": FakeResponse(200, {"responseCode": 200, "data": []})}))
    assert not empty.lookup(ioc("192.0.2.10")).found
    limited = PassiveDNS(session=FakeSession({"https://api.mnemonic.no": FakeResponse(402, {})}))
    r = limited.lookup(ioc("192.0.2.10"))
    assert not r.ok and "rate limited" in r.error and "1,000" in r.error
    bad = PassiveDNS(session=FakeSession({"https://api.mnemonic.no": FakeResponse(200, {"responseCode": 500})}))
    assert not bad.lookup(ioc("192.0.2.10")).ok


def test_passive_dns_timestamps_in_seconds_or_milliseconds():
    assert to_date(1764000000000) == to_date(1764000000) != ""
    assert to_date(0) == "" and to_date(None) == "" and to_date("x") == "" and to_date(True) == ""


def test_new_sources_resolve_by_alias():
    assert resolve_names("whois,dns") == ["rdap", "pdns"]
