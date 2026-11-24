from conftest import FakeResponse, FakeSession, ioc

from iocscope.cli import main
from iocscope.models import IOCType
from iocscope.providers.asn import DROP_URL, ASNBlocklist, parse_custom, parse_drop

DROP = (
    '{"asn":64500,"rir":"ripencc","domain":"bad.example","cc":"NL","asname":"EXAMPLE-BULLETPROOF"}\n'
    '{"asn":64501,"rir":"arin","domain":"worse.example","cc":"US","asname":"EXAMPLE-SPAM"}\n'
    '{"type":"metadata","timestamp":1795543004,"size":200,"records":2}\n'
)
NET_INFO = "https://stat.ripe.net/data/network-info/"
AS_OVERVIEW = "https://stat.ripe.net/data/as-overview/"


def network(asns, prefix="198.51.100.0/24"):
    return FakeResponse(200, {"data": {"asns": asns, "prefix": prefix}})


def provider(tmp_path, routes, custom=None, drop=True):
    routes = {DROP_URL: FakeResponse(200, text=DROP), **routes} if drop else routes
    session = FakeSession(routes)
    return ASNBlocklist(custom, session, drop_cache=tmp_path / "asndrop.json"), session


def test_parse_drop_skips_metadata():
    listed = parse_drop(DROP + "not json\n")
    assert set(listed) == {64500, 64501}
    assert listed[64500]["asname"] == "EXAMPLE-BULLETPROOF"


def test_parse_custom_formats():
    listed = parse_custom("# my list\nAS64510  # bulletproof host from case 4411\n64511\nas64512\nnonsense\n")
    assert set(listed) == {64510, 64511, 64512}
    assert listed[64510]["reason"] == "bulletproof host from case 4411"
    assert listed[64511]["reason"] == "on your blocklist"


def test_ip_in_drop_listed_asn(tmp_path):
    p, _ = provider(tmp_path, {NET_INFO: network(["64500"])})
    r = p.lookup(ioc("198.51.100.23"))
    assert r.ok and r.found and r.score == 75
    assert r.summary == "AS64500 EXAMPLE-BULLETPROOF is on Spamhaus ASN-DROP"
    assert r.data["prefix"] == "198.51.100.0/24" and r.data["country"] == "NL"


def test_ip_in_clean_asn_gives_context_only(tmp_path):
    p, _ = provider(tmp_path, {NET_INFO: network(["13335"], "1.1.1.0/24"),
                               AS_OVERVIEW: FakeResponse(200, {"data": {"holder": "CLOUDFLARENET"}})})
    r = p.lookup(ioc("1.1.1.1"))
    assert r.ok and r.score is None
    assert not r.found  # every routed IP has an ASN: context, not a sighting
    assert r.summary == "AS13335 CLOUDFLARENET · 1.1.1.0/24 · not blocklisted"

    from iocscope.scoring import assess
    assert assess([r], {"asn": 0.8})[1].value == "unknown"  # does not turn "unknown" into "low"


def test_custom_blocklist(tmp_path):
    custom = tmp_path / "asns.txt"
    custom.write_text("AS64520 # leased to a phishing kit operator\n")
    p, _ = provider(tmp_path, {NET_INFO: network(["64520"]),
                               AS_OVERVIEW: FakeResponse(200, {"data": {"holder": "EXAMPLE-LEASE"}})},
                    custom=str(custom))
    r = p.lookup(ioc("198.51.100.9"))
    assert r.score == 75
    assert r.summary == ("AS64520 EXAMPLE-LEASE is on your blocklist "
                         "(leased to a phishing kit operator)")


def test_unannounced_ip_is_not_found(tmp_path):
    p, _ = provider(tmp_path, {NET_INFO: network([], "")})
    assert not p.lookup(ioc("198.51.100.1")).found


def test_drop_list_is_downloaded_once_and_cached(tmp_path):
    p, session = provider(tmp_path, {NET_INFO: network(["64500"])})
    p.lookup(ioc("198.51.100.1"))
    p.lookup(ioc("198.51.100.2"))
    downloads = [c for c in session.calls if c[1] == DROP_URL]
    assert len(downloads) == 1 and (tmp_path / "asndrop.json").exists()

    p2, session2 = provider(tmp_path, {NET_INFO: network(["64500"])})    # a new run
    assert p2.lookup(ioc("198.51.100.3")).score == 75
    assert not [c for c in session2.calls if c[1] == DROP_URL]


def test_drop_unavailable_still_reports_the_asn(tmp_path):
    p, _ = provider(tmp_path, {DROP_URL: FakeResponse(503, text=""), NET_INFO: network(["64500"]),
                               AS_OVERVIEW: FakeResponse(200, {"data": {"holder": "X"}})}, drop=False)
    r = p.lookup(ioc("198.51.100.1"))
    assert r.ok and r.score is None
    assert "ASN-DROP unavailable" in r.summary


def test_ipv6_supported_and_domains_not(tmp_path):
    p, _ = provider(tmp_path, {})
    assert p.supports_ioc(ioc("2001:db8::1", IOCType.IPV6))
    assert not p.supports_ioc(ioc("evil.test", IOCType.DOMAIN))


def test_cli_rejects_missing_blocklist_file(capsys):
    assert main(["1.2.3.4", "--asn-blocklist", "nope.txt", "-q"]) == 2
    assert "ASN blocklist not found" in capsys.readouterr().err


def test_demo_includes_asn_source(capsys):
    import json
    assert main(["--demo", "-q", "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    bad = next(r for r in doc["results"] if r["ioc"] == "198.51.100.23")
    assert "ASN-DROP" in bad["sources"]["asn"]["summary"]
