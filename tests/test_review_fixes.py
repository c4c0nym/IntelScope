"""Regression tests for problems found in the code review."""

import threading
import urllib.request

from conftest import FakeResponse, FakeSession

from intelscope.allowlist import load_allowlist
from intelscope.cache import Cache
from intelscope.detect import classify
from intelscope.enrich import Enricher
from intelscope.models import IOC, IOCType
from intelscope.providers.censys import Censys
from intelscope.providers.urlscan import URLscan
from intelscope.providers.virustotal import VirusTotal
from intelscope.server import serve
from intelscope.tracker import Tracker, to_markdown


def _domain(value: str) -> IOC:
    return IOC(value, IOCType.DOMAIN, value)


# --------------------------------------------------------------------------- allowlist

def test_default_allowlist_does_not_wave_through_user_content_hosts():
    allow = load_allowlist(skip_reserved=False)
    for abused in ("storage.googleapis.com", "bucket.storage.googleapis.com", "drive.google.com",
                   "sites.google.com", "docs.google.com", "onedrive.live.com",
                   "evil.sharepoint.com"):
        assert allow.match(_domain(abused)) is None, abused


def test_default_allowlist_still_covers_the_vendors_themselves():
    allow = load_allowlist(skip_reserved=False)
    for fine in ("google.com", "www.google.com", "update.microsoft.com", "mozilla.org"):
        assert allow.match(_domain(fine)), fine


# --------------------------------------------------------------------------- input parsing

def test_file_names_are_not_mistaken_for_domains():
    for name in ("invoice.exe", "payload.dll", "report.pdf", "setup.msi", "macro.docm", "run.ps1",
                 "archive.7z", "photo.jpg"):
        assert classify(name) is None, name


def test_real_domains_still_parse():
    for fine in ("example.com", "evil-login.example.org", "shop.co.uk", "xn--80ak6aa92e.com"):
        assert classify(fine) is not None, fine


# --------------------------------------------------------------------------- cache

URLSCAN_SEARCH = {"total": 1, "results": [{"_id": "abc", "task": {"time": "2026-11-20T10:00:00Z"}, "page": {}}]}


def test_a_keyless_urlscan_result_is_not_reused_once_a_key_is_added(tmp_path):
    cache = Cache(tmp_path / "c.json", ttl_seconds=3600)
    ioc = _domain("evil.test")
    anon = FakeSession({"https://urlscan.io/api/v1/search/": FakeResponse(200, URLSCAN_SEARCH)})
    Enricher([URLscan(None, anon)], cache=cache).enrich([ioc])
    assert len(anon.calls) == 1

    keyed = FakeSession({"https://urlscan.io/api/v1/search/": FakeResponse(200, URLSCAN_SEARCH),
                         "https://urlscan.io/api/v1/result/": FakeResponse(
                             200, {"verdicts": {"overall": {"malicious": True, "score": 100}}})})
    out = Enricher([URLscan("key", keyed)], cache=cache).enrich([ioc])[0]
    assert keyed.calls, "the keyed lookup must not be answered from the keyless cache"
    assert out.results[0].score == 100


def test_a_keyless_result_is_still_reused_while_nothing_changed(tmp_path):
    cache = Cache(tmp_path / "c.json", ttl_seconds=3600)
    ioc = _domain("evil.test")
    first = FakeSession({"https://urlscan.io/api/v1/search/": FakeResponse(200, URLSCAN_SEARCH)})
    Enricher([URLscan(None, first)], cache=cache).enrich([ioc])
    second = FakeSession({"https://urlscan.io/api/v1/search/": FakeResponse(200, URLSCAN_SEARCH)})
    again = Enricher([URLscan(None, second)], cache=cache).enrich([ioc])[0]
    assert not second.calls and again.results[0].cached


# --------------------------------------------------------------------------- tracker

def test_two_writers_on_one_file_do_not_lose_rows(tmp_path):
    path = tmp_path / "t.json"
    writers = [Tracker(path) for _ in range(4)]  # like the CLI and the dashboard server at once

    def work(index: int) -> None:
        for i in range(25):
            writers[index].add(f"10.{index}.0.{i + 1}", source="s")

    threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(Tracker(path).entries()) == 100


def test_defanged_markdown_also_defangs_links_typed_into_free_text(tmp_path):
    t = Tracker(tmp_path / "t.json")
    t.add("198.51.100.23", source="see https://intel.example/report", context="panel at http://evil.test/login")
    safe = to_markdown(t.entries())
    assert "http://" not in safe and "https://" not in safe
    assert "hxxp://evil[.]test/login" in safe and "hxxps://intel[.]example/report" in safe
    raw = to_markdown(t.entries(), defanged=False)
    assert "http://evil.test/login" in raw


# --------------------------------------------------------------------------- server and providers

def test_dashboard_cannot_be_framed_by_another_site():
    httpd = serve(port=0, demo=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        resp = urllib.request.urlopen(f"http://127.0.0.1:{httpd.server_address[1]}/", timeout=5)
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_source_that_answers_with_the_wrong_shape_is_an_error_not_a_crash():
    ioc = IOC("198.51.100.23", IOCType.IPV4, "198.51.100.23")
    odd = FakeResponse(200, ["not", "an", "object"])
    r = Censys("tok", FakeSession({"https://api.platform.censys.io": odd})).lookup(ioc)
    assert not r.ok and "unexpected response" in r.error
    r = VirusTotal("k", FakeSession({"https://www.virustotal.com": odd})).lookup(ioc)
    assert not r.ok and "unexpected response" in r.error
