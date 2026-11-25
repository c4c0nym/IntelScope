"""The dashboard server's key settings and tracker API."""

import json
import threading
import urllib.error
import urllib.request

import pytest

from intelscope import settings
from intelscope.server import serve


@pytest.fixture()
def live_server():
    """A non-demo server on an isolated home: keys and tracker go to tmp_path, not the real ones."""
    httpd = serve(port=0, demo=False, use_cache=False)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    token = json.loads(urllib.request.urlopen(base + "/api/health", timeout=5).read())["token"]
    yield base, token
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture()
def demo_server():
    httpd = serve(port=0, demo=True)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    token = json.loads(urllib.request.urlopen(base + "/api/health", timeout=5).read())["token"]
    yield base, token
    httpd.shutdown()
    httpd.server_close()


def call(base, token, path, body=None):
    headers = {"X-Intelscope-Token": token, "Content-Type": "application/json"}
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


# --------------------------------------------------------------------------- settings

def test_settings_need_the_token(live_server):
    base, _ = live_server
    assert call(base, "wrong", "/api/settings")[0] == 403
    assert call(base, "wrong", "/api/settings", {"provider": "censys", "values": {"api_key": "x"}})[0] == 403


def test_settings_list_every_source_with_fields_and_no_secret_values(live_server):
    base, token = live_server
    status, doc = call(base, token, "/api/settings")
    assert status == 200
    names = {p["name"] for p in doc["providers"]}
    assert {"censys", "urlscan", "intel471", "opencti", "abuseipdb", "greynoise", "virustotal"} <= names
    assert "asn" not in names and "shodan" not in names  # nothing to enter
    octi = next(p for p in doc["providers"] if p["name"] == "opencti")
    assert [f["name"] for f in octi["fields"]] == ["url", "api_key"] and not octi["configured"]


def test_session_key_is_used_but_never_written_or_echoed(live_server):
    base, token = live_server
    status, doc = call(base, token, "/api/settings",
                       {"provider": "censys", "values": {"api_key": "super-secret-token"}, "persist": False})
    assert status == 200
    censys = next(p for p in doc["providers"] if p["name"] == "censys")
    assert censys["configured"]
    field = censys["fields"][0]
    assert field["set"] and field["origin"] == "session" and field["preview"].endswith("oken")
    assert "super-secret-token" not in json.dumps(doc) and field["value"] == ""
    assert not settings.credentials_path().exists()
    health = json.loads(urllib.request.urlopen(base + "/api/health", timeout=5).read())
    assert next(p for p in health["providers"] if p["name"] == "censys")["configured"]


def test_saved_key_is_written_with_the_file_and_can_be_cleared(live_server):
    base, token = live_server
    call(base, token, "/api/settings", {"provider": "opencti", "persist": True,
                                        "values": {"url": "https://octi.test/", "api_key": "tok"}})
    assert settings.load_stored() == {"opencti": {"url": "https://octi.test", "api_key": "tok"}}
    _, doc = call(base, token, "/api/settings")
    octi = next(p for p in doc["providers"] if p["name"] == "opencti")
    assert octi["configured"] and octi["fields"][0]["value"] == "https://octi.test"  # urls are not secret
    call(base, token, "/api/settings", {"provider": "opencti", "values": {"api_key": ""}})
    assert settings.load_stored() == {"opencti": {"url": "https://octi.test"}}
    _, doc = call(base, token, "/api/settings")
    assert not next(p for p in doc["providers"] if p["name"] == "opencti")["configured"]


def test_settings_validation(live_server):
    base, token = live_server
    assert call(base, token, "/api/settings", {"provider": "nope", "values": {"api_key": "x"}})[0] == 400
    assert call(base, token, "/api/settings", {"provider": "censys", "values": {"wrong": "x"}})[0] == 400
    assert call(base, token, "/api/settings", {"provider": "opencti", "values": {"url": "ftp://x"}})[0] == 400
    assert call(base, token, "/api/settings", {"provider": "censys", "values": {"api_key": "a\nb"}})[0] == 400
    assert call(base, token, "/api/settings", {"provider": "asn", "values": {"api_key": "x"}})[0] == 400
    assert call(base, token, "/api/settings", {"provider": "censys", "values": {}})[0] == 400


def test_key_test_reports_not_configured_and_demo_stores_nothing(live_server, demo_server):
    base, token = live_server
    assert call(base, token, "/api/settings/test", {"provider": "censys"}) == (
        200, {"ok": False, "message": "not configured yet"})
    dbase, dtoken = demo_server
    status, doc = call(dbase, dtoken, "/api/settings", {"provider": "censys", "values": {"api_key": "x"}})
    assert status == 400 and "demo" in doc["error"]
    assert not settings.credentials_path().exists()


# --------------------------------------------------------------------------- tracker

def test_tracker_needs_the_token(live_server):
    base, _ = live_server
    assert call(base, "wrong", "/api/tracker")[0] == 403
    assert call(base, "wrong", "/api/tracker/add", {"text": "1.2.3.4"})[0] == 403


def test_tracker_add_list_update_export_delete(live_server):
    base, token = live_server
    status, doc = call(base, token, "/api/tracker/add", {
        "text": "198.51.100[.]23\nevil[.]test\nnot valid", "tlp": "amber", "context": "phish wave",
        "source": "Report 12", "date": "2026-11-24"})
    assert status == 200 and doc["added"] == 2 and doc["rejected"] == ["not", "valid"]
    _, doc = call(base, token, "/api/tracker")
    rows = doc["entries"]
    assert len(rows) == 2 and {r["tlp"] for r in rows} == {"AMBER"} and doc["tlp_levels"][0] == "CLEAR"
    assert {r["source"] for r in rows} == {"Report 12"} and {r["date"] for r in rows} == {"2026-11-24"}

    status, doc = call(base, token, "/api/tracker/update", {"id": rows[0]["id"], "fields": {"tlp": "red"}})
    assert status == 200 and doc["entry"]["tlp"] == "RED"
    assert call(base, token, "/api/tracker/update", {"id": rows[0]["id"], "fields": {"tlp": "mauve"}})[0] == 400

    status, doc = call(base, token, "/api/tracker/export", {})
    assert status == 200 and doc["rows"] == 2 and doc["filename"].startswith("ioc-tracker-")
    assert "**TLP:RED**" in doc["markdown"] and "Report 12" in doc["markdown"] and "[.]" in doc["markdown"]
    _, doc = call(base, token, "/api/tracker/export", {"max_tlp": "amber", "defang": False})
    assert doc["rows"] == 1 and "`evil.test`" in doc["markdown"]  # the RED row is left out of an AMBER export

    status, doc = call(base, token, "/api/tracker/delete", {"ids": [r["id"] for r in rows]})
    assert doc["removed"] == 2
    assert call(base, token, "/api/tracker")[1]["entries"] == []


def test_tracker_add_from_triage_results_keeps_verdict_and_score(live_server):
    base, token = live_server
    call(base, token, "/api/tracker/add", {"items": [{"ioc": "evil.test", "verdict": "malicious", "score": 92}],
                                           "tlp": "green", "source": "triage"})
    row = call(base, token, "/api/tracker")[1]["entries"][0]
    assert row["verdict"] == "malicious" and row["score"] == 92 and row["source"] == "triage"


def test_tracker_add_validation(live_server):
    base, token = live_server
    assert call(base, token, "/api/tracker/add", {"text": "1.2.3.4", "tlp": "mauve"})[0] == 400
    assert call(base, token, "/api/tracker/add", {"text": "1.2.3.4", "date": "yesterday"})[0] == 400
    assert call(base, token, "/api/tracker/add", {"text": "garbage only"})[0] == 400
    assert call(base, token, "/api/tracker/delete", {"ids": ["x"]})[0] == 400


def test_demo_tracker_lives_in_memory_only(demo_server, tmp_path):
    base, token = demo_server
    call(base, token, "/api/tracker/add", {"text": "198.51.100.23", "source": "demo"})
    assert len(call(base, token, "/api/tracker")[1]["entries"]) == 1
    assert not (tmp_path / "home" / "tracker.json").exists()


def test_dashboard_has_tracker_and_key_views(live_server):
    base, _ = live_server
    page = urllib.request.urlopen(base + "/", timeout=5).read()
    assert b'id="v-tracker"' in page and b'id="v-keys"' in page


def test_the_abusech_key_entered_on_one_card_shows_as_set_on_the_other(live_server):
    base, token = live_server
    _, doc = call(base, token, "/api/settings", {"provider": "threatfox", "values": {"api_key": "abuse-ch-key"},
                                                 "persist": False})
    cards = {p["name"]: p for p in doc["providers"]}
    assert cards["threatfox"]["configured"] and cards["urlhaus"]["configured"]
    assert cards["urlhaus"]["fields"][0]["set"] and "abuse-ch-key" not in json.dumps(doc)


# --------------------------------------------------------------------------- dump -> check -> list -> Markdown

MESSY = "198.51.100[.]23, 203.0.113.77\t192.0.2.10;secure-login-micros0ft[.]test\nintranet-portal.example | 8.8.8.8"


def _wait_for(base, token, job_id):
    import time

    for _ in range(100):
        _, doc = call(base, token, "/api/enrich/status", {"id": job_id})
        if doc["state"] != "running":
            return doc
        time.sleep(0.1)
    raise AssertionError("the check did not finish")


def test_enrich_job_reports_progress_and_the_result(demo_server):
    base, token = demo_server
    status, doc = call(base, token, "/api/enrich/start", {"iocs": MESSY.splitlines()})
    assert status == 200
    done = _wait_for(base, token, doc["id"])
    assert done["state"] == "done" and done["total"] > 0 and done["done"] == done["total"]
    assert {r["ioc"] for r in done["result"]["results"]} >= {"198.51.100.23", "203.0.113.77", "192.0.2.10",
                                                             "secure-login-micros0ft.test", "8.8.8.8"}
    assert done["result"]["results"][0]["verdict"] == "malicious"  # most urgent first


def test_enrich_job_validation(demo_server):
    base, token = demo_server
    assert call(base, token, "/api/enrich/start", {"iocs": ["nothing useful here"]})[0] == 400
    assert call(base, token, "/api/enrich/start", {"iocs": "x"})[0] == 400
    assert call(base, token, "/api/enrich/status", {"id": "nope"})[0] == 404
    assert call(base, "wrong", "/api/enrich/start", {"iocs": ["1.2.3.4"]})[0] == 403


def test_whole_flow_paste_check_list_export_import(demo_server, tmp_path):
    base, token = demo_server
    _, job = call(base, token, "/api/enrich/start", {"iocs": MESSY.splitlines()})
    results = _wait_for(base, token, job["id"])["result"]["results"]
    known = {r["ioc"]: {"verdict": r["verdict"], "score": r["score"]} for r in results}

    status, doc = call(base, token, "/api/tracker/add", {
        "text": MESSY, "known": known, "tlp": "amber", "source": "Dump 2026-11-25",
        "context": "pasted from a ticket", "date": "2026-11-25"})
    assert status == 200 and doc["added"] == 6 and doc["rejected"] == []
    rows = call(base, token, "/api/tracker")[1]["entries"]
    mal = next(r for r in rows if r["ioc"] == "198.51.100.23")
    assert mal["verdict"] == "malicious" and mal["score"] == 100 and mal["tlp"] == "AMBER"
    assert mal["confidence"] == "medium"

    md = call(base, token, "/api/tracker/export", {})[1]["markdown"]
    assert md.count("| Dump 2026-11-25 |") == 6
    call(base, token, "/api/tracker/delete", {"ids": [r["id"] for r in rows]})
    assert call(base, token, "/api/tracker")[1]["entries"] == []

    status, doc = call(base, token, "/api/tracker/import", {"markdown": md})
    assert status == 200 and doc == {"added": 6, "updated": 0, "errors": []}
    back = call(base, token, "/api/tracker")[1]["entries"]
    assert {r["ioc"] for r in back} == {r["ioc"] for r in rows}
    assert {r["tlp"] for r in back} == {"AMBER"} and {r["context"] for r in back} == {"pasted from a ticket"}


def test_markdown_import_errors_are_plain(demo_server):
    base, token = demo_server
    assert call(base, token, "/api/tracker/import", {"markdown": "no table here"})[0] == 400
    assert call(base, token, "/api/tracker/import", {"markdown": 5})[0] == 400
    assert call(base, "wrong", "/api/tracker/import", {"markdown": "| IOC |\n|---|\n| 1.2.3.4 |"})[0] == 403
