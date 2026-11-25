"""The IOC tracker, its Markdown export, stored credentials, and the keys/track CLI."""

import json

import pytest

from intelscope import settings
from intelscope.cli import main
from intelscope.tracker import Tracker, defang, normalize_date, normalize_tlp, to_markdown

# --------------------------------------------------------------------------- tracker


def test_tlp_names_are_normalised():
    assert normalize_tlp("tlp:amber") == "AMBER"
    assert normalize_tlp("White") == "CLEAR"
    assert normalize_tlp("amber strict") == "AMBER+STRICT"
    assert normalize_tlp("") == "AMBER"  # unlabelled data is treated as restricted
    with pytest.raises(ValueError):
        normalize_tlp("purple")


def test_dates():
    assert normalize_date("2026-11-25") == "2026-11-25"
    assert normalize_date("2026-11-25T10:00:00Z") == "2026-11-25"
    assert len(normalize_date("")) == 10
    with pytest.raises(ValueError):
        normalize_date("25/11/2026")


def test_add_keeps_ioc_tlp_context_source_and_date(tmp_path):
    t = Tracker(tmp_path / "t.json")
    entry, created = t.add("198.51.100[.]23", tlp="red", context="C2 for the loader", source="Report 12",
                           when="2026-11-24")
    assert created
    assert (entry.ioc, entry.type, entry.tlp, entry.context, entry.source, entry.date) == (
        "198.51.100.23", "ipv4", "RED", "C2 for the loader", "Report 12", "2026-11-24")
    again = Tracker(tmp_path / "t.json").entries()  # survives a restart
    assert [e.ioc for e in again] == ["198.51.100.23"] and again[0].tlp == "RED"


def test_same_ioc_and_source_updates_but_another_source_adds_a_row(tmp_path):
    t = Tracker(tmp_path / "t.json")
    first, _ = t.add("evil.test", tlp="green", source="Feed A", context="old")
    same, created = t.add("EVIL.test", tlp="amber", source="feed a", context="new")
    assert not created and same.id == first.id and same.tlp == "AMBER" and same.context == "new"
    _, created = t.add("evil.test", tlp="green", source="Feed B")
    assert created and len(t.entries()) == 2


def test_rejects_bad_input_and_keeps_going(tmp_path):
    t = Tracker(tmp_path / "t.json")
    with pytest.raises(ValueError):
        t.add("not an indicator")
    with pytest.raises(ValueError):
        t.add("1.2.3.4", tlp="mauve")
    with pytest.raises(ValueError):
        t.add("1.2.3.4", context="x" * 2001)
    assert t.entries() == []


def test_update_remove_and_search(tmp_path):
    t = Tracker(tmp_path / "t.json")
    a, _ = t.add("1.2.3.4", tlp="green", source="Feed A", context="scanner")
    b, _ = t.add("evil.test", tlp="red", source="Case 7", context="phishing kit")
    assert t.update(a.id, tlp="amber", context="mass scanner").tlp == "AMBER"
    assert [e.ioc for e in t.search(tlp="red")] == ["evil.test"]
    assert [e.ioc for e in t.search(text="phishing")] == ["evil.test"]
    assert [e.ioc for e in t.search(source="feed")] == ["1.2.3.4"]
    assert [e.ioc for e in t.search(max_tlp="amber")] == ["1.2.3.4"]
    with pytest.raises(KeyError):
        t.update(999, tlp="red")
    with pytest.raises(ValueError):
        t.update(a.id, ioc="9.9.9.9")
    assert t.remove([b.id, 999]) == 1 and len(t.entries()) == 1


def test_ids_are_not_reused_after_a_delete(tmp_path):
    t = Tracker(tmp_path / "t.json")
    a, _ = t.add("1.2.3.4")
    t.remove([a.id])
    b, _ = t.add("5.6.7.8")
    assert b.id != a.id


def test_memory_tracker_writes_nothing(tmp_path):
    t = Tracker(None)
    t.add("1.2.3.4")
    assert len(t.entries()) == 1 and list(tmp_path.iterdir()) == []


def test_corrupt_file_is_an_error_not_a_silent_reset(tmp_path):
    path = tmp_path / "t.json"
    path.write_text("{not json")
    with pytest.raises(ValueError):
        Tracker(path).entries()
    assert path.read_text() == "{not json"


# --------------------------------------------------------------------------- Markdown

def test_defang():
    assert defang("198.51.100.23") == "198[.]51[.]100[.]23"
    assert defang("https://evil.test/a.exe") == "hxxps://evil[.]test/a[.]exe"
    assert defang("a" * 64) == "a" * 64


def test_markdown_has_every_field_and_a_tlp_banner(tmp_path):
    t = Tracker(tmp_path / "t.json")
    t.add("198.51.100.23", tlp="amber", context="C2 | seen in <logs>", source="Report 12", when="2026-11-24")
    t.add("https://evil.test/x", tlp="green", context="line one\nline two", source="Feed", when="2026-11-25")
    md = to_markdown(t.entries())
    assert md.startswith("# IOC tracker")
    assert "**TLP:AMBER**" in md and "1 AMBER" in md and "1 GREEN" in md
    assert "| IOC | Type | TLP | Confidence | Source | Date | Context |" in md
    assert "| `198[.]51[.]100[.]23` | ipv4 | AMBER | medium | Report 12 | 2026-11-24 | C2 \\| seen in &lt;logs&gt; |" in md
    assert "| `hxxps://evil[.]test/x` | url | GREEN | Feed | 2026-11-25 | line one line two |" in md
    assert md.index("evil[.]test") < md.index("198[.]51")  # newest first
    assert "https://evil.test" not in md  # defanged, so nothing renders as a live link


def test_markdown_raw_mode_and_empty_tracker(tmp_path):
    t = Tracker(tmp_path / "t.json")
    assert "No indicators tracked yet" in to_markdown([])
    t.add("evil.test", tlp="red")
    raw = to_markdown(t.entries(), defanged=False)
    assert "`evil.test`" in raw and "live" in raw and "TLP:RED" in raw


# --------------------------------------------------------------------------- stored credentials

def test_stored_credentials_roundtrip_and_clear():
    settings.set_stored("censys", {"api_key": "tok", "org": "o1"})
    assert settings.load_stored() == {"censys": {"api_key": "tok", "org": "o1"}}
    settings.set_stored("censys", {"org": ""})
    assert settings.load_stored() == {"censys": {"api_key": "tok"}}
    assert settings.remove_stored("censys") and settings.load_stored() == {}
    assert not settings.remove_stored("censys")


def test_stored_file_lives_under_the_isolated_home(tmp_path):
    settings.set_stored("urlscan", {"api_key": "k"})
    assert settings.credentials_path().is_file()
    assert str(settings.credentials_path()).startswith(str(tmp_path))


def test_saved_key_beats_environment_and_session_beats_saved(monkeypatch):
    from intelscope.providers.censys import Censys

    monkeypatch.setenv("CENSYS_API_KEY", "from-env")
    assert Censys.from_env().api_key == "from-env"
    settings.set_stored("censys", {"api_key": "from-file"})
    assert Censys.from_env().api_key == "from-file"
    assert Censys.from_env(None, {"censys": {"api_key": "from-session"}}).api_key == "from-session"


def test_clean_value_rules():
    assert settings.clean_value("  abc  ") == "abc"
    assert settings.clean_value("https://octi.test/", "url") == "https://octi.test"
    with pytest.raises(ValueError):
        settings.clean_value("javascript:alert(1)", "url")
    with pytest.raises(ValueError):
        settings.clean_value("a\nb")
    assert settings.mask("abcdefghij") == "••••ghij"


# --------------------------------------------------------------------------- CLI

def test_cli_track_add_list_export(tmp_path, capsys):
    db = str(tmp_path / "t.json")
    assert main(["track", "--db", db, "add", "198.51.100[.]23", "evil[.]test", "--tlp", "AMBER",
                 "--source", "Report 12", "--context", "phish wave", "--date", "2026-11-24"]) == 0
    assert main(["track", "--db", db, "add", "198.51.100.23", "--tlp", "GREEN", "--source", "Report 12"]) == 0
    rows = Tracker(db).entries()
    assert len(rows) == 2 and {e.tlp for e in rows} == {"AMBER", "GREEN"}
    out = tmp_path / "iocs.md"
    assert main(["track", "--db", db, "export", "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "evil[.]test" in text and "Report 12" in text and "2026-11-24" in text and "phish wave" in text
    assert main(["track", "--db", db, "export", "--max-tlp", "GREEN", "-o", str(out)]) == 0
    assert "evil[.]test" not in out.read_text(encoding="utf-8")
    assert main(["track", "--db", db, "edit", str(rows[0].id), "--tlp", "red"]) == 0
    assert Tracker(db).entries()[0].tlp == "RED"
    assert main(["track", "--db", db, "remove", str(rows[0].id)]) == 0
    assert main(["track", "--db", db, "remove", "999"]) == 1
    assert main(["track", "--db", db, "list"]) == 0


def test_cli_track_rejects_bad_tlp_and_nothing_valid(tmp_path):
    db = str(tmp_path / "t.json")
    assert main(["track", "--db", db, "add", "1.2.3.4", "--tlp", "mauve"]) == 2
    assert main(["track", "--db", db, "add", "not-an-ioc"]) == 2


def test_cli_enrich_with_track_flag_stores_verdicts(tmp_path, monkeypatch):
    monkeypatch.setenv("INTELSCOPE_TRACKER", str(tmp_path / "t.json"))
    assert main(["--demo", "--track", "--tlp", "green", "--source", "demo run", "--context", "sample",
                 "--format", "json", "-q"]) == 0
    rows = Tracker(tmp_path / "t.json").entries()
    assert len(rows) >= 7 and {e.source for e in rows} == {"demo run"}
    assert any(e.verdict == "malicious" and e.score for e in rows)


def test_cli_track_flag_fails_before_spending_quota_on_a_bad_tlp(tmp_path, monkeypatch):
    monkeypatch.setenv("INTELSCOPE_TRACKER", str(tmp_path / "t.json"))
    assert main(["--demo", "--track", "--tlp", "mauve", "-q"]) == 2
    assert not (tmp_path / "t.json").exists()


def test_cli_markdown_report_is_defanged(tmp_path):
    out = tmp_path / "r.md"
    assert main(["--demo", "-o", str(out), "-q"]) == 0
    text = out.read_text(encoding="utf-8")
    assert text.startswith("# IntelScope triage") and "| Verdict | Score |" in text
    assert "198[.]51[.]100[.]23" in text and "hxxp://" in text


def test_cli_keys_list_and_remove(capsys):
    settings.set_stored("opencti", {"url": "https://octi.test", "api_key": "secret-token"})
    assert main(["keys", "list"]) == 0
    shown = capsys.readouterr().out
    assert "OpenCTI" in shown and "secret-token" not in shown  # never printed
    assert main(["keys", "remove", "octi"]) == 0
    assert settings.load_stored() == {}


def test_cli_keys_set_refuses_without_a_terminal():
    assert main(["keys", "set", "censys"]) == 2  # secrets are never taken from arguments or pipes


def test_cli_list_providers_shows_new_sources(capsys):
    assert main(["--list-providers"]) == 0
    out = capsys.readouterr().out
    for label in ("Censys", "urlscan.io", "Intel 471", "OpenCTI", "AbuseIPDB", "GreyNoise"):
        assert label in out


def test_tracker_file_is_plain_json(tmp_path):
    t = Tracker(tmp_path / "t.json")
    t.add("1.2.3.4", source="x")
    doc = json.loads((tmp_path / "t.json").read_text(encoding="utf-8"))
    assert doc["entries"][0]["ioc"] == "1.2.3.4" and doc["next_id"] == 2


def test_cli_track_import_round_trip(tmp_path):
    a, b = str(tmp_path / "a.json"), str(tmp_path / "b.json")
    assert main(["track", "--db", a, "add", "198.51.100[.]23", "evil[.]example", "--tlp", "RED",
                 "--source", "Report 12", "--context", "phish", "--date", "2026-11-24"]) == 0
    md = tmp_path / "iocs.md"
    assert main(["track", "--db", a, "export", "-o", str(md)]) == 0
    assert main(["track", "--db", b, "import", str(md)]) == 0
    def rows(path):  # the export is newest first, so compare the content, not the order
        return sorted((e.ioc, e.tlp, e.source, e.date, e.context) for e in Tracker(path).entries())

    assert rows(b) == rows(a) and len(rows(a)) == 2
    (tmp_path / "bad.md").write_text("nothing here")
    assert main(["track", "--db", b, "import", str(tmp_path / "bad.md")]) == 2
