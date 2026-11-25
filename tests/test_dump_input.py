"""A pasted dump of indicators: any delimiter, decoration or defanging, and the Markdown round trip."""

import pytest

from intelscope.detect import parse_iocs
from intelscope.tracker import Tracker, parse_markdown, to_markdown

TEN = ["198.51.100.23", "203.0.113.77", "192.0.2.10", "8.8.8.8", "1.1.1.1",
       "evil-login.example", "secure-update.test", "cdn.bad-site.example", "phish.example.org", "c2.example.net"]


def values(text: str) -> list[str]:
    iocs, _ = parse_iocs(text.splitlines())
    return [i.value for i in iocs]


@pytest.mark.parametrize("sep", ["\n", " ", "\t", ",", ", ", ";", " ; ", "|", " | ", "\r\n", "  \t ,\n", ",\n"])
def test_ten_indicators_with_any_delimiter(sep):
    assert values(sep.join(TEN)) == TEN


def test_mixed_delimiters_in_one_paste():
    text = "198.51.100.23, 203.0.113.77\t192.0.2.10;8.8.8.8\n\n  1.1.1.1 | evil-login.example\r\nsecure-update.test,cdn.bad-site.example phish.example.org\tc2.example.net"
    assert values(text) == TEN


def test_defanged_decorated_and_quoted_tokens():
    text = '"198.51.100[.]23", (203.0.113.77) <192.0.2.10> [8.8.8.8] \'evil-login[.]example\' secure-update(.)test.'
    assert values(text) == ["198.51.100.23", "203.0.113.77", "192.0.2.10", "8.8.8.8", "evil-login.example",
                            "secure-update.test"]


def test_ports_bullets_numbers_and_comments_are_handled():
    text = "- 198.51.100.23:443\n* evil-login.example:8080\n1. 203.0.113.77\n2) 192.0.2.10   # the scanner\n• c2.example.net"
    iocs, rejected = parse_iocs(text.splitlines())
    assert [i.value for i in iocs] == ["198.51.100.23", "evil-login.example", "203.0.113.77", "192.0.2.10",
                                       "c2.example.net"]
    assert rejected == []  # bullets and numbering are not "unrecognised indicators"


def test_ipv6_and_urls_survive_the_trimming():
    iocs, _ = parse_iocs(["[2001:db8::1] 2001:db8::2 http://evil.test/a?b=(1) https://evil.test/x,"])
    assert [i.value for i in iocs] == ["2001:db8::1", "2001:db8::2", "http://evil.test/a?b=(1)",
                                       "https://evil.test/x"]


def test_duplicates_collapse_and_junk_is_reported():
    iocs, rejected = parse_iocs(["1.2.3.4 1.2.3[.]4 1.2.3.4, hello 999.1.1.1"])
    assert [i.value for i in iocs] == ["1.2.3.4"] and rejected == ["hello", "999.1.1.1"]


# --------------------------------------------------------------------------- Markdown import


def test_markdown_round_trip(tmp_path):
    src = Tracker(tmp_path / "a.json")
    src.add("198.51.100.23", tlp="amber", source="CERT report | 12", context="C2 for <loader>, see \\notes",
            when="2026-11-24")
    src.add("https://evil.test/panel", tlp="red", source="Case 7", context="phishing kit", when="2026-11-20")
    src.add("evil.test", tlp="green", source="", context="", when="2026-11-21")
    md = to_markdown(src.entries())

    dst = Tracker(tmp_path / "b.json")
    result = dst.import_markdown(md)
    assert result == {"added": 3, "updated": 0, "errors": []}
    by_ioc = {e.ioc: e for e in dst.entries()}
    a = by_ioc["198.51.100.23"]
    assert (a.tlp, a.source, a.date, a.context) == ("AMBER", "CERT report | 12", "2026-11-24",
                                                   "C2 for <loader>, see \\notes")
    assert by_ioc["https://evil.test/panel"].tlp == "RED"  # defanged in the file, refanged on import
    assert by_ioc["evil.test"].source == "" and by_ioc["evil.test"].context == ""

    again = dst.import_markdown(md)  # importing twice updates, never duplicates
    assert again["added"] == 0 and again["updated"] == 3 and len(dst.entries()) == 3


def test_markdown_import_is_tolerant_about_columns_and_labels(tmp_path):
    text = """Some notes above the table.

| Indicator | Notes | TLP:  | Source |
|:--|---|:-:|---|
| `198[.]51[.]100[.]23` | seen at the VPN | tlp:green | Peer group |
| evil-login[.]example | | | |
| not an ioc | x | red | y |

Trailing text.
"""
    t = Tracker(tmp_path / "t.json")
    result = t.import_markdown(text)
    assert result["added"] == 2 and len(result["errors"]) == 1 and "not an ioc" in result["errors"][0]
    rows = {e.ioc: e for e in t.entries()}
    assert rows["198.51.100.23"].tlp == "GREEN" and rows["198.51.100.23"].context == "seen at the VPN"
    assert rows["evil-login.example"].tlp == "AMBER"  # unlabelled means AMBER


def test_markdown_without_a_table_says_so(tmp_path):
    t = Tracker(tmp_path / "t.json")
    with pytest.raises(ValueError, match="table"):
        t.import_markdown("just some text, 1.2.3.4")
    assert parse_markdown("| a | b |\n|---|---|\n| 1 | 2 |") == []  # a table without an IOC column
