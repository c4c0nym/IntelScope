import pytest

from iocscope.detect import classify, parse_iocs, refang
from iocscope.models import IOCType


@pytest.mark.parametrize(
    ("raw", "value", "kind"),
    [
        ("1.2.3.4", "1.2.3.4", IOCType.IPV4),
        ("1.2.3[.]4", "1.2.3.4", IOCType.IPV4),
        ("2001:DB8::1", "2001:db8::1", IOCType.IPV6),
        ("[2001:db8::1]", "2001:db8::1", IOCType.IPV6),
        ("Evil.Example.COM.", "evil.example.com", IOCType.DOMAIN),
        ("evil(.)example[dot]com", "evil.example.com", IOCType.DOMAIN),
        ("xn--80ak6aa92e.com", "xn--80ak6aa92e.com", IOCType.DOMAIN),
        ("hxxps://evil[.]com/a?b=1", "https://evil.com/a?b=1", IOCType.URL),
        ("hXXp[:]//evil[.]com/x", "http://evil.com/x", IOCType.URL),
        ("44D88612FEA8A8F36DE82E1278ABB02F", "44d88612fea8a8f36de82e1278abb02f", IOCType.MD5),
        ("3395856ce81f2b7382dee72602f798b642f14140", "3395856ce81f2b7382dee72602f798b642f14140",
         IOCType.SHA1),
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
         "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", IOCType.SHA256),
    ],
)
def test_classify(raw, value, kind):
    result = classify(raw)
    assert result is not None
    assert (result.value, result.type) == (value, kind)
    assert result.original == raw


@pytest.mark.parametrize(
    "raw", ["", "hello", "300.1.1.1", "ftp://files.example.com/x", "abc123", "localhost", "a.b"]
)
def test_classify_rejects(raw):
    assert classify(raw) is None


def test_refang_leaves_clean_values_alone():
    assert refang("https://example.com/path") == "https://example.com/path"


def test_parse_iocs_dedupes_and_skips_comments():
    lines = [
        "# header comment",
        "",
        "1.2.3.4, evil[.]com  # inline note",
        "1.2.3[.]4",
        "EVIL.com not_an_ioc",
    ]
    iocs, rejected = parse_iocs(lines)
    assert [i.value for i in iocs] == ["1.2.3.4", "evil.com"]
    assert rejected == ["not_an_ioc"]
