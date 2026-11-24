from iocscope.allowlist import Allowlist, load_allowlist
from iocscope.detect import classify


def check(allowlist, raw):
    return allowlist.match(classify(raw))


def test_reserved_and_known_resolvers():
    al = load_allowlist()
    assert check(al, "10.0.0.5") == "non-routable / reserved address"
    assert check(al, "127.0.0.1")
    assert check(al, "8.8.8.8") == "allowlisted IP"
    assert check(al, "185.220.101.1") is None


def test_domain_suffix_matching():
    al = load_allowlist()
    assert check(al, "update.microsoft.com")
    assert check(al, "microsoft.com")
    assert check(al, "notmicrosoft.com") is None
    assert check(al, "microsoft.com.evil.example") is None


def test_urls_are_never_allowlisted_by_host():
    al = load_allowlist()
    assert check(al, "https://docs.google.com/uc?id=payload") is None


def test_skip_reserved_can_be_disabled():
    al = load_allowlist(skip_reserved=False)
    assert check(al, "192.0.2.10") is None


def test_file_entries(tmp_path):
    path = tmp_path / "allow.txt"
    path.write_text("# corp ranges\n203.0.113.0/24\n198.51.100.9\ncorp.example # intranet\n")
    al = load_allowlist(path, include_defaults=False, skip_reserved=False)
    assert check(al, "203.0.113.50") == "allowlisted network"
    assert check(al, "198.51.100.9") == "allowlisted IP"
    assert check(al, "vpn.corp.example")
    assert check(al, "8.8.8.8") is None


def test_ipv6_against_ipv4_network_does_not_crash():
    al = Allowlist(networks=[__import__("ipaddress").ip_network("203.0.113.0/24")],
                   skip_reserved=False)
    assert check(al, "2a00:1450::1") is None
