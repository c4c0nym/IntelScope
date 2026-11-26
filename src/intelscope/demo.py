"""Offline demo mode: canned provider responses, no API keys or network needed.

All IPs come from the RFC 5737 documentation ranges and all domains use the reserved
``.test`` / ``.example`` TLDs, so the sample data never accuses a real host.
The one real value is the EICAR anti-virus *test file* hash, which is harmless.
"""

from __future__ import annotations

from typing import Any

from intelscope.models import IOC, ProviderResult
from intelscope.providers import REGISTRY
from intelscope.providers.base import Provider

DEMO_IOCS = [
    "198.51.100[.]23",
    "hxxp://update-check[.]cdn-delivery[.]test/payload/inv_2291.exe",
    "secure-login-micros0ft[.]test",
    "44d88612fea8a8f36de82e1278abb02f",
    "203.0.113.77",
    "192.0.2.10",
    "intranet-portal.example",
    "8.8.8.8",
]

_URL = "http://update-check.cdn-delivery.test/payload/inv_2291.exe"

# provider -> indicator -> ProviderResult fields
CANNED: dict[str, dict[str, dict[str, Any]]] = {
    "virustotal": {
        "198.51.100.23": {"score": 84, "summary": "7/94 engines malicious, 2 suspicious"},
        _URL: {"score": 100, "summary": "18/96 engines malicious · trojan.agenttesla"},
        "secure-login-micros0ft.test": {"score": 48, "summary": "4/94 engines malicious"},
        "44d88612fea8a8f36de82e1278abb02f": {
            "score": 100,
            "summary": "61/72 engines malicious · eicar/test-file",
        },
        "203.0.113.77": {"score": 0, "summary": "0/94 engines malicious"},
        "192.0.2.10": {"score": 12, "summary": "1/94 engines malicious"},
    },
    "abuseipdb": {
        "198.51.100.23": {
            "score": 100,
            "summary": "100% abuse confidence, 1,284 reports (90d) · ExampleHost / NL",
        },
        "203.0.113.77": {"score": 0, "summary": "0% abuse confidence, 0 reports (90d)"},
        "192.0.2.10": {"score": 34, "summary": "34% abuse confidence, 41 reports (90d)"},
    },
    "urlhaus": {
        _URL: {"score": 95, "summary": "malware_download URL, online · AgentTesla, exe"},
    },
    "threatfox": {
        "198.51.100.23": {
            "score": 85,
            "summary": "1 ThreatFox indicator · ExampleLoader · botnet C2 · confidence 85%",
        },
        _URL: {
            "score": 75,
            "summary": "1 ThreatFox indicator · AgentTesla · payload delivery · confidence 75%",
        },
    },
    "greynoise": {
        "198.51.100.23": {"score": 70, "summary": "classified malicious (mass scanning)"},
        "203.0.113.77": {
            "score": 0,
            "benign": True,
            "summary": "known business service (RIOT): Example Search Crawler",
        },
        "192.0.2.10": {"score": 20, "summary": "internet background noise"},
    },
    # documentation ASNs (RFC 5398), never real networks
    "asn": {
        "198.51.100.23": {"score": 75, "summary": "AS64500 EXAMPLE-BULLETPROOF is on Spamhaus ASN-DROP"},
        "203.0.113.77": {
            "score": None,
            "summary": "AS64501 EXAMPLE-SEARCH · 203.0.113.0/24 · not blocklisted",
        },
        "192.0.2.10": {"score": None, "summary": "AS64502 EXAMPLE-HOSTING · 192.0.2.0/24 · not blocklisted"},
    },
    "shodan": {
        "198.51.100.23": {"score": None, "summary": "ports 22, 3389 · tags: self-signed"},
        "192.0.2.10": {"score": None, "summary": "ports 80, 443, 8080 · 3 CVEs"},
    },
    "censys": {
        "198.51.100.23": {
            "score": 60,
            "summary": "threat label c2 · ports 22, 3389, 8443 · ssh, rdp, http · AS64500 EXAMPLE-BULLETPROOF",  # noqa: E501
        },
        "192.0.2.10": {
            "score": None,
            "summary": "ports 80, 443, 8080 · http, https · AS64502 EXAMPLE-HOSTING",
        },
    },
    "urlscan": {
        _URL: {"score": 75, "summary": "4 public scans · latest 2026-11-20 · verdict: malicious"},
        "secure-login-micros0ft.test": {
            "score": 55,
            "summary": "9 public scans · latest 2026-11-22 · impersonates Microsoft",
        },
        "192.0.2.10": {"score": None, "summary": "2 public scans · latest 2026-10-02"},
    },
    "rdap": {
        "secure-login-micros0ft.test": {
            "score": 70,
            "summary": "registered 2026-11-22 (3 days ago) · Example Registrar Inc.",
        },
    },
    "pdns": {
        "198.51.100.23": {
            "score": None,
            "summary": "38 records · 3 distinct domains · 2026-09-14 to 2026-11-20 · e.g. update-check.cdn-delivery.test, secure-login-micros0ft.test",  # noqa: E501
        },
        "secure-login-micros0ft.test": {
            "score": None,
            "summary": "6 records · 1 distinct addresses · 2026-11-22 to 2026-11-24 · e.g. 198.51.100.23",
        },
        "192.0.2.10": {
            "score": None,
            "summary": "412 records · 87 distinct domains · 2024-02-01 to 2026-11-25 · e.g. shop-one.example, blog-two.example (+85)",  # noqa: E501
        },
    },
    "opencti": {
        "198.51.100.23": {"score": 80, "summary": "known observable · score 80 · labels: c2, tlp-amber"},
        "secure-login-micros0ft.test": {"score": None, "summary": "known observable · labels: phishing"},
    },
}


class DemoProvider(Provider):
    key_required = False
    rate_limit = (1000, 1.0)

    def __init__(self, real: type[Provider]) -> None:
        super().__init__(api_key=None, session=object())
        self.name = real.name  # type: ignore[misc]
        self.label = real.label  # type: ignore[misc]
        self.supports = real.supports  # type: ignore[misc]
        self.weight = real.weight  # type: ignore[misc]
        self._canned = CANNED.get(real.name, {})

    def _lookup(self, ioc: IOC) -> ProviderResult:
        canned = self._canned.get(ioc.value)
        if canned is None:
            return self._not_found("no record")
        return self._result(**canned)


def build_demo_providers(names: list[str]) -> list[Provider]:
    return [DemoProvider(REGISTRY[name]) for name in names]
