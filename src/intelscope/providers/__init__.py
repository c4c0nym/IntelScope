"""Threat intelligence source integrations."""

from __future__ import annotations

from typing import Any

from intelscope.providers.abuseipdb import AbuseIPDB
from intelscope.providers.asn import ASNBlocklist
from intelscope.providers.base import Provider
from intelscope.providers.greynoise import GreyNoise
from intelscope.providers.shodan import ShodanInternetDB
from intelscope.providers.urlhaus import URLhaus
from intelscope.providers.virustotal import VirusTotal

REGISTRY: dict[str, type[Provider]] = {
    cls.name: cls
    for cls in (VirusTotal, AbuseIPDB, URLhaus, GreyNoise, ShodanInternetDB, ASNBlocklist)
}

ALIASES = {
    "vt": "virustotal",
    "abuse": "abuseipdb",
    "gn": "greynoise",
    "internetdb": "shodan",
    "asndrop": "asn",
}

LABELS = {name: cls.label for name, cls in REGISTRY.items()}


def resolve_names(spec: str | None) -> list[str]:
    if not spec:
        return list(REGISTRY)
    names = []
    for raw in spec.split(","):
        name = ALIASES.get(raw.strip().lower(), raw.strip().lower())
        if not name:
            continue
        if name not in REGISTRY:
            raise ValueError(f"unknown provider '{raw.strip()}' (choose from {', '.join(REGISTRY)})")
        if name not in names:
            names.append(name)
    return names


def build_providers(
    spec: str | None = None, session: Any = None, asn_blocklist: str | None = None
) -> list[Provider]:
    providers = []
    for name in resolve_names(spec):
        if name == ASNBlocklist.name:
            providers.append(ASNBlocklist.from_env(session, blocklist_file=asn_blocklist))
        else:
            providers.append(REGISTRY[name].from_env(session))
    return providers


__all__ = ["Provider", "REGISTRY", "LABELS", "build_providers", "resolve_names"]
