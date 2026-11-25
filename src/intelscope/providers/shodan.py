"""Shodan InternetDB: free, keyless exposure data for an IP (ports, CVEs, tags)."""

from __future__ import annotations

from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.providers.base import Provider

# InternetDB tags that indicate the host itself is attacker-controlled or compromised.
_HOSTILE_TAGS = {"c2", "compromised", "malware", "botnet"}


class ShodanInternetDB(Provider):
    name = "shodan"
    label = "Shodan InternetDB"
    env_key = None
    key_required = False
    supports = frozenset({IOCType.IPV4})
    rate_limit = (30, 60.0)
    weight = 0.5
    BASE = "https://internetdb.shodan.io"

    def _lookup(self, ioc: IOC) -> ProviderResult:
        resp = self.session.get(f"{self.BASE}/{ioc.value}", timeout=self.timeout)
        if resp.status_code == 404:
            return self._not_found("no services indexed")
        resp.raise_for_status()
        d = resp.json()

        ports = sorted(d.get("ports") or [])
        vulns = sorted(d.get("vulns") or [])
        tags = sorted(d.get("tags") or [])
        hostile = sorted(set(tags) & _HOSTILE_TAGS)

        parts = []
        if ports:
            shown = ", ".join(map(str, ports[:6])) + ("…" if len(ports) > 6 else "")
            parts.append(f"ports {shown}")
        if vulns:
            parts.append(f"{len(vulns)} CVE{'s' if len(vulns) != 1 else ''}")
        if tags:
            parts.append(f"tags: {', '.join(tags)}")
        return self._result(
            # Exposure is context, not maliciousness, unless Shodan tags the host as hostile.
            score=60 if hostile else None,
            summary=" · ".join(parts) or "indexed, no open ports",
            data={
                "ports": ports,
                "vulns": vulns,
                "tags": tags,
                "hostnames": d.get("hostnames"),
                "cpes": d.get("cpes"),
            },
        )
