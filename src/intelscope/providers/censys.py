"""Censys: what an internet scanner sees on an IP (open ports, services, labels, network).

Two kinds of credential are accepted in the one key field:

* a Platform API personal access token (the current API, ``api.platform.censys.io``), with an
  optional organization ID, or
* ``API_ID:API_SECRET`` from the older Search v2 API (``search.censys.io``), kept so existing keys
  keep working.

Censys does not say whether a host is malicious, so it only scores when the host carries a
threat label such as ``c2``. Mostly it is context: ports, services and who runs the network.
"""

from __future__ import annotations

from typing import Any

from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.providers.base import Field, Provider

_BAD_LABELS = {"c2", "c2-server", "command-and-control", "malware", "botnet", "phishing", "ransomware"}


def _labels(host: dict[str, Any]) -> list[str]:
    out = []
    for item in host.get("labels") or []:
        value = (item.get("value") or item.get("name")) if isinstance(item, dict) else item
        if isinstance(value, str) and value:
            out.append(value.lower())
    return sorted(set(out))


class Censys(Provider):
    name = "censys"
    label = "Censys"
    env_key = "CENSYS_API_KEY"
    fields = (
        Field("api_key", "CENSYS_API_KEY", "Personal access token (or API_ID:API_SECRET)",
              hint="Platform token from censys.com, or the legacy ID:secret pair"),
        Field("org", "CENSYS_ORG_ID", "Organization ID", secret=False, required=False, kind="text",
              hint="Only if your token needs one"),
    )
    note = "Free accounts get a small monthly quota. Only IP addresses are looked up."
    supports = frozenset({IOCType.IPV4, IOCType.IPV6})
    rate_limit = (10, 60.0)
    weight = 0.6
    PLATFORM = "https://api.platform.censys.io/v3/global/asset/host"
    LEGACY = "https://search.censys.io/api/v2/hosts"

    def _fetch(self, ip: str):
        key = self.api_key or ""
        if ":" in key:  # legacy API ID:secret
            user, _, secret = key.partition(":")
            return self.session.get(f"{self.LEGACY}/{ip}", auth=(user, secret),
                                    headers={"Accept": "application/json"}, timeout=self.timeout)
        params = {"organization_id": self.extra["org"]} if self.extra.get("org") else None
        return self.session.get(
            f"{self.PLATFORM}/{ip}",
            params=params,
            headers={"Authorization": f"Bearer {key}",
                     "Accept": "application/vnd.censys.api.v3.host.v1+json"},
            timeout=self.timeout,
        )

    def _lookup(self, ioc: IOC) -> ProviderResult:
        resp = self._fetch(ioc.value)
        if resp.status_code == 404:
            return self._not_found("not in the Censys dataset")
        resp.raise_for_status()
        payload = resp.json()
        result = payload.get("result") or {}
        host = result.get("resource") or result  # v3 nests the host under "resource"
        services = [s for s in (host.get("services") or []) if isinstance(s, dict)]

        ports = sorted({s["port"] for s in services if isinstance(s.get("port"), int)})
        names = sorted({str(s.get("protocol") or s.get("service_name") or "").lower()
                        for s in services} - {""})
        asys = host.get("autonomous_system") or {}
        loc = host.get("location") or {}
        country = loc.get("country_code") or loc.get("country")
        labels = _labels(host)
        bad = sorted(set(labels) & _BAD_LABELS)

        parts = []
        if ports:
            parts.append("ports " + ", ".join(map(str, ports[:12])) + (" …" if len(ports) > 12 else ""))
        if names:
            parts.append(", ".join(names[:6]))
        if labels:
            parts.append("labels: " + ", ".join(labels[:6]))
        asn = f"AS{asys['asn']}" if asys.get("asn") else ""
        net = " ".join(x for x in (asn, asys.get("name") or "") if x)
        if net:
            parts.append(net)
        summary = " · ".join(parts) or "host known, no services recorded"
        return self._result(
            score=60 if bad else None,
            summary=("threat label " + ", ".join(bad) + " · " + summary) if bad else summary,
            found=bool(services or labels or asys),
            data={"ports": ports, "services": names, "labels": labels, "asn": asys.get("asn"),
                  "as_name": asys.get("name"), "country": country},
        )
