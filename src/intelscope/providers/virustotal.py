"""VirusTotal API v3."""

from __future__ import annotations

import base64

from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.providers.base import Provider

_COLLECTIONS = {
    IOCType.IPV4: "ip_addresses",
    IOCType.IPV6: "ip_addresses",
    IOCType.DOMAIN: "domains",
    IOCType.URL: "urls",
    IOCType.MD5: "files",
    IOCType.SHA1: "files",
    IOCType.SHA256: "files",
}


def url_id(url: str) -> str:
    """VirusTotal identifies URLs by unpadded URL-safe base64."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotal(Provider):
    name = "virustotal"
    label = "VirusTotal"
    env_key = "VT_API_KEY"
    supports = frozenset(_COLLECTIONS)
    rate_limit = (4, 60.0)  # public API tier
    weight = 1.0
    BASE = "https://www.virustotal.com/api/v3"

    def _lookup(self, ioc: IOC) -> ProviderResult:
        ident = url_id(ioc.value) if ioc.type is IOCType.URL else ioc.value
        resp = self.session.get(
            f"{self.BASE}/{_COLLECTIONS[ioc.type]}/{ident}",
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
            timeout=self.timeout,
        )
        if resp.status_code == 404:
            return self._not_found("not in VirusTotal")
        resp.raise_for_status()
        attrs = resp.json()["data"]["attributes"]

        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        engines = malicious + suspicious + int(stats.get("harmless", 0)) + int(
            stats.get("undetected", 0)
        )
        # A couple of detections are often false positives; five or more is a strong signal.
        score = min(100, malicious * 12 + suspicious * 4)

        data = {
            "malicious": malicious,
            "suspicious": suspicious,
            "engines": engines,
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags"),
        }
        label = None
        if ioc.type.is_hash:
            label = (attrs.get("popular_threat_classification") or {}).get(
                "suggested_threat_label"
            )
            data.update(
                name=attrs.get("meaningful_name"),
                file_type=attrs.get("type_description"),
                threat_label=label,
            )
        elif ioc.type.is_ip:
            data.update(
                asn=attrs.get("asn"),
                as_owner=attrs.get("as_owner"),
                country=attrs.get("country"),
            )

        summary = f"{malicious}/{engines} engines malicious"
        if suspicious:
            summary += f", {suspicious} suspicious"
        if label:
            summary += f" · {label}"
        return self._result(score=score, summary=summary, data=data)
