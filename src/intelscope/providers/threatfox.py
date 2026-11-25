"""abuse.ch ThreatFox: confirmed IOCs (botnet C2, payload delivery) tied to malware families.

Uses the same free Auth-Key as URLhaus (https://auth.abuse.ch/). A hit means the community has
confirmed the indicator as malicious infrastructure, so the score is ThreatFox's own confidence
(50-100, 75 when it gives none). IPs are matched whatever port ThreatFox recorded them with.
A file hash matches when the sample is linked to ThreatFox indicators, e.g. as the malware that
talks to a listed C2. ThreatFox no longer exposes indicators older than six months.
"""

from __future__ import annotations

import re
from typing import Any

from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.providers.base import Provider

_THREATS = {"botnet_cc": "botnet C2", "payload_delivery": "payload delivery"}
_PORT = re.compile(r":\d{1,5}$")


def _matches(ioc: IOC, item: dict[str, Any]) -> bool:
    """Wildcard searches can return neighbours; keep only the indicator that was asked about."""
    found = str(item.get("ioc") or "").lower()
    wanted = ioc.value.lower()
    if ioc.type is IOCType.IPV4:
        return _PORT.sub("", found) == wanted
    return found.rstrip("/") == wanted.rstrip("/")


class ThreatFox(Provider):
    name = "threatfox"
    label = "ThreatFox"
    env_key = "ABUSECH_AUTH_KEY"
    shares_key_with = "urlhaus"
    note = "The same free abuse.ch key as URLhaus, so entering it once covers both."
    supports = frozenset({IOCType.IPV4, IOCType.DOMAIN, IOCType.URL, IOCType.MD5, IOCType.SHA256})
    rate_limit = (30, 60.0)
    weight = 0.95
    URL = "https://threatfox-api.abuse.ch/api/v1/"

    def _lookup(self, ioc: IOC) -> ProviderResult:
        if ioc.type.is_hash:
            body = {"query": "search_hash", "hash": ioc.value}
        else:
            body = {"query": "search_ioc", "search_term": ioc.value, "exact_match": True}
        resp = self.session.post(self.URL, json=body, headers={"Auth-Key": self.api_key},
                                 timeout=self.timeout)
        resp.raise_for_status()
        doc = resp.json()

        status = str(doc.get("query_status") or "")
        if status.startswith("no_result"):
            return self._not_found("not in ThreatFox")
        if status != "ok":
            return self._error(f"ThreatFox: {status or 'no status'}")
        items = [i for i in doc.get("data") or [] if isinstance(i, dict)]
        if not ioc.type.is_hash:
            items = [i for i in items if _matches(ioc, i)]
        if not items:
            return self._not_found("not in ThreatFox")

        numeric = (int, float)
        confidences = [i["confidence_level"] for i in items if isinstance(i.get("confidence_level"), numeric)]
        score = float(max(confidences)) if confidences else 75.0
        families = sorted({str(i.get("malware_printable") or i.get("malware")) for i in items
                           if i.get("malware_printable") or i.get("malware")})
        threats = sorted({_THREATS.get(str(i.get("threat_type")), str(i.get("threat_type")))
                          for i in items if i.get("threat_type")})
        tags = sorted({t for i in items for t in (i.get("tags") or []) if isinstance(t, str)})
        seen = sorted(str(i["first_seen"])[:10] for i in items if i.get("first_seen"))
        last = sorted(str(i["last_seen"])[:10] for i in items if i.get("last_seen"))

        what = "ThreatFox indicator" if not ioc.type.is_hash else "ThreatFox indicator linked to this sample"
        parts = [f"{len(items)} {what}{'s' if len(items) != 1 else ''}"]
        if families:
            parts.append(", ".join(families[:3]))
        if threats:
            parts.append(", ".join(threats[:2]))
        parts.append(f"confidence {int(score)}%")
        first_id = items[0].get("id")
        return self._result(
            score=score,
            summary=" · ".join(parts),
            data={
                "indicators": len(items),
                "malware": families,
                "threat_types": threats,
                "tags": tags[:8],
                "first_seen": seen[0] if seen else None,
                "last_seen": last[-1] if last else None,
                "reference": f"https://threatfox.abuse.ch/ioc/{first_id}/" if first_id else None,
            },
        )
