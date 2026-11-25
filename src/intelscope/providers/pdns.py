"""Passive DNS (mnemonic's public service): where a domain has pointed, and which domains an IP has served.

Useful for pivoting: an IP that carries dozens of unrelated domains is shared hosting, one that
carries a single odd domain is not. It is context, not a verdict, so it never raises the score.

The public API needs no key but only returns public (TLP:WHITE) data and allows 10 requests a
minute and 1,000 a day. An Argus key (optional) lifts those limits. Records are sorted newest first.
Timestamps are Unix epoch, taken as milliseconds when they are that large.

Privacy: the indicator you look up is sent to mnemonic.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.providers.base import Field, Provider

SAMPLE = 5
LIMIT = 200  # records asked for; the service itself caps a public query at 1,000
PUBLIC_CAP = 1000


def to_date(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return ""
    seconds = value / 1000 if value > 1e11 else value
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).date().isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


class PassiveDNS(Provider):
    name = "pdns"
    label = "Passive DNS"
    env_key = "PDNS_API_KEY"
    key_required = False
    fields = (Field("api_key", "PDNS_API_KEY", "Argus API key", required=False,
                    hint="Optional: lifts the public limits (10/min, 1,000/day)"),)
    note = "mnemonic passive DNS. Free without a key; public data only."
    supports = frozenset({IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6})
    rate_limit = (10, 60.0)
    weight = 0.5
    BASE = "https://api.mnemonic.no/pdns/v3"

    def _lookup(self, ioc: IOC) -> ProviderResult:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Argus-API-Key"] = self.api_key
        resp = self.session.get(f"{self.BASE}/{ioc.value}", params={"limit": LIMIT}, headers=headers,
                                timeout=self.timeout)
        if resp.status_code == 402:
            return self._error("rate limited (public API: 10 a minute, 1,000 a day)")
        resp.raise_for_status()
        doc = resp.json()
        if doc.get("responseCode", 200) != 200:
            raise ValueError(f"responseCode {doc.get('responseCode')}")
        rows = [r for r in doc.get("data") or [] if isinstance(r, dict)]
        if not rows:
            return self._not_found("no passive DNS records")

        # for an IP the interesting side is the name that pointed at it, for a name it is the answer
        side = "query" if ioc.type.is_ip else "answer"
        seen: list[str] = []
        for r in rows:  # already newest first
            value = str(r.get(side) or "").rstrip(".").lower()
            if value and value != ioc.value and value not in seen:
                seen.append(value)
        numeric = (int, float)
        firsts = [r["firstSeenTimestamp"] for r in rows if isinstance(r.get("firstSeenTimestamp"), numeric)]
        lasts = [r["lastSeenTimestamp"] for r in rows if isinstance(r.get("lastSeenTimestamp"), numeric)]
        first, last = to_date(min(firsts)) if firsts else "", to_date(max(lasts)) if lasts else ""
        total = int(doc.get("count") or len(rows))

        what = "domains" if ioc.type.is_ip else "addresses"
        capped = "+" if total >= PUBLIC_CAP else ""
        more_rows = "+" if len(rows) >= LIMIT else ""  # only the newest LIMIT records are read
        parts = [f"{total:,}{capped} record{'s' if total != 1 else ''}",
                 f"{len(seen)}{more_rows} distinct {what}"]
        if first and last:
            parts.append(f"{first} to {last}")
        if seen:
            more = f" (+{len(seen) - SAMPLE})" if len(seen) > SAMPLE else ""
            parts.append("e.g. " + ", ".join(seen[:SAMPLE]) + more)
        return self._result(
            score=None,
            summary=" · ".join(parts),
            data={"records": total, "distinct": len(seen), "first_seen": first or None,
                  "last_seen": last or None, "examples": seen[:10]},
        )
