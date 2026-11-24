"""AbuseIPDB API v2."""

from __future__ import annotations

from iocscope.models import IOC, IOCType, ProviderResult
from iocscope.providers.base import Provider


class AbuseIPDB(Provider):
    name = "abuseipdb"
    label = "AbuseIPDB"
    env_key = "ABUSEIPDB_API_KEY"
    supports = frozenset({IOCType.IPV4, IOCType.IPV6})
    rate_limit = (30, 60.0)
    weight = 0.9
    URL = "https://api.abuseipdb.com/api/v2/check"

    def _lookup(self, ioc: IOC) -> ProviderResult:
        resp = self.session.get(
            self.URL,
            params={"ipAddress": ioc.value, "maxAgeInDays": 90},
            headers={"Key": self.api_key, "Accept": "application/json"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        d = resp.json()["data"]

        confidence = int(d.get("abuseConfidenceScore") or 0)
        reports = int(d.get("totalReports") or 0)
        summary = f"{confidence}% abuse confidence, {reports:,} reports (90d)"
        context = " / ".join(x for x in (d.get("isp"), d.get("countryCode")) if x)
        if context:
            summary += f" · {context}"
        return self._result(
            score=confidence,
            benign=bool(d.get("isWhitelisted")),
            summary=summary,
            found=reports > 0 or bool(d.get("isWhitelisted")),
            data={
                "confidence": confidence,
                "reports": reports,
                "distinct_users": d.get("numDistinctUsers"),
                "isp": d.get("isp"),
                "usage_type": d.get("usageType"),
                "country": d.get("countryCode"),
                "domain": d.get("domain"),
                "last_reported": d.get("lastReportedAt"),
                "tor": d.get("isTor"),
            },
        )
