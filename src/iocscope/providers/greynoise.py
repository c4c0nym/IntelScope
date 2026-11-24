"""GreyNoise Community API: separates targeted activity from internet background noise."""

from __future__ import annotations

from iocscope.models import IOC, IOCType, ProviderResult
from iocscope.providers.base import Provider


class GreyNoise(Provider):
    name = "greynoise"
    label = "GreyNoise"
    env_key = "GREYNOISE_API_KEY"
    key_required = False  # community endpoint works without a key (lower quota)
    supports = frozenset({IOCType.IPV4})
    rate_limit = (10, 60.0)
    weight = 0.7
    BASE = "https://api.greynoise.io/v3/community"

    def _lookup(self, ioc: IOC) -> ProviderResult:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["key"] = self.api_key
        resp = self.session.get(f"{self.BASE}/{ioc.value}", headers=headers, timeout=self.timeout)
        if resp.status_code == 404:
            return self._not_found("not observed by GreyNoise")
        resp.raise_for_status()
        d = resp.json()

        classification = d.get("classification") or "unknown"
        riot = bool(d.get("riot"))
        noise = bool(d.get("noise"))
        name = d.get("name") or ""
        data = {
            "classification": classification,
            "noise": noise,
            "riot": riot,
            "name": name,
            "last_seen": d.get("last_seen"),
            "link": d.get("link"),
        }

        if riot or classification == "benign":
            label = "known business service (RIOT)" if riot else "benign"
            summary = f"{label}: {name}" if name else label
            return self._result(score=0, benign=True, summary=summary, data=data)
        if classification == "malicious":
            return self._result(score=70, summary="classified malicious (mass scanning)", data=data)
        if noise:
            return self._result(score=20, summary="internet background noise", data=data)
        return self._result(score=None, summary=f"classification: {classification}", data=data)
