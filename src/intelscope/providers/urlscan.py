"""urlscan.io: what the site looked like when it was scanned, and urlscan's own verdict.

Search works without a key at a low rate. With a key, the newest scan is opened for urlscan's
verdict, brands and tags. Scans are public: anything found here was already visible to everyone.
"""

from __future__ import annotations

from typing import Any

import requests

from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.providers.base import Provider

_MAX_QUERY = 500


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_query(ioc: IOC) -> str:
    if ioc.type is IOCType.DOMAIN:
        return f"page.domain:{_quote(ioc.value)}"
    if ioc.type.is_ip:
        return f"page.ip:{_quote(ioc.value)}"
    if ioc.type is IOCType.URL:
        return f"page.url:{_quote(ioc.value[:_MAX_QUERY])}"
    return f"hash:{ioc.value}"  # sha256 of a downloaded file


class URLscan(Provider):
    name = "urlscan"
    label = "urlscan.io"
    env_key = "URLSCAN_API_KEY"
    key_required = False  # search works anonymously
    cache_by_key = True  # a key adds urlscan's verdict, so keyless results are not a substitute
    note = "Works without a key at a low rate. A key adds urlscan's verdict for the newest scan."
    supports = frozenset({IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL, IOCType.SHA256})
    rate_limit = (20, 60.0)
    weight = 0.8
    BASE = "https://urlscan.io/api/v1"

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["API-Key"] = self.api_key
        return headers

    def _verdict(self, scan_id: str) -> dict[str, Any]:
        """urlscan's verdict for one scan. Best effort: a failure here must not lose the search result."""
        try:
            resp = self.session.get(f"{self.BASE}/result/{scan_id}/", headers=self._headers(),
                                    timeout=self.timeout)
            resp.raise_for_status()
            return (resp.json().get("verdicts") or {}).get("overall") or {}
        except (requests.RequestException, ValueError, AttributeError):
            return {}

    def _lookup(self, ioc: IOC) -> ProviderResult:
        resp = self.session.get(f"{self.BASE}/search/", params={"q": build_query(ioc), "size": 10},
                                headers=self._headers(), timeout=self.timeout)
        resp.raise_for_status()
        doc = resp.json()
        results = [r for r in (doc.get("results") or []) if isinstance(r, dict)]
        total = int(doc.get("total") or len(results))
        if not results:
            return self._not_found("no public scans")

        newest = results[0]
        task = newest.get("task") or {}
        page = newest.get("page") or {}
        scan_id = newest.get("_id") or task.get("uuid") or ""
        when = (task.get("time") or "")[:10]

        overall = (newest.get("verdicts") or {}).get("overall") or {}
        if not overall and scan_id and self.api_key:
            overall = self._verdict(scan_id)
        malicious = bool(overall.get("malicious"))
        raw_score = overall.get("score")
        brands = [b if isinstance(b, str) else (b.get("name") or "") for b in overall.get("brands") or []]
        brands = [b for b in brands if b]
        tags = [t for t in overall.get("tags") or [] if isinstance(t, str)]

        score: float | None = None
        if malicious:
            score = max(75.0, float(raw_score)) if isinstance(raw_score, (int, float)) else 75.0
        elif isinstance(raw_score, (int, float)) and raw_score > 0:
            score = float(raw_score)

        parts = [f"{total:,} public scan{'s' if total != 1 else ''}"]
        if when:
            parts.append(f"latest {when}")
        if malicious:
            parts.append("verdict: malicious")
        if brands:
            parts.append("impersonates " + ", ".join(brands[:3]))
        if tags:
            parts.append("tags: " + ", ".join(tags[:4]))
        return self._result(
            score=score,
            summary=" · ".join(parts),
            data={
                "scans": total,
                "latest_scan": task.get("time"),
                "verdict_malicious": malicious or None,
                "verdict_score": raw_score,
                "brands": brands,
                "tags": tags,
                "page_ip": page.get("ip"),
                "page_country": page.get("country"),
                "server": page.get("server"),
                "report": f"https://urlscan.io/result/{scan_id}/" if scan_id else None,
            },
        )
