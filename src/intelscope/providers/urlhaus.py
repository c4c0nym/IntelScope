"""abuse.ch URLhaus API."""

from __future__ import annotations

from typing import Any

from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.providers.base import Provider


class URLhaus(Provider):
    name = "urlhaus"
    label = "URLhaus"
    env_key = "ABUSECH_AUTH_KEY"
    shares_key_with = "threatfox"
    note = "The same free abuse.ch key as ThreatFox, so entering it once covers both."
    supports = frozenset(
        {IOCType.IPV4, IOCType.DOMAIN, IOCType.URL, IOCType.MD5, IOCType.SHA256}
    )
    rate_limit = (30, 60.0)
    weight = 1.0
    BASE = "https://urlhaus-api.abuse.ch/v1"

    def _post(self, endpoint: str, form: dict[str, str]) -> dict[str, Any]:
        resp = self.session.post(
            f"{self.BASE}/{endpoint}/",
            data=form,
            headers={"Auth-Key": self.api_key},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def _lookup(self, ioc: IOC) -> ProviderResult:
        if ioc.type is IOCType.URL:
            body = self._post("url", {"url": ioc.value})
            handler = self._from_url
        elif ioc.type.is_hash:
            field = "md5_hash" if ioc.type is IOCType.MD5 else "sha256_hash"
            body = self._post("payload", {field: ioc.value})
            handler = self._from_payload
        else:
            body = self._post("host", {"host": ioc.value})
            handler = self._from_host

        status = body.get("query_status")
        if status == "no_results":
            return self._not_found("not in URLhaus")
        if status != "ok":
            return self._not_found(f"URLhaus: {status}")
        return handler(body)

    def _from_host(self, body: dict[str, Any]) -> ProviderResult:
        urls = body.get("urls") or []
        count = int(body.get("url_count") or len(urls))
        if not count:
            return self._not_found("not in URLhaus")
        online = sum(1 for u in urls if u.get("url_status") == "online")
        threats = sorted({u["threat"] for u in urls if u.get("threat")})
        tags = sorted({t for u in urls for t in (u.get("tags") or [])})
        summary = f"{count} malware URL{'s' if count != 1 else ''} hosted ({online} online)"
        if tags:
            summary += f" · {', '.join(tags[:4])}"
        return self._result(
            score=90 if online else 65,
            summary=summary,
            data={
                "url_count": count,
                "online": online,
                "threats": threats,
                "tags": tags,
                "first_seen": body.get("firstseen"),
                "blacklists": body.get("blacklists"),
                "reference": body.get("urlhaus_reference"),
            },
        )

    def _from_url(self, body: dict[str, Any]) -> ProviderResult:
        status = body.get("url_status") or "unknown"
        threat = body.get("threat") or "malware"
        tags = body.get("tags") or []
        summary = f"{threat} URL, {status}"
        if tags:
            summary += f" · {', '.join(tags[:4])}"
        return self._result(
            score=95 if status == "online" else 80,
            summary=summary,
            data={
                "status": status,
                "threat": threat,
                "tags": tags,
                "date_added": body.get("date_added"),
                "reference": body.get("urlhaus_reference"),
            },
        )

    def _from_payload(self, body: dict[str, Any]) -> ProviderResult:
        signature = body.get("signature") or "unknown family"
        file_type = body.get("file_type") or "file"
        return self._result(
            score=90,
            summary=f"malware payload: {signature} ({file_type})",
            data={
                "signature": body.get("signature"),
                "file_type": body.get("file_type"),
                "first_seen": body.get("firstseen"),
                "url_count": body.get("url_count"),
            },
        )
