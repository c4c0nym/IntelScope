"""Intel 471 indicators: adversary-linked IPs, domains, URLs and file hashes with a confidence rating.

Two generations of the API are supported and chosen by the base URL:

* **Verity471** (default, ``https://api.intel471.cloud``): create an application in the Intel 471
  Developer Portal and use its *client ID* and *client secret* (HTTP Basic). The application must
  have the Indicators API enabled. Search is
  ``GET /integrations/indicators/v1/indicators/stream?text_filter=<value>``.
* **Titan** (legacy, any base URL on ``intel471.com``): account e-mail as the client ID and the
  Titan API key as the secret. Search is ``GET /v1/indicators/stream?indicator=<value>``.

Verity's search is free text, so results are matched exactly against the indicator before they
count. A hit is intelligence about an adversary, so it scores by the indicator's own confidence
(0-100 in Verity, low/medium/high in Titan). Revoked and expired indicators are reported but do
not raise the score.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.providers.base import Field, Provider

_TITAN_CONFIDENCE = {"high": 90.0, "medium": 65.0, "low": 35.0}
VERITY_BASE = "https://api.intel471.cloud"
TITAN_BASE = "https://api.intel471.com/v1"


def _dig(doc: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(doc, dict):
            return None
        doc = doc.get(key)
    return doc


def _is_titan(base: str) -> bool:
    host = (urlsplit(base).hostname or "").lower()
    return host == "intel471.com" or host.endswith(".intel471.com")


def _confidence(raw: Any) -> float:
    if isinstance(raw, bool):
        return 50.0
    if isinstance(raw, (int, float)):
        return max(0.0, min(100.0, float(raw)))
    return _TITAN_CONFIDENCE.get(str(raw or "").lower(), 50.0)


def _values(item: dict[str, Any]) -> set[str]:
    """Every indicator value an item carries, lower-cased, across both API generations."""
    data = item.get("data") or {}
    out = {
        _dig(data, "ipv4", "ip_address"), data.get("domain"), data.get("url"),
        _dig(data, "file", "md5"), _dig(data, "file", "sha1"), _dig(data, "file", "sha256"),
        _dig(data, "indicator_data", "address"), _dig(data, "indicator_data", "url"),
        _dig(data, "indicator_data", "file", "md5"), _dig(data, "indicator_data", "file", "sha1"),
        _dig(data, "indicator_data", "file", "sha256"),
    }
    return {str(v).lower().rstrip("/") for v in out if isinstance(v, str) and v}


def _family(item: dict[str, Any]) -> str:
    data = item.get("data") or {}
    threat = item.get("threat") or data.get("threat") or {}
    for path in (("data", "malware_family", "name"), ("data", "malware", "family"), ("data", "family"),
                 ("family",)):
        value = _dig(threat, *path)
        if isinstance(value, str) and value:
            return value
    return ""


def _when(value: Any) -> str:
    return str(value or "")[:10]


def _expired(item: dict[str, Any]) -> bool:
    raw = item.get("expiration_ts")
    if not isinstance(raw, str):
        return False
    try:
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return False
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp < datetime.now(timezone.utc)


class Intel471(Provider):
    name = "intel471"
    label = "Intel 471"
    env_key = "INTEL471_CLIENT_SECRET"
    fields = (
        Field("client_id", "INTEL471_CLIENT_ID", "Client ID", secret=False, kind="text",
              hint="Verity application client ID (Titan: account e-mail)"),
        Field("api_key", "INTEL471_CLIENT_SECRET", "Client secret",
              hint="Verity application client secret (Titan: API key)"),
        Field("url", "INTEL471_URL", "API base URL", secret=False, required=False, kind="url",
              hint="Default https://api.intel471.cloud (Verity). A base URL on intel471.com selects Titan"),
    )
    note = ("Verity471 by default: create an application in the Intel 471 Developer Portal and enable the "
            "Indicators API for it. Checked against Intel 471's SDK, not yet against a live tenant.")
    supports = frozenset({IOCType.IPV4, IOCType.DOMAIN, IOCType.URL, IOCType.MD5, IOCType.SHA1,
                          IOCType.SHA256})
    rate_limit = (20, 60.0)
    weight = 0.95

    @property
    def configured(self) -> bool:
        return bool(self.api_key and self.extra.get("client_id"))

    def _request(self, ioc: IOC):
        base = (self.extra.get("url") or VERITY_BASE).rstrip("/")
        if _is_titan(base):
            url, params = f"{base}/indicators/stream", {"indicator": ioc.value, "count": 20}
        else:
            url = f"{base}/integrations/indicators/v1/indicators/stream"
            params = {"text_filter": ioc.value, "size": 50}
        return self.session.get(
            url,
            params=params,
            auth=(self.extra["client_id"], self.api_key),
            headers={"Accept": "application/json"},
            timeout=self.timeout,
        )

    def _lookup(self, ioc: IOC) -> ProviderResult:
        resp = self._request(ioc)
        if resp.status_code == 404:
            return self._not_found("no Intel 471 indicator")
        if resp.status_code == 403:
            return self._error("not authorised: enable the Indicators API for this application")
        resp.raise_for_status()
        doc = resp.json()
        wanted = ioc.value.lower().rstrip("/")
        items = [i for i in (doc.get("indicators") or []) if isinstance(i, dict) and wanted in _values(i)]
        if not items:
            return self._not_found("no Intel 471 indicator")

        live = [i for i in items if not _dig(i, "revocation", "revoked") and not _expired(i)]
        families: list[str] = []
        kinds: list[str] = []
        last = ""
        for item in items:
            family = _family(item)
            if family and family not in families:
                families.append(family)
            kind = _dig(item, "threat", "type") or _dig(item, "data", "threat", "type")
            if isinstance(kind, str) and kind and kind not in kinds:
                kinds.append(kind)
            seen = _when(_dig(item, "activity", "last_seen_ts") or _dig(item, "activity", "last")
                         or item.get("last_updated"))
            last = max(last, seen)

        parts = [f"{len(items)} Intel 471 indicator{'s' if len(items) != 1 else ''}"]
        if len(live) != len(items):
            parts.append(f"{len(items) - len(live)} revoked or expired")
        if families:
            parts.append(", ".join(families[:3]))
        if kinds:
            parts.append(", ".join(kinds[:3]))
        score = max((_confidence(i.get("confidence", _dig(i, "data", "confidence"))) for i in live),
                    default=None)
        return self._result(
            score=score,
            summary=" · ".join(parts),
            data={"indicators": len(items), "active": len(live), "families": families,
                  "threat_types": kinds, "last_seen": last or None},
        )
