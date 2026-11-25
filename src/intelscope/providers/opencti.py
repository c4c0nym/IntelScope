"""OpenCTI: does your own threat-intelligence platform already know this observable?

Searches the platform's observables over GraphQL. Credentials are the platform URL and a user
API token (your profile page in OpenCTI). Only exact matches count. The platform's own
score is passed on as-is; a known observable without a score is context, not an accusation.

This integration was written against the public GraphQL schema and has not been run against a
live platform. If your version rejects the label fields it retries with the minimal query.
"""

from __future__ import annotations

from typing import Any

from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.providers.base import Field, Provider

_FIELDS = "id entity_type observable_value x_opencti_score"
_QUERY_FULL = ("query($s: String) { stixCyberObservables(search: $s, first: 10) { edges { node { "
               + _FIELDS + " objectLabel { value } } } } }")
_QUERY_MIN = ("query($s: String) { stixCyberObservables(search: $s, first: 10) { edges { node { "
              + _FIELDS + " } } } }")


def _labels(node: dict[str, Any]) -> list[str]:
    raw = node.get("objectLabel") or []
    if isinstance(raw, dict):  # older schema: a connection
        raw = [e.get("node") for e in raw.get("edges") or []]
    return [x["value"] for x in raw if isinstance(x, dict) and isinstance(x.get("value"), str)]


class OpenCTI(Provider):
    name = "opencti"
    label = "OpenCTI"
    env_key = "OPENCTI_TOKEN"
    fields = (
        Field("url", "OPENCTI_URL", "Platform URL", secret=False, kind="url",
              hint="For example https://opencti.example.org"),
        Field("api_key", "OPENCTI_TOKEN", "API token", hint="Your profile page in OpenCTI"),
    )
    note = "Your own platform, so nothing leaves your network. Not yet tested against a live platform."
    supports = frozenset(IOCType)
    rate_limit = (60, 60.0)
    weight = 0.7

    @property
    def configured(self) -> bool:
        return bool(self.api_key and self.extra.get("url"))

    def _query(self, query: str, search: str) -> dict[str, Any]:
        resp = self.session.post(
            self.extra["url"].rstrip("/") + "/graphql",
            json={"query": query, "variables": {"s": search}},
            headers={"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def _lookup(self, ioc: IOC) -> ProviderResult:
        doc = self._query(_QUERY_FULL, ioc.value)
        if doc.get("errors"):
            doc = self._query(_QUERY_MIN, ioc.value)
        if doc.get("errors"):
            first = doc["errors"][0] if isinstance(doc["errors"][0], dict) else {}
            raise ValueError(str(first.get("message") or "GraphQL error")[:80])
        edges = ((doc.get("data") or {}).get("stixCyberObservables") or {}).get("edges") or []
        wanted = ioc.value.lower()
        nodes = [e["node"] for e in edges if isinstance(e, dict) and isinstance(e.get("node"), dict)
                 and str(e["node"].get("observable_value", "")).lower() == wanted]
        if not nodes:
            return self._not_found("not in OpenCTI")

        node = nodes[0]
        score = node.get("x_opencti_score")
        score = float(score) if isinstance(score, (int, float)) else None
        labels = _labels(node)
        parts = ["known observable"]
        if score is not None:
            parts.append(f"score {int(score)}")
        if labels:
            parts.append("labels: " + ", ".join(labels[:5]))
        return self._result(
            score=score if score else None,
            summary=" · ".join(parts),
            data={"entity_type": node.get("entity_type"), "opencti_score": score, "labels": labels,
                  "link": f"{self.extra['url'].rstrip('/')}/dashboard/id/{node.get('id')}"},
        )
