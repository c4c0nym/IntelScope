from __future__ import annotations

from typing import Any

import pytest
import requests

from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.providers.base import Provider


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)


class FakeSession:
    """Routes requests by URL prefix to canned responses and records every call."""

    def __init__(self, routes: dict[str, FakeResponse] | None = None) -> None:
        self.routes = routes or {}
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def _match(self, url: str) -> FakeResponse:
        for prefix, response in self.routes.items():
            if url.startswith(prefix):
                return response
        return FakeResponse(404, {})

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("GET", url, kwargs))
        return self._match(url)

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("POST", url, kwargs))
        return self._match(url)


class StubProvider(Provider):
    """In-memory provider for enrichment tests."""

    key_required = False
    rate_limit = (10_000, 1.0)

    def __init__(self, name: str, answers: dict[str, ProviderResult | Exception],
                 supports: frozenset[IOCType] = frozenset(IOCType), weight: float = 1.0):
        super().__init__(session=object())
        self.name = name  # type: ignore[misc]
        self.label = name.title()  # type: ignore[misc]
        self.supports = supports  # type: ignore[misc]
        self.weight = weight  # type: ignore[misc]
        self.answers = answers
        self.calls: list[str] = []

    def _lookup(self, ioc: IOC) -> ProviderResult:
        self.calls.append(ioc.value)
        answer = self.answers.get(ioc.value)
        if isinstance(answer, Exception):
            raise answer
        return answer or self._not_found()


def result(provider: str, score: float | None = None, *, found: bool = True,
           benign: bool = False, ok: bool = True, summary: str = "x") -> ProviderResult:
    return ProviderResult(provider=provider, ok=ok, found=found, score=score, benign=benign,
                          summary=summary, error=None if ok else summary)


def ioc(value: str, kind: IOCType = IOCType.IPV4) -> IOC:
    return IOC(value, kind, value)


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    for var in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "ABUSECH_AUTH_KEY", "GREYNOISE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.chdir(tmp_path)  # keep a developer's real .env out of the tests
