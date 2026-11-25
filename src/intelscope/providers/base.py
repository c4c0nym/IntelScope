"""Provider base class: rate limiting, error handling and result helpers."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Any, ClassVar

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from intelscope import __version__
from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.ratelimit import RateLimiter


def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=16)
    session.mount("https://", adapter)
    session.headers["User-Agent"] = f"intelscope/{__version__}"
    return session


def describe_http_error(response: Any) -> str:
    status = getattr(response, "status_code", None)
    if status in (401, 403):
        return "authentication failed (check API key)"
    if status == 429:
        return "rate limited / quota exhausted"
    return f"HTTP {status}" if status else "HTTP error"


def compact(data: dict[str, Any]) -> dict[str, Any]:
    """Drop empty values so exports stay readable."""
    return {k: v for k, v in data.items() if v not in (None, "", [], {})}


class Provider(ABC):
    name: ClassVar[str]
    label: ClassVar[str]
    env_key: ClassVar[str | None] = None
    key_required: ClassVar[bool] = True
    supports: ClassVar[frozenset[IOCType]]
    rate_limit: ClassVar[tuple[int, float]] = (60, 60.0)
    weight: ClassVar[float] = 1.0
    timeout: ClassVar[float] = 20.0

    def __init__(self, api_key: str | None = None, session: Any = None) -> None:
        self.api_key = api_key or None
        self.session = session if session is not None else build_session()
        self.limiter = RateLimiter(*self.rate_limit)

    @classmethod
    def from_env(cls, session: Any = None) -> Provider:
        key = os.environ.get(cls.env_key) if cls.env_key else None
        return cls(key, session)

    @property
    def configured(self) -> bool:
        return bool(self.api_key) or not self.key_required

    def supports_ioc(self, ioc: IOC) -> bool:
        return ioc.type in self.supports

    def lookup(self, ioc: IOC) -> ProviderResult:
        if not self.supports_ioc(ioc):
            raise ValueError(f"{self.name} does not support {ioc.type.value}")
        self.limiter.wait()
        try:
            return self._lookup(ioc)
        except requests.HTTPError as exc:
            return self._error(describe_http_error(exc.response))
        except requests.RequestException as exc:
            return self._error(f"network error ({exc.__class__.__name__})")
        except (ValueError, KeyError, TypeError) as exc:
            return self._error(f"unexpected response ({exc.__class__.__name__})")

    @abstractmethod
    def _lookup(self, ioc: IOC) -> ProviderResult: ...

    # Helpers for subclasses
    def _result(
        self,
        *,
        score: float | None = None,
        benign: bool = False,
        summary: str = "",
        data: dict[str, Any] | None = None,
        found: bool = True,
    ) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            ok=True,
            found=found,
            score=score,
            benign=benign,
            summary=summary,
            data=compact(data or {}),
        )

    def _not_found(self, summary: str = "no record") -> ProviderResult:
        return ProviderResult(provider=self.name, ok=True, found=False, summary=summary)

    def _error(self, message: str) -> ProviderResult:
        return ProviderResult(provider=self.name, ok=False, error=message, summary=message)
