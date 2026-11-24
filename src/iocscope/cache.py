"""Small on-disk cache so repeat lookups don't burn API quota."""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

from iocscope.models import IOC, ProviderResult


def default_cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "iocscope" / "cache.json"


class Cache:
    def __init__(
        self,
        path: Path,
        ttl_seconds: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self.ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._dirty = False
        self._data: dict[str, dict] = self._load()

    def _load(self) -> dict[str, dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def key(provider: str, ioc: IOC) -> str:
        return f"{provider}|{ioc.type.value}|{ioc.value}"

    def _fresh(self, entry: dict) -> bool:
        return self._clock() - float(entry.get("ts", 0)) <= self.ttl

    def get(self, provider: str, ioc: IOC) -> ProviderResult | None:
        with self._lock:
            entry = self._data.get(self.key(provider, ioc))
        if not entry or not self._fresh(entry):
            return None
        try:
            result = ProviderResult.from_dict(entry["result"])
        except (KeyError, TypeError):
            return None
        result.cached = True
        return result

    def put(self, provider: str, ioc: IOC, result: ProviderResult) -> None:
        if not result.ok:  # never cache failures; retry them next run
            return
        payload = result.to_dict()
        payload["cached"] = False
        with self._lock:
            self._data[self.key(provider, ioc)] = {"ts": self._clock(), "result": payload}
            self._dirty = True

    def save(self) -> None:
        with self._lock:
            if not self._dirty:
                return
            self._data = {k: v for k, v in self._data.items() if self._fresh(v)}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data), encoding="utf-8")
            tmp.replace(self.path)
            self._dirty = False
