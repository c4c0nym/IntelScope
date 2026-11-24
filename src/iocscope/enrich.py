"""Fan indicator lookups out across providers and assemble scored results."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from iocscope.allowlist import Allowlist
from iocscope.cache import Cache
from iocscope.models import IOC, EnrichedIOC, ProviderResult
from iocscope.providers.base import Provider
from iocscope.scoring import assess

ProgressCallback = Callable[[int, int], None]
"""Called with (completed, total) lookups."""


@dataclass
class Enricher:
    providers: Sequence[Provider]
    allowlist: Allowlist | None = None
    cache: Cache | None = None
    max_workers: int = 8

    def enrich(
        self, iocs: Sequence[IOC], on_progress: ProgressCallback | None = None
    ) -> list[EnrichedIOC]:
        allow = {ioc: (self.allowlist.match(ioc) if self.allowlist else None) for ioc in iocs}
        results: dict[IOC, dict[str, ProviderResult]] = {ioc: {} for ioc in iocs}

        jobs: list[tuple[IOC, Provider]] = []
        for ioc in iocs:
            if allow[ioc]:
                continue  # don't spend quota on known-benign indicators
            for provider in self.providers:
                if not provider.supports_ioc(ioc):
                    continue
                cached = self.cache.get(provider.name, ioc) if self.cache else None
                if cached is not None:
                    results[ioc][provider.name] = cached
                else:
                    jobs.append((ioc, provider))

        total = len(jobs)
        if on_progress:
            on_progress(0, total)
        if jobs:
            with ThreadPoolExecutor(max_workers=max(1, self.max_workers)) as pool:
                futures = {pool.submit(p.lookup, ioc): (ioc, p) for ioc, p in jobs}
                for done, future in enumerate(as_completed(futures), start=1):
                    ioc, provider = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:  # a broken provider must not sink the run
                        result = ProviderResult(
                            provider=provider.name,
                            ok=False,
                            error=f"internal error ({exc.__class__.__name__})",
                            summary="internal error",
                        )
                    results[ioc][provider.name] = result
                    if self.cache:
                        self.cache.put(provider.name, ioc, result)
                    if on_progress:
                        on_progress(done, total)

        weights = {p.name: p.weight for p in self.providers}
        enriched = []
        for ioc in iocs:
            ordered = [results[ioc][p.name] for p in self.providers if p.name in results[ioc]]
            score, verdict, reasons = assess(ordered, weights, allow[ioc])
            enriched.append(
                EnrichedIOC(ioc, ordered, score, verdict, reasons, allowlisted=bool(allow[ioc]))
            )
        return enriched


def triage_order(items: Sequence[EnrichedIOC]) -> list[EnrichedIOC]:
    """Most urgent first: by verdict, then score. Stable for equal keys."""
    return sorted(items, key=lambda i: (i.verdict.rank, i.score), reverse=True)
