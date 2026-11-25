"""ASN blocklist: is the IP announced by a network run by criminals?

The IP's origin ASN comes from RIPEstat (free, keyless, worldwide). It is checked against
Spamhaus ASN-DROP (autonomous systems "controlled by spammers or cyber criminals") and,
optionally, your own list of ASNs.

A bad ASN says something about the *neighbourhood*, not the host itself, so the source weight
is moderate: on its own it makes an IP suspicious, and together with another source it pushes
the verdict to malicious.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

from intelscope.cache import default_cache_path
from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.providers.base import Provider

DROP_URL = "https://www.spamhaus.org/drop/asndrop.json"
RIPESTAT = "https://stat.ripe.net/data"
DROP_MAX_AGE = 24 * 3600  # Spamhaus updates the list daily; please don't fetch it more often


def _asn_number(raw: str) -> int | None:
    m = re.fullmatch(r"\s*(?:AS)?(\d{1,10})\s*", raw, re.I)
    return int(m.group(1)) if m else None


def parse_drop(text: str) -> dict[int, dict[str, Any]]:
    """ASN-DROP is newline-delimited JSON with one ASN per line and a trailing metadata record."""
    listed: dict[int, dict[str, Any]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and isinstance(entry.get("asn"), int):
            listed[entry["asn"]] = entry
    return listed


def parse_custom(text: str) -> dict[int, dict[str, Any]]:
    """One ASN per line ("AS64500" or "64500"), optional "# reason" comment."""
    listed: dict[int, dict[str, Any]] = {}
    for line in text.splitlines():
        entry, _, comment = line.partition("#")
        asn = _asn_number(entry)
        if asn is not None:
            listed[asn] = {"asn": asn, "reason": comment.strip() or "on your blocklist"}
    return listed


class ASNBlocklist(Provider):
    name = "asn"
    label = "ASN blocklist"
    env_key = "INTELSCOPE_ASN_BLOCKLIST"  # optional: path to your own ASN list
    key_required = False
    supports = frozenset({IOCType.IPV4, IOCType.IPV6})
    rate_limit = (60, 60.0)
    weight = 0.8

    def __init__(self, api_key: str | None = None, session: Any = None,
                 drop_cache: Path | None = None, use_drop: bool = True) -> None:
        # api_key doubles as the custom blocklist path, so from_env() picks up the env variable
        super().__init__(api_key, session)
        self.custom_file = api_key
        self.drop_cache = drop_cache or default_cache_path().with_name("asndrop.json")
        self.use_drop = use_drop
        self._lock = threading.Lock()
        self._lists: tuple[dict, dict, str | None] | None = None
        self._holders: dict[int, str] = {}

    @classmethod
    def from_env(cls, session: Any = None, blocklist_file: str | None = None) -> ASNBlocklist:
        return cls(blocklist_file or os.environ.get(cls.env_key), session)

    # -- blocklists ---------------------------------------------------------------------------
    def _load_drop(self) -> tuple[dict, str | None]:
        """Spamhaus ASN-DROP from a daily on-disk cache; a stale copy beats none."""
        cached = None
        try:
            if time.time() - self.drop_cache.stat().st_mtime < DROP_MAX_AGE:
                return parse_drop(self.drop_cache.read_text(encoding="utf-8")), None
            cached = self.drop_cache.read_text(encoding="utf-8")
        except OSError:
            pass
        try:
            resp = self.session.get(DROP_URL, timeout=self.timeout)
            resp.raise_for_status()
            listed = parse_drop(resp.text)
            if not listed:
                raise ValueError("empty list")
            self.drop_cache.parent.mkdir(parents=True, exist_ok=True)
            self.drop_cache.write_text(resp.text, encoding="utf-8")
            return listed, None
        except Exception as exc:  # network, HTTP or parse problem
            if cached:
                return parse_drop(cached), "using a cached ASN-DROP list (download failed)"
            return {}, f"Spamhaus ASN-DROP unavailable ({exc.__class__.__name__})"

    def _blocklists(self) -> tuple[dict, dict, str | None]:
        with self._lock:
            if self._lists is None:
                drop, note = self._load_drop() if self.use_drop else ({}, None)
                custom = {}
                if self.custom_file:
                    try:
                        custom = parse_custom(Path(self.custom_file).read_text(encoding="utf-8"))
                    except OSError:
                        note = "; ".join(filter(None, [note, f"could not read {self.custom_file}"]))
                self._lists = (drop, custom, note)
            return self._lists

    # -- lookups -----------------------------------------------------------------------------
    def _ripestat(self, call: str, resource: str) -> dict[str, Any]:
        resp = self.session.get(
            f"{RIPESTAT}/{call}/data.json",
            params={"resource": resource, "sourceapp": "intelscope"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json().get("data") or {}

    def _holder(self, asn: int) -> str:
        if asn not in self._holders:
            try:
                self._holders[asn] = self._ripestat("as-overview", f"AS{asn}").get("holder") or ""
            except Exception:
                self._holders[asn] = ""
        return self._holders[asn]

    def _lookup(self, ioc: IOC) -> ProviderResult:
        drop, custom, note = self._blocklists()
        info = self._ripestat("network-info", ioc.value)
        asns = [int(a) for a in info.get("asns") or [] if str(a).isdigit()]
        prefix = info.get("prefix") or ""
        if not asns:
            return self._not_found("not announced on the internet (no origin ASN)")

        hits = []
        for asn in asns:
            if asn in custom:
                hits.append((asn, "your blocklist", custom[asn]["reason"]))
            if asn in drop:
                entry = drop[asn]
                hits.append((asn, "Spamhaus ASN-DROP", entry.get("asname") or ""))

        asn = hits[0][0] if hits else asns[0]
        holder = (drop.get(asn) or {}).get("asname") or self._holder(asn)
        data = {
            "asn": asn,
            "asns": asns if len(asns) > 1 else None,
            "holder": holder,
            "prefix": prefix,
            "country": (drop.get(asn) or {}).get("cc"),
            "listed_on": sorted({h[1] for h in hits}),
            "note": note,
        }
        if hits:
            sources = " + ".join(sorted({h[1] for h in hits}))
            detail = next((h[2] for h in hits if h[1] == "your blocklist"), "")
            summary = f"AS{asn} {holder} is on {sources}" + (f" ({detail})" if detail else "")
            return self._result(score=75, summary=summary, data=data)
        parts = [f"AS{asn} {holder}".strip()]
        if prefix:
            parts.append(prefix)
        parts.append("not blocklisted")
        if note:
            parts.append(note)
        # Every routed IP has an ASN, so a clean one is context, not a sighting: it must not turn
        # an indicator nobody knows ("unknown") into one that sources have seen ("low").
        return self._result(score=None, summary=" · ".join(parts), data=data, found=False)
