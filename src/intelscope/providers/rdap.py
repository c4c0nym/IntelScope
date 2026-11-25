"""RDAP (the successor to WHOIS): when a domain was registered, and by whom.

A domain that was registered days ago and already shows up in an indicator list is worth a closer
look: phishing and command-and-control domains are overwhelmingly young. Age alone is weak evidence
(plenty of legitimate sites are new), so the score is modest and only a brand-new domain reaches
"suspicious" on its own. Old domains get no score at all: age is not proof of innocence.

No key needed. Queries go through ``rdap.org``, which redirects to the registry that owns the TLD.
A subdomain is looked up by stripping labels until a registered name is found.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from intelscope.models import IOC, IOCType, ProviderResult
from intelscope.providers.base import Provider

MAX_TRIES = 4


def parse_when(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def age_score(days: int) -> float | None:
    if days < 7:
        return 70.0
    if days < 30:
        return 55.0
    if days < 90:
        return 30.0
    return None


def candidates(domain: str) -> list[str]:
    """The name itself, then its parents down to two labels: mail.evil.test -> evil.test."""
    labels = domain.split(".")
    names = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    return names[:MAX_TRIES]


def _event(doc: dict[str, Any], *actions: str) -> datetime | None:
    for ev in doc.get("events") or []:
        if isinstance(ev, dict) and ev.get("eventAction") in actions:
            stamp = parse_when(ev.get("eventDate"))
            if stamp:
                return stamp
    return None


def _registrar(doc: dict[str, Any]) -> str:
    for ent in doc.get("entities") or []:
        if not isinstance(ent, dict) or "registrar" not in (ent.get("roles") or []):
            continue
        card = ent.get("vcardArray")
        if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list):
            for prop in card[1]:
                if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn" and isinstance(prop[3], str):
                    return prop[3]
    return ""


class RDAP(Provider):
    name = "rdap"
    label = "RDAP / WHOIS"
    key_required = False
    settable = False
    note = "Domain registration age and registrar. No key needed."
    supports = frozenset({IOCType.DOMAIN})
    rate_limit = (20, 60.0)
    weight = 0.6
    BASE = "https://rdap.org/domain"

    def _lookup(self, ioc: IOC) -> ProviderResult:
        doc: dict[str, Any] | None = None
        queried = ""
        for attempt, name in enumerate(candidates(ioc.value)):
            if attempt:
                self.limiter.wait()  # every request counts, not just the first
            resp = self.session.get(f"{self.BASE}/{name}", headers={"Accept": "application/rdap+json"},
                                    timeout=self.timeout)
            if resp.status_code in (400, 404):  # unregistered; some say 400 for a subdomain
                continue
            resp.raise_for_status()
            doc, queried = resp.json(), name
            break
        if not isinstance(doc, dict):
            return self._not_found("no registration record (unregistered, or the registry has no RDAP)")

        registered = _event(doc, "registration")
        changed = _event(doc, "last changed", "last update of RDAP database")
        expires = _event(doc, "expiration")
        registrar = _registrar(doc)
        status = [s for s in doc.get("status") or [] if isinstance(s, str)]
        servers = sorted({str(n.get("ldhName", "")).lower() for n in doc.get("nameservers") or []
                          if isinstance(n, dict) and n.get("ldhName")})

        parts: list[str] = []
        score = None
        days = None
        if registered:
            days = max(0, (datetime.now(timezone.utc) - registered).days)
            score = age_score(days)
            ago = "today" if days == 0 else f"{days} day{'s' if days != 1 else ''} ago"
            parts.append(f"registered {registered.date()} ({ago})")
        else:
            parts.append("registration date not published")
        if registrar:
            parts.append(registrar)
        if queried != ioc.value:
            parts.append(f"parent domain {queried}")
        return self._result(
            score=score,
            summary=" · ".join(parts),
            data={
                "domain": queried,
                "registered": registered.date().isoformat() if registered else None,
                "age_days": days,
                "last_changed": changed.date().isoformat() if changed else None,
                "expires": expires.date().isoformat() if expires else None,
                "registrar": registrar,
                "status": status,
                "nameservers": servers[:6],
            },
        )
