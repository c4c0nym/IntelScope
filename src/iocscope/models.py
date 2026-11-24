"""Core data types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"

    @property
    def is_ip(self) -> bool:
        return self in (IOCType.IPV4, IOCType.IPV6)

    @property
    def is_hash(self) -> bool:
        return self in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    LOW = "low"
    UNKNOWN = "unknown"
    BENIGN = "benign"

    @property
    def rank(self) -> int:
        """Triage priority, higher means look at it first."""
        return _RANK[self]


_RANK = {
    Verdict.BENIGN: 0,
    Verdict.UNKNOWN: 1,
    Verdict.LOW: 2,
    Verdict.SUSPICIOUS: 3,
    Verdict.MALICIOUS: 4,
}


@dataclass(frozen=True)
class IOC:
    value: str
    """Normalised (refanged, lower-cased where appropriate) value."""
    type: IOCType
    original: str
    """The indicator exactly as it was submitted (may be defanged)."""


@dataclass
class ProviderResult:
    provider: str
    ok: bool
    """False when the lookup failed (network, auth, quota, parse error)."""
    found: bool = False
    """True when the source has any record of the indicator."""
    score: float | None = None
    """0-100, how malicious this source considers the indicator. None = no opinion."""
    benign: bool = False
    """The source positively asserts the indicator is benign (e.g. allowlisted service)."""
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ProviderResult:
        known = {k: raw[k] for k in cls.__dataclass_fields__ if k in raw}
        return cls(**known)


@dataclass
class EnrichedIOC:
    ioc: IOC
    results: list[ProviderResult]
    score: int
    verdict: Verdict
    reasons: list[str]
    allowlisted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc": self.ioc.value,
            "type": self.ioc.type.value,
            "original": self.ioc.original,
            "verdict": self.verdict.value,
            "score": self.score,
            "allowlisted": self.allowlisted,
            "reasons": self.reasons,
            "sources": {r.provider: r.to_dict() for r in self.results},
        }
