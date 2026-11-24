"""Refang and classify raw indicator strings."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlsplit

from iocscope.models import IOC, IOCType

_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"^h(?:xx|\*\*)p(s?)(?=\[?:)", re.I), r"http\1"),
    (re.compile(r"^fxp(?=\[?:)", re.I), "ftp"),
]

_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)"
    r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HASH_TYPES = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_TOKEN_SPLIT = re.compile(r"[\s,;]+")
_INLINE_COMMENT = re.compile(r"\s#")


def refang(value: str) -> str:
    """Undo common defanging, e.g. ``hxxps://evil[.]com`` -> ``https://evil.com``."""
    value = value.strip().strip("\"'<>")
    for pattern, replacement in _REFANG_RULES:
        value = pattern.sub(replacement, value)
    return value


def classify(raw: str) -> IOC | None:
    """Return a normalised IOC, or None if the string is not a supported indicator."""
    original = raw.strip()
    value = refang(original)
    if not value:
        return None

    if _SCHEME_RE.match(value):
        parts = urlsplit(value)
        if parts.scheme.lower() in ("http", "https") and parts.hostname:
            return IOC(value, IOCType.URL, original)
        return None

    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        pass
    else:
        kind = IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
        return IOC(str(ip), kind, original)

    if len(value) in _HASH_TYPES and _HEX_RE.match(value):
        return IOC(value.lower(), _HASH_TYPES[len(value)], original)

    host = value.lower().rstrip(".")
    if _DOMAIN_RE.match(host):
        return IOC(host, IOCType.DOMAIN, original)
    return None


def parse_iocs(lines: Iterable[str]) -> tuple[list[IOC], list[str]]:
    """Parse free-form lines into unique IOCs (input order kept) plus rejected tokens.

    Blank lines and ``#`` comments are ignored; several indicators may share a line
    when separated by whitespace, commas or semicolons.
    """
    seen: set[tuple[IOCType, str]] = set()
    iocs: list[IOC] = []
    rejected: list[str] = []
    for line in lines:
        line = _INLINE_COMMENT.split(line, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        for token in _TOKEN_SPLIT.split(line):
            if not token:
                continue
            ioc = classify(token)
            if ioc is None:
                rejected.append(token)
                continue
            key = (ioc.type, ioc.value)
            if key not in seen:
                seen.add(key)
                iocs.append(ioc)
    return iocs, rejected
