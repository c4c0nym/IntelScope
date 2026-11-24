"""Known-benign filtering so analysts (and API quotas) are not spent on noise."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from pathlib import Path

from iocscope.models import IOC, IOCType

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

DEFAULT_IPS = {
    "8.8.8.8", "8.8.4.4",  # Google Public DNS
    "1.1.1.1", "1.0.0.1",  # Cloudflare DNS
    "9.9.9.9", "149.112.112.112",  # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
}

# Domain-level entries only. URLs are never allowlisted by host, because attackers
# routinely host payloads on legitimate platforms.
DEFAULT_DOMAINS = {
    "google.com", "gstatic.com", "googleapis.com",
    "microsoft.com", "windowsupdate.com", "office.com", "live.com",
    "apple.com", "icloud.com",
    "mozilla.org", "cloudflare.com",
}


class Allowlist:
    def __init__(
        self,
        ips: Iterable[str] = (),
        networks: Iterable[IPNetwork] = (),
        domains: Iterable[str] = (),
        skip_reserved: bool = True,
    ) -> None:
        self.ips = {str(ipaddress.ip_address(ip)) for ip in ips}
        self.networks = list(networks)
        self.domains = {d.lower().rstrip(".") for d in domains}
        self.skip_reserved = skip_reserved

    @classmethod
    def from_lines(cls, lines: Iterable[str], **kwargs) -> Allowlist:
        ips, networks, domains = [], [], []
        for line in lines:
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                if "/" in entry:
                    networks.append(ipaddress.ip_network(entry, strict=False))
                else:
                    ips.append(str(ipaddress.ip_address(entry)))
            except ValueError:
                domains.append(entry)
        return cls(ips, networks, domains, **kwargs)

    def merge(self, other: Allowlist) -> Allowlist:
        return Allowlist(
            self.ips | other.ips,
            self.networks + other.networks,
            self.domains | other.domains,
            skip_reserved=self.skip_reserved,
        )

    def match(self, ioc: IOC) -> str | None:
        """Return why the IOC is allowlisted, or None."""
        if ioc.type.is_ip:
            ip = ipaddress.ip_address(ioc.value)
            if self.skip_reserved and not ip.is_global:
                return "non-routable / reserved address"
            if ioc.value in self.ips:
                return "allowlisted IP"
            if any(ip in net for net in self.networks):
                return "allowlisted network"
        elif ioc.type is IOCType.DOMAIN:
            for entry in self.domains:
                if ioc.value == entry or ioc.value.endswith("." + entry):
                    return f"allowlisted domain ({entry})"
        return None


def load_allowlist(
    extra_file: str | Path | None = None,
    include_defaults: bool = True,
    skip_reserved: bool = True,
) -> Allowlist:
    base = Allowlist(
        DEFAULT_IPS if include_defaults else (),
        (),
        DEFAULT_DOMAINS if include_defaults else (),
        skip_reserved=skip_reserved,
    )
    if extra_file:
        text = Path(extra_file).read_text(encoding="utf-8")
        base = base.merge(Allowlist.from_lines(text.splitlines()))
    return base
