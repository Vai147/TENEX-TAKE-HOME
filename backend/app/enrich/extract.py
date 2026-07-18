"""Pull threat-intel indicators out of parsed log entries.

Pure and I/O-free, like the detectors: `(entries) -> list[Indicator]`, so it is
unit-testable without a database or the network. Only *destination* indicators are
produced — the source IP is the internal client (e.g. 10.x) and has no external
reputation to look up.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.detectors.base import EntryLike, is_blocked

IndicatorType = str  # "url" | "domain" | "ip"

# A full URL is worth keeping but caps out fast; trim so a crafted query string
# cannot bloat storage or a VT request.
MAX_URL_LENGTH = 400


@dataclass(frozen=True)
class Indicator:
    """One deduplicated indicator and the entries it was seen on.

    `blocked` and `entry_ids` are ranking/attribution hints for the caller: which
    indicators to spend limited VirusTotal quota on first, and which log row to
    anchor an alert to.
    """

    type: IndicatorType
    value: str
    entry_ids: tuple[int, ...]
    blocked: bool

    @property
    def representative_entry_id(self) -> int | None:
        return self.entry_ids[0] if self.entry_ids else None


def _host_of(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _is_public_ip(value: str) -> bool:
    """True only for a routable public IP. Private/loopback/link-local/reserved
    addresses are internal and have no external reputation, so they are skipped."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)


def _classify_host(host: str) -> IndicatorType | None:
    """`ip` for a public IP host, `domain` for a hostname, None for anything to skip
    (a private IP, or a bare hostname with no dot that cannot be a real domain)."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "domain" if "." in host else None
    return "ip" if _is_public_ip(host) else None


def extract_indicators(entries: Sequence[EntryLike]) -> list[Indicator]:
    """Deduplicated indicators across all entries, worst-first.

    For every entry URL we emit the host (a `domain` or public `ip`) and the full
    `url`. Duplicates are merged, carrying every source entry id and whether any of
    them was blocked. Ordering puts blocked-linked indicators first, then hosts
    before full URLs, so a caller capping lookups spends quota on the highest-signal
    destinations.
    """
    # key -> (type, value, entry_ids, blocked)
    seen: dict[tuple[str, str], dict] = {}

    def add(itype: IndicatorType, value: str, entry_id: int | None, blocked: bool) -> None:
        key = (itype, value)
        bucket = seen.get(key)
        if bucket is None:
            bucket = {"type": itype, "value": value, "entry_ids": [], "blocked": False}
            seen[key] = bucket
        if entry_id is not None and entry_id not in bucket["entry_ids"]:
            bucket["entry_ids"].append(entry_id)
        bucket["blocked"] = bucket["blocked"] or blocked

    for entry in entries:
        if not entry.url:
            continue
        blocked = is_blocked(entry)
        host = _host_of(entry.url)
        if host:
            host_type = _classify_host(host)
            if host_type:
                add(host_type, host, entry.id, blocked)
        add("url", entry.url[:MAX_URL_LENGTH], entry.id, blocked)

    indicators = [
        Indicator(
            type=b["type"],
            value=b["value"],
            entry_ids=tuple(b["entry_ids"]),
            blocked=b["blocked"],
        )
        for b in seen.values()
    ]

    type_rank = {"ip": 0, "domain": 0, "url": 1}
    indicators.sort(key=lambda i: (not i.blocked, type_rank.get(i.type, 2), i.value))
    return indicators
