"""Roll log entries up into compact statistics.

Two consumers: the Claude layer (which gets aggregates, never raw log lines — a
10 MB file would blow the context window and cost a fortune to little benefit)
and the Phase 6 charts. Pure functions, no DB.
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from urllib.parse import urlparse

from app.detectors.base import EntryLike, Finding, is_blocked

BUCKET = timedelta(hours=1)
TOP_TALKER_LIMIT = 10
MAX_BREAKDOWN_ITEMS = 6


@dataclass(frozen=True)
class TimelineBucket:
    start: str  # ISO-8601, pre-serialized for JSON storage and the chart
    requests: int
    blocked: int


@dataclass(frozen=True)
class TalkerStat:
    src_ip: str
    requests: int
    blocked: int
    bytes_recv: int
    bytes_sent: int


@dataclass(frozen=True)
class Aggregates:
    total_entries: int
    blocked_entries: int
    unique_ips: int
    unique_users: int
    first_seen: str | None
    last_seen: str | None
    timeline: list[TimelineBucket]
    top_talkers: list[TalkerStat]


def _floor_to_bucket(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def _timeline(entries: Sequence[EntryLike]) -> list[TimelineBucket]:
    """Requests per hour. Empty hours are omitted, not zero-filled: a gap in proxy
    traffic is not the same claim as "we observed zero requests"."""
    buckets: dict[datetime, list[int]] = {}
    for entry in entries:
        if entry.ts is None:
            continue
        key = _floor_to_bucket(entry.ts)
        counts = buckets.setdefault(key, [0, 0])
        counts[0] += 1
        if is_blocked(entry):
            counts[1] += 1

    return [
        TimelineBucket(start=key.isoformat(),
                       requests=counts[0], blocked=counts[1])
        for key, counts in sorted(buckets.items())
    ]


def _top_talkers(entries: Sequence[EntryLike]) -> list[TalkerStat]:
    stats: dict[str, list[int]] = {}
    for entry in entries:
        if not entry.src_ip:
            continue
        row = stats.setdefault(entry.src_ip, [0, 0, 0, 0])
        row[0] += 1
        if is_blocked(entry):
            row[1] += 1
        row[2] += entry.bytes_recv or 0
        row[3] += entry.bytes_sent or 0

    talkers = [
        TalkerStat(
            src_ip=ip, requests=r[0], blocked=r[1], bytes_recv=r[2], bytes_sent=r[3])
        for ip, r in stats.items()
    ]
    # Busiest first; IP breaks ties so the output is stable across runs.
    talkers.sort(key=lambda t: (-t.requests, t.src_ip))
    return talkers[:TOP_TALKER_LIMIT]


def _take(items: set[str]) -> list[str]:
    return sorted(items)[:MAX_BREAKDOWN_ITEMS]


def _hostname(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc or url


def _hour_ips(entries: Sequence[EntryLike]) -> list[dict[str, object]]:
    hour_sets: dict[int, dict[str, set[str]]] = {}
    for entry in entries:
        if entry.ts is None or not entry.src_ip:
            continue
        hour = entry.ts.hour
        bucket = hour_sets.setdefault(
            hour, {"allowed": set(), "blocked": set()})
        (bucket["blocked"] if is_blocked(entry)
         else bucket["allowed"]).add(entry.src_ip)

    return [
        {"hour": hour, "allowed": _take(
            bucket["allowed"]), "blocked": _take(bucket["blocked"])}
        for hour, bucket in sorted(hour_sets.items())
    ]


def _talker_dests(entries: Sequence[EntryLike]) -> list[dict[str, object]]:
    dest_sets: dict[str, dict[str, set[str]]] = {}
    for entry in entries:
        if not entry.src_ip or not entry.url:
            continue
        bucket = dest_sets.setdefault(
            entry.src_ip, {"allowed": set(), "blocked": set()})
        target = _hostname(entry.url)
        (bucket["blocked"] if is_blocked(entry)
         else bucket["allowed"]).add(target)

    return [
        {"src_ip": src_ip, "allowed": _take(
            bucket["allowed"]), "blocked": _take(bucket["blocked"])}
        for src_ip, bucket in sorted(dest_sets.items())
    ]


def _detector_ips(entries: Sequence[EntryLike], findings: Sequence[Finding]) -> list[dict[str, object]]:
    entry_ip: dict[int, str] = {}
    for entry in entries:
        if entry.id is not None and entry.src_ip:
            entry_ip[entry.id] = entry.src_ip

    detector_sets: dict[str, set[str]] = {}
    for finding in findings:
        if finding.entry_id is None:
            continue
        ip = entry_ip.get(finding.entry_id)
        if not ip:
            continue
        detector_sets.setdefault(finding.type, set()).add(ip)

    return [
        {"type": type_, "ips": _take(ips)}
        for type_, ips in sorted(detector_sets.items())
    ]


def breakdowns_json(entries: Sequence[EntryLike], findings: Sequence[Finding]) -> str:
    return json.dumps(
        {
            "hour_ips": _hour_ips(entries),
            "talker_dests": _talker_dests(entries),
            "detector_ips": _detector_ips(entries, findings),
        }
    )


def build_aggregates(entries: Sequence[EntryLike]) -> Aggregates:
    timestamps = sorted(e.ts for e in entries if e.ts is not None)
    return Aggregates(
        total_entries=len(entries),
        blocked_entries=sum(1 for e in entries if is_blocked(e)),
        unique_ips=len({e.src_ip for e in entries if e.src_ip}),
        unique_users=len({e.user for e in entries if e.user}),
        first_seen=timestamps[0].isoformat() if timestamps else None,
        last_seen=timestamps[-1].isoformat() if timestamps else None,
        timeline=_timeline(entries),
        top_talkers=_top_talkers(entries),
    )


def timeline_json(aggregates: Aggregates) -> str:
    return json.dumps([asdict(b) for b in aggregates.timeline])


def top_talkers_json(aggregates: Aggregates) -> str:
    return json.dumps([asdict(t) for t in aggregates.top_talkers])
