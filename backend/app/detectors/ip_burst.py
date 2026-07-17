"""Detector: a source IP firing many requests inside a short window.

Catches credential stuffing, scanning, and scripted enumeration — traffic that a
human driving a browser cannot physically produce.
"""
from __future__ import annotations

from collections.abc import Sequence

from app.detectors.base import (
    EntryLike,
    Finding,
    clamp,
    group_by_ip,
    quote_untrusted,
    severity_for,
)

TYPE = "ip_burst"

BURST_WINDOW_SECONDS = 10
MIN_BURST_COUNT = 5
# A window holding MIN_BURST_COUNT * SATURATION_FACTOR requests scores 1.0.
SATURATION_FACTOR = 2.0


def _peak_window(entries: list[EntryLike]) -> tuple[int, EntryLike | None]:
    """Densest BURST_WINDOW_SECONDS window, via an O(n) two-pointer sweep.

    Returns the request count and the entry that opens that window.
    """
    ordered = sorted(entries, key=lambda e: e.ts)
    best_count = 0
    best_anchor: EntryLike | None = None
    left = 0

    for right in range(len(ordered)):
        span = (ordered[right].ts - ordered[left].ts).total_seconds()
        while span > BURST_WINDOW_SECONDS:
            left += 1
            span = (ordered[right].ts - ordered[left].ts).total_seconds()
        count = right - left + 1
        if count > best_count:
            best_count = count
            best_anchor = ordered[left]

    return best_count, best_anchor


def detect_ip_burst(entries: Sequence[EntryLike]) -> list[Finding]:
    """One finding per IP, describing its single worst window."""
    findings: list[Finding] = []

    for ip, ip_entries in group_by_ip(entries).items():
        timed = [e for e in ip_entries if e.ts is not None]
        if len(timed) < MIN_BURST_COUNT:
            continue

        count, anchor = _peak_window(timed)
        if count < MIN_BURST_COUNT or anchor is None:
            continue

        confidence = clamp(count / (MIN_BURST_COUNT * SATURATION_FACTOR))
        findings.append(
            Finding(
                type=TYPE,
                entry_id=anchor.id,
                confidence=confidence,
                severity=severity_for(confidence),
                reason=(
                    f"{quote_untrusted(ip)} made {count} requests within {BURST_WINDOW_SECONDS}s "
                    f"starting {anchor.ts.isoformat()} "
                    f"(threshold: {MIN_BURST_COUNT})."
                ),
            )
        )

    return findings
