"""Detector: activity outside working hours.

Weak on its own — plenty of people work late — so it scores conservatively and
earns its keep by corroborating the other detectors during scoring. A 3am
credential burst is a stronger story than either signal alone.

Business hours are evaluated in UTC. A real deployment would carry a per-tenant
timezone; that is out of scope for the prototype and noted in the README.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from app.detectors.base import (
    EntryLike,
    Finding,
    clamp,
    group_by_ip,
    quote_untrusted,
    severity_for,
)

TYPE = "off_hours"

BUSINESS_START_HOUR = 7
BUSINESS_END_HOUR = 19  # exclusive
DEEP_NIGHT_END_HOUR = 5  # 00:00–04:59, when even late workers are asleep
SATURDAY = 5  # datetime.weekday(): Monday is 0

DEEP_NIGHT_SCORE = 0.6
OFF_HOURS_SCORE = 0.35
WEEKEND_BONUS = 0.15
VOLUME_BONUS_PER_ENTRY = 0.02
MAX_VOLUME_BONUS = 0.25


def _is_weekend(ts: datetime) -> bool:
    return ts.weekday() >= SATURDAY


def _is_off_hours(ts: datetime) -> bool:
    if _is_weekend(ts):
        return True
    return not (BUSINESS_START_HOUR <= ts.hour < BUSINESS_END_HOUR)


def detect_off_hours(entries: Sequence[EntryLike]) -> list[Finding]:
    """One finding per IP, anchored at its earliest off-hours request."""
    findings: list[Finding] = []

    for ip, ip_entries in group_by_ip(entries).items():
        off = [e for e in ip_entries if e.ts is not None and _is_off_hours(e.ts)]
        if not off:
            continue

        is_deep_night = any(e.ts.hour < DEEP_NIGHT_END_HOUR for e in off)
        is_weekend = any(_is_weekend(e.ts) for e in off)

        base = DEEP_NIGHT_SCORE if is_deep_night else OFF_HOURS_SCORE
        volume_bonus = min(MAX_VOLUME_BONUS, len(off) * VOLUME_BONUS_PER_ENTRY)
        confidence = clamp(
            base + volume_bonus + (WEEKEND_BONUS if is_weekend else 0.0)
        )

        anchor = min(off, key=lambda e: e.ts)
        window = "outside business hours"
        if is_deep_night:
            window = "in the middle of the night"
        elif is_weekend:
            window = "over the weekend"

        findings.append(
            Finding(
                type=TYPE,
                entry_id=anchor.id,
                confidence=confidence,
                severity=severity_for(confidence),
                reason=(
                    f"{quote_untrusted(ip)} made {len(off)} request(s) {window}, first at "
                    f"{anchor.ts.isoformat()} (business hours: "
                    f"{BUSINESS_START_HOUR:02d}:00–{BUSINESS_END_HOUR:02d}:00 UTC, Mon–Fri)."
                ),
            )
        )

    return findings
