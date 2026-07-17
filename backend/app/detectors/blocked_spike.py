"""Detector: a source IP whose traffic is mostly refused by the proxy.

A high block ratio separates an attacker probing for a way in from a user who
occasionally trips a content filter.
"""
from __future__ import annotations

from collections.abc import Sequence

from app.detectors.base import (
    EntryLike,
    Finding,
    clamp,
    group_by_ip,
    is_blocked,
    quote_untrusted,
    severity_for,
)

TYPE = "blocked_spike"

BLOCKED_RATIO_THRESHOLD = 0.5
# Below this, a couple of filtered ad domains would look like an attack.
MIN_BLOCKED_COUNT = 3
SATURATION_FACTOR = 2.0

# How far past the ratio threshold matters more than raw volume, but a large
# number of blocks is corroborating evidence on its own.
RATIO_WEIGHT = 0.6
VOLUME_WEIGHT = 0.4


def detect_blocked_spike(entries: Sequence[EntryLike]) -> list[Finding]:
    findings: list[Finding] = []

    for ip, ip_entries in group_by_ip(entries).items():
        blocked = [e for e in ip_entries if is_blocked(e)]
        if len(blocked) < MIN_BLOCKED_COUNT:
            continue

        ratio = len(blocked) / len(ip_entries)
        if ratio < BLOCKED_RATIO_THRESHOLD:
            continue

        ratio_score = (ratio - BLOCKED_RATIO_THRESHOLD) / (1 - BLOCKED_RATIO_THRESHOLD)
        volume_score = clamp(len(blocked) / (MIN_BLOCKED_COUNT * SATURATION_FACTOR))
        confidence = clamp(RATIO_WEIGHT * ratio_score + VOLUME_WEIGHT * volume_score)

        findings.append(
            Finding(
                type=TYPE,
                entry_id=blocked[0].id,
                confidence=confidence,
                severity=severity_for(confidence),
                reason=(
                    f"{quote_untrusted(ip)} had {len(blocked)} of {len(ip_entries)} requests blocked "
                    f"({ratio:.0%}), above the {BLOCKED_RATIO_THRESHOLD:.0%} threshold."
                ),
            )
        )

    return findings
