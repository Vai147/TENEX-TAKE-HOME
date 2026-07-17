"""Detector: transfers far larger than the rest of the file — possible exfiltration.

Uses Tukey's fence (Q3 + k*IQR) rather than a mean/stddev z-score. Proxy logs are
heavily skewed and full of repeated values (every blocked request transfers the
same few bytes), which both drags the mean toward the noise and lets a single
huge transfer inflate the stddev enough to mask the merely-large ones. Quartiles
ignore both problems.

Only the high side is flagged; a small response is not a security event. Zero-byte
rows are excluded — they are blocked requests, not transfers, and including them
would define "typical" as "no data moved".
"""
from __future__ import annotations

from collections.abc import Sequence
from statistics import quantiles

from app.detectors.base import EntryLike, Finding, clamp, severity_for

TYPE = "byte_volume"

WATCHED_FIELDS = ("bytes_recv", "bytes_sent")
# Quartiles from fewer samples than this are noise, not a baseline.
MIN_SAMPLES = 8
# 3.0 is Tukey's "extreme outlier" fence (1.5 is the mild one — too chatty here).
IQR_MULTIPLIER = 3.0
SATURATION_FACTOR = 2.0


def _fence(entries: Sequence[EntryLike], field: str) -> tuple[float, float] | None:
    """Return (q3, iqr) for a field's positive values, or None if unmeasurable."""
    values = sorted(
        value for e in entries if (value := getattr(e, field) or 0) > 0
    )
    if len(values) < MIN_SAMPLES:
        return None

    q1, _, q3 = quantiles(values, n=4, method="inclusive")
    iqr = q3 - q1
    if iqr <= 0:  # more than half the file is one identical value: no spread to compare against
        return None
    return q3, iqr


def detect_byte_volume(entries: Sequence[EntryLike]) -> list[Finding]:
    """One finding per outlying entry, scored on its worst field."""
    fences = {field: _fence(entries, field) for field in WATCHED_FIELDS}
    findings: list[Finding] = []

    for entry in entries:
        worst: tuple[float, str, int] | None = None

        for field in WATCHED_FIELDS:
            fence = fences[field]
            value = getattr(entry, field) or 0
            if fence is None or value <= 0:
                continue

            q3, iqr = fence
            excess = (value - q3) / iqr
            if excess < IQR_MULTIPLIER:
                continue
            if worst is None or excess > worst[0]:
                worst = (excess, field, value)

        if worst is None:
            continue

        excess, field, value = worst
        confidence = clamp(excess / (IQR_MULTIPLIER * SATURATION_FACTOR))
        direction = "downloaded" if field == "bytes_recv" else "uploaded"
        findings.append(
            Finding(
                type=TYPE,
                entry_id=entry.id,
                confidence=confidence,
                severity=severity_for(confidence),
                reason=(
                    f"{value:,} bytes {direction} — {excess:.1f} interquartile ranges "
                    f"above this file's upper quartile for {field} "
                    f"(outlier fence: {IQR_MULTIPLIER})."
                ),
            )
        )

    return findings
