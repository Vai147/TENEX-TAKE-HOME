"""Shared types and helpers for the deterministic anomaly detectors.

Every detector is a pure function `(entries) -> list[Finding]`: no DB, no HTTP,
no shared state. That keeps each one unit-testable in isolation and lets the
engine compose them in any order.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


class EntryLike(Protocol):
    """Structural view of the log entry fields a detector may read.

    `app.models.LogEntry` satisfies this once flushed (so `id` is assigned);
    tests use a lightweight stub with the same attributes.
    """

    id: int | None
    ts: datetime | None
    src_ip: str | None
    user: str | None
    url: str | None
    action: str | None
    status_code: int | None
    bytes_sent: int | None
    bytes_recv: int | None
    user_agent: str | None


@dataclass(frozen=True)
class Finding:
    """One deterministic detection, anchored to the entry that best evidences it.

    `reason` is analyst-facing prose that quotes fields from the log file, which is
    adversary-controlled input: an attacker picks their own User-Agent, and URLs are
    equally attacker-influenced. Quoted values are passed through `quote_untrusted`,
    but the contract for every consumer is that `reason` is **plain text, never
    markup** — render it escaped. Never interpolate it into HTML unescaped.
    """

    type: str
    entry_id: int | None
    confidence: float
    severity: str
    reason: str
    source: str = "deterministic"


# Long enough to identify a real UA, short enough that a crafted one cannot flood
# the findings table or an analyst's screen.
MAX_QUOTED_LENGTH = 120


def quote_untrusted(value: str, limit: int = MAX_QUOTED_LENGTH) -> str:
    """Make an adversary-controlled log field safe to embed in analyst-facing prose.

    Strips control characters (newlines forge log structure, ANSI escapes hijack a
    terminal) and truncates. This is defence in depth, not the primary XSS control —
    the frontend escaping `reason` on render is. It never makes the value HTML-safe,
    because escaping belongs at the point of rendering, not storage.
    """
    cleaned = "".join(ch for ch in value if ch.isprintable())
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1] + "…"
    return cleaned


# (exclusive upper bound, label) — anything at or above the last bound is critical.
SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (0.4, "low"),
    (0.7, "medium"),
    (0.9, "high"),
)


def severity_for(confidence: float) -> str:
    for upper, label in SEVERITY_BANDS:
        if confidence < upper:
            return label
    return "critical"


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


BLOCKED_ACTIONS = frozenset({"blocked", "denied", "drop", "dropped"})
BLOCKED_STATUS_CODES = frozenset({401, 403, 407})


def is_blocked(entry: EntryLike) -> bool:
    """A request the proxy refused, by either the action column or the status code."""
    if (entry.action or "").strip().lower() in BLOCKED_ACTIONS:
        return True
    return entry.status_code in BLOCKED_STATUS_CODES


def group_by_ip(entries: Sequence[EntryLike]) -> dict[str, list[EntryLike]]:
    """Bucket entries by source IP, dropping entries with no IP to attribute."""
    groups: dict[str, list[EntryLike]] = {}
    for entry in entries:
        if not entry.src_ip:
            continue
        groups.setdefault(entry.src_ip, []).append(entry)
    return groups
