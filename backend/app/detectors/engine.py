"""Composes the deterministic detectors into one ranked list of findings.

Confidence answers "how sure is this detector?"; the weight answers "how much do
we care if it is right?". A certain off-hours hit is less actionable than a
probable data exfil, so the two are multiplied to rank, while the raw confidence
is what gets persisted and shown to the analyst.

`run_detectors` returns *everything* it found, ranked. Truncation is the caller's
decision via `top_findings`, so that statistics over the full result set (how many
entries were flagged) never silently inherit a display limit.
"""
from __future__ import annotations

import logging
from collections.abc import Sequence

from app.detectors import blocked_spike, byte_volume, ip_burst, off_hours, rare_user_agent
from app.detectors.base import EntryLike, Finding

logger = logging.getLogger(__name__)

DETECTORS = (
    ip_burst.detect_ip_burst,
    blocked_spike.detect_blocked_spike,
    rare_user_agent.detect_rare_user_agent,
    byte_volume.detect_byte_volume,
    off_hours.detect_off_hours,
)

DETECTOR_WEIGHTS = {
    ip_burst.TYPE: 1.0,
    byte_volume.TYPE: 1.0,
    blocked_spike.TYPE: 0.9,
    rare_user_agent.TYPE: 0.7,
    off_hours.TYPE: 0.5,
}
DEFAULT_WEIGHT = 0.5

# How many findings an analyst is shown. Ranking decides which survive the cut.
MAX_FINDINGS = 50


def score(finding: Finding) -> float:
    """Rank order only — not persisted, and not the same thing as confidence."""
    return finding.confidence * DETECTOR_WEIGHTS.get(finding.type, DEFAULT_WEIGHT)


def _sort_key(finding: Finding) -> tuple[float, str, int]:
    # Type and entry id break ties so the output is stable across runs.
    entry_id = finding.entry_id if finding.entry_id is not None else -1
    return (-score(finding), finding.type, entry_id)


def run_detectors(entries: Sequence[EntryLike]) -> list[Finding]:
    """Every finding from every detector, worst first.

    Detectors are best-effort, mirroring the parser's tolerance for messy input:
    one detector blowing up on a pathological file must not throw away the other
    four's results, nor fail an upload whose entries parsed and stored fine.
    """
    findings: list[Finding] = []
    for detect in DETECTORS:
        try:
            findings.extend(detect(entries))
        except Exception:
            logger.exception("Detector %s failed; skipping it", detect.__name__)

    return sorted(findings, key=_sort_key)


def top_findings(findings: Sequence[Finding]) -> list[Finding]:
    """The slice worth showing an analyst. Never use this to compute totals."""
    return list(findings[:MAX_FINDINGS])