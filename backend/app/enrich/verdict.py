"""Pure mapping from a VirusTotal verdict to an alert severity and a finding.

No DB, no network — just the policy for turning detection counts into an
analyst-facing judgement, kept in one testable place.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.detectors.base import clamp, quote_untrusted
from app.enrich.virustotal import VtVerdict

# Malicious-engine thresholds → severity. Ordered high to low; first match wins.
_SEVERITY_BANDS: tuple[tuple[int, str], ...] = (
    (5, "critical"),
    (3, "high"),
    (1, "medium"),
)

FINDING_TYPE = "threat_intel"
FINDING_SOURCE = "virustotal"


def is_alertable(verdict: VtVerdict, min_malicious: int) -> bool:
    """Worth raising as a finding: enough engines called it malicious, or it is
    suspicious with at least one malicious hit shy of the bar."""
    if verdict.status != "ok":
        return False
    return verdict.malicious >= min_malicious or (
        verdict.malicious >= 1 and verdict.suspicious >= 1
    )


def severity_for(verdict: VtVerdict) -> str:
    for threshold, label in _SEVERITY_BANDS:
        if verdict.malicious >= threshold:
            return label
    return "low"  # suspicious-only, or a single malicious hit below the bands


def confidence_for(verdict: VtVerdict) -> float:
    """A display figure for the confidence meter, rising with engine consensus."""
    return clamp(0.5 + 0.1 * verdict.malicious + 0.03 * verdict.suspicious, 0.5, 0.99)


@dataclass(frozen=True)
class FindingFields:
    type: str
    source: str
    severity: str
    confidence: float
    reason: str
    entry_id: int | None


def to_finding(verdict: VtVerdict, entry_id: int | None) -> FindingFields:
    """Finding fields for an alertable verdict. `reason` quotes the indicator and
    threat labels, which are adversary-influenced — passed through
    `quote_untrusted` and contracted as plain text, never markup."""
    label_suffix = ""
    if verdict.threat_labels:
        joined = ", ".join(verdict.threat_labels[:3])
        label_suffix = f" — {quote_untrusted(joined)}"

    reason = (
        f"VirusTotal flagged {verdict.indicator_type} "
        f"{quote_untrusted(verdict.indicator)}: "
        f"{verdict.malicious} malicious, {verdict.suspicious} suspicious"
        f"{label_suffix}"
    )
    return FindingFields(
        type=FINDING_TYPE,
        source=FINDING_SOURCE,
        severity=severity_for(verdict),
        confidence=confidence_for(verdict),
        reason=reason,
        entry_id=entry_id,
    )
