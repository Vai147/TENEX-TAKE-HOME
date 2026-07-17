"""Detector: user agents that are either statistically rare or openly automated.

Two independent signals, because either alone is weak:

* Rarity — a UA almost nobody else in the file uses. Only meaningful once the
  file is big enough for "share of traffic" to mean anything, hence
  MIN_ENTRIES_FOR_RARITY; in a 20-line file every UA is "rare".
* Signature — the UA names a tool. `sqlmap` in a proxy log is a different
  conversation from `curl`, so the two tiers score differently.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from app.detectors.base import EntryLike, Finding, clamp, quote_untrusted, severity_for

TYPE = "rare_user_agent"

# Rarity needs a population to be rare *within*.
MIN_ENTRIES_FOR_RARITY = 50
RARE_UA_SHARE = 0.15
RARITY_WEIGHT = 0.6

# Tools whose presence implies an active attempt to find or exploit a weakness.
EXPLOITATION_SIGNATURES = ("sqlmap", "nikto", "nmap", "masscan", "hydra", "havij", "acunetix")
EXPLOITATION_SCORE = 0.85

# Scripted clients: common in legitimate automation, but not in browser traffic.
AUTOMATION_SIGNATURES = (
    "curl/",
    "wget/",
    "python-requests",
    "python-urllib",
    "go-http-client",
    "libwww-perl",
    "java/",
)
AUTOMATION_SCORE = 0.5

MIN_CONFIDENCE = 0.3


def _signature_score(user_agent: str) -> float:
    lowered = user_agent.lower()
    if any(sig in lowered for sig in EXPLOITATION_SIGNATURES):
        return EXPLOITATION_SCORE
    if any(sig in lowered for sig in AUTOMATION_SIGNATURES):
        return AUTOMATION_SCORE
    return 0.0


def detect_rare_user_agent(entries: Sequence[EntryLike]) -> list[Finding]:
    """One finding per distinct user agent, anchored at its first appearance."""
    identified = [e for e in entries if e.user_agent]
    if not identified:
        return []

    counts = Counter(e.user_agent for e in identified)
    first_seen: dict[str, EntryLike] = {}
    for entry in identified:
        first_seen.setdefault(entry.user_agent, entry)

    total = len(identified)
    rarity_is_meaningful = total >= MIN_ENTRIES_FOR_RARITY
    findings: list[Finding] = []

    for user_agent, count in counts.items():
        share = count / total
        rarity_score = (
            clamp(1 - share / RARE_UA_SHARE) if rarity_is_meaningful else 0.0
        )
        signature_score = _signature_score(user_agent)

        confidence = clamp(RARITY_WEIGHT * rarity_score + signature_score)
        if confidence < MIN_CONFIDENCE:
            continue

        reasons = []
        if signature_score:
            reasons.append("matches a known non-browser tool signature")
        if rarity_score:
            reasons.append(f"used by only {share:.1%} of requests in this file")

        findings.append(
            Finding(
                type=TYPE,
                entry_id=first_seen[user_agent].id,
                confidence=confidence,
                severity=severity_for(confidence),
                reason=(
                    f"User agent '{quote_untrusted(user_agent)}' ({count} request(s)) "
                    f"{' and '.join(reasons)}."
                ),
            )
        )

    return findings
