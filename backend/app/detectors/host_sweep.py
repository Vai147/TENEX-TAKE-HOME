"""Detector: one source rapidly touches many distinct web destinations.

A normal page can fan out across several hosts, so this only claims network
service discovery when the burst comes from an explicitly scripted client.
"""
from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlsplit

from app.detectors.base import (
    EntryLike,
    Finding,
    clamp,
    group_by_ip,
    quote_untrusted,
    severity_for,
)

TYPE = "host_sweep"
WINDOW_SECONDS = 30
MIN_DISTINCT_HOSTS = 4
SATURATION_HOSTS = 8
SCRIPTED_AGENTS = (
    "masscan",
    "nmap",
    "nikto",
    "sqlmap",
    "curl/",
    "wget/",
    "python-requests",
    "go-http-client",
)


def _host(entry: EntryLike) -> str | None:
    if not entry.url:
        return None
    try:
        return urlsplit(entry.url).hostname
    except ValueError:
        return None


def _is_scripted(entry: EntryLike) -> bool:
    agent = (entry.user_agent or "").lower()
    return any(signature in agent for signature in SCRIPTED_AGENTS)


def detect_host_sweep(entries: Sequence[EntryLike]) -> list[Finding]:
    """One finding per source IP, anchored to its densest scripted host sweep."""
    findings: list[Finding] = []

    for ip, ip_entries in group_by_ip(entries).items():
        candidates = sorted(
            (
                entry
                for entry in ip_entries
                if entry.ts and _host(entry) and _is_scripted(entry)
            ),
            key=lambda entry: entry.ts,
        )
        best_hosts: set[str] = set()
        best_anchor: EntryLike | None = None
        left = 0

        for right, entry in enumerate(candidates):
            while (entry.ts - candidates[left].ts).total_seconds() > WINDOW_SECONDS:
                left += 1
            hosts = {_host(candidate) for candidate in candidates[left : right + 1]}
            hosts.discard(None)
            if len(hosts) > len(best_hosts):
                best_hosts = hosts
                best_anchor = candidates[left]

        if len(best_hosts) < MIN_DISTINCT_HOSTS or best_anchor is None:
            continue

        confidence = clamp(len(best_hosts) / SATURATION_HOSTS)
        findings.append(
            Finding(
                type=TYPE,
                entry_id=best_anchor.id,
                confidence=confidence,
                severity=severity_for(confidence),
                reason=(
                    f"{quote_untrusted(ip)} used a scripted client to contact "
                    f"{len(best_hosts)} distinct hosts within {WINDOW_SECONDS}s "
                    f"(threshold: {MIN_DISTINCT_HOSTS})."
                ),
            )
        )

    return findings
