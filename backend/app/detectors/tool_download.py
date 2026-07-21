"""Detector: an allowed proxy request downloads an executable or script payload."""
from __future__ import annotations

from collections.abc import Sequence
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from app.detectors.base import (
    EntryLike,
    Finding,
    clamp,
    is_blocked,
    quote_untrusted,
    severity_for,
)

TYPE = "tool_download"
MIN_DOWNLOAD_BYTES = 100_000
CRITICAL_DOWNLOAD_BYTES = 10_000_000
EXECUTABLE_SUFFIXES = frozenset({".exe", ".dll", ".msi", ".ps1", ".bat", ".scr"})
SCRIPTED_AGENTS = (
    "curl/",
    "wget/",
    "python-requests",
    "go-http-client",
    "powershell",
)


def _suffix(url: str | None) -> str:
    if not url:
        return ""
    try:
        return PurePosixPath(urlsplit(url).path).suffix.lower()
    except ValueError:
        return ""


def _is_scripted(entry: EntryLike) -> bool:
    agent = (entry.user_agent or "").lower()
    return any(signature in agent for signature in SCRIPTED_AGENTS)


def detect_tool_download(entries: Sequence[EntryLike]) -> list[Finding]:
    findings: list[Finding] = []

    for entry in entries:
        received = entry.bytes_recv or 0
        suffix = _suffix(entry.url)
        if (
            is_blocked(entry)
            or not _is_scripted(entry)
            or suffix not in EXECUTABLE_SUFFIXES
            or received < MIN_DOWNLOAD_BYTES
        ):
            continue

        confidence = clamp(0.7 + 0.3 * received / CRITICAL_DOWNLOAD_BYTES)
        findings.append(
            Finding(
                type=TYPE,
                entry_id=entry.id,
                confidence=confidence,
                severity=severity_for(confidence),
                reason=(
                    f"Downloaded {received:,} bytes from executable or script URL "
                    f"'{quote_untrusted(entry.url or '')}' ({suffix} payload)."
                ),
            )
        )

    return findings
