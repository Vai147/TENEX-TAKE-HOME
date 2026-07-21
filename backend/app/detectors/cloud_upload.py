"""Detector: a large outbound transfer targets a consumer cloud service."""
from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlsplit

from app.detectors.base import (
    EntryLike,
    Finding,
    clamp,
    is_blocked,
    quote_untrusted,
    severity_for,
)

TYPE = "cloud_upload"
MIN_UPLOAD_BYTES = 10_000_000
CRITICAL_UPLOAD_BYTES = 100_000_000
CLOUD_HOSTS = (
    "drive.google.com",
    "dropbox.com",
    "box.com",
    "onedrive.live.com",
    "s3.amazonaws.com",
)


def _host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _is_cloud_host(host: str | None) -> bool:
    return bool(
        host
        and any(
            host == domain or host.endswith(f".{domain}") for domain in CLOUD_HOSTS
        )
    )


def detect_cloud_upload(entries: Sequence[EntryLike]) -> list[Finding]:
    findings: list[Finding] = []

    for entry in entries:
        sent = entry.bytes_sent or 0
        host = _host(entry.url)
        if is_blocked(entry) or sent < MIN_UPLOAD_BYTES or not _is_cloud_host(host):
            continue

        confidence = clamp(0.65 + 0.35 * sent / CRITICAL_UPLOAD_BYTES)
        findings.append(
            Finding(
                type=TYPE,
                entry_id=entry.id,
                confidence=confidence,
                severity=severity_for(confidence),
                reason=(
                    f"Uploaded {sent:,} bytes to cloud service "
                    f"'{quote_untrusted(host or '')}' (threshold: {MIN_UPLOAD_BYTES:,})."
                ),
            )
        )

    return findings
