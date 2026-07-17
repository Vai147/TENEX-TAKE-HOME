"""ZScaler Web Proxy log parser.

Input format (documented, CSV with header):
    timestamp,user,src_ip,url,action,status,bytes_sent,bytes_recv,user_agent

Pure module: takes raw text, returns structured dicts. No DB, no HTTP.
Malformed rows are skipped but counted, so a few bad lines never abort a file.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import datetime, timezone

BOM = "\ufeff"  # zero-width; spelled as an escape so it stays visible in source

# Canonical column names we understand. Parsing is tolerant of column order
# and of unknown extra columns (ignored).
KNOWN_FIELDS = {
    "timestamp",
    "user",
    "src_ip",
    "url",
    "action",
    "status",
    "bytes_sent",
    "bytes_recv",
    "user_agent",
}


@dataclass
class ParsedEntry:
    ts: datetime | None
    src_ip: str | None
    user: str | None
    url: str | None
    action: str | None
    status_code: int | None
    bytes_sent: int | None
    bytes_recv: int | None
    user_agent: str | None
    raw: str


@dataclass
class ParseResult:
    entries: list[ParsedEntry] = field(default_factory=list)
    total_lines: int = 0
    skipped_lines: int = 0


def _parse_ts(value: str) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    # Support trailing Z and common ISO variants.
    normalized = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def parse_logs(text: str) -> ParseResult:
    """Parse ZScaler CSV text into structured entries.

    Requires a header row containing at least the known column names.
    """
    result = ParseResult()
    # Excel's "CSV UTF-8" and most Windows exporters prefix a BOM. Left in place it
    # becomes part of the first header name, so "timestamp" silently stops matching
    # and every row parses with ts=None — muting the time-based detectors instead of
    # failing loudly. Strip it before the header is read.
    reader = csv.DictReader(io.StringIO(text.lstrip(BOM)))

    if reader.fieldnames is None:
        return result

    # Guard: reject files whose header shares no known columns.
    header = {h.strip() for h in reader.fieldnames if h}
    if not (header & KNOWN_FIELDS):
        raise ValueError(
            "Unrecognized log format: header must include ZScaler columns "
            f"such as {sorted(KNOWN_FIELDS)}"
        )

    for row in reader:
        result.total_lines += 1
        raw = ",".join((row.get(h) or "") for h in reader.fieldnames)
        try:
            entry = ParsedEntry(
                ts=_parse_ts(row.get("timestamp", "")),
                src_ip=_clean(row.get("src_ip")),
                user=_clean(row.get("user")),
                url=_clean(row.get("url")),
                action=_clean(row.get("action")),
                status_code=_parse_int(row.get("status")),
                bytes_sent=_parse_int(row.get("bytes_sent")),
                bytes_recv=_parse_int(row.get("bytes_recv")),
                user_agent=_clean(row.get("user_agent")),
                raw=raw,
            )
        except Exception:
            result.skipped_lines += 1
            continue
        result.entries.append(entry)

    return result
