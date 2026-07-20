"""Analysis orchestration: save file, parse, persist entries, detect, narrate.

Kept separate from the HTTP route so the pipeline is testable in isolation.
"""
from __future__ import annotations

import logging
import os
import uuid

from sqlalchemy.orm import Session

from app.aggregates import build_aggregates, timeline_json, top_talkers_json
from app.config import get_settings
from app.detectors import run_detectors, top_findings
from app.detectors.base import Finding
from app.llm import LlmUnavailable, analyse, fallback_narrative
from app.models import AnalysisSummary, AnomalyFinding, LogEntry, Upload
from app.parser import parse_logs

logger = logging.getLogger(__name__)
settings = get_settings()


def save_upload_file(raw_bytes: bytes, original_name: str) -> str:
    """Write raw upload to the storage volume, return the stored path."""
    os.makedirs(settings.upload_dir, exist_ok=True)
    safe = f"{uuid.uuid4().hex}_{os.path.basename(original_name)}"
    path = os.path.join(settings.upload_dir, safe)
    with open(path, "wb") as fh:
        fh.write(raw_bytes)
    return path


def process_upload(
    db: Session, user_id: int, filename: str, raw_bytes: bytes
) -> Upload:
    """Full ingest pipeline for one file (synchronous, prototype)."""
    stored_path = save_upload_file(raw_bytes, filename)

    upload = Upload(
        user_id=user_id,
        filename=filename,
        stored_path=stored_path,
        status="processing",
    )
    db.add(upload)
    db.flush()  # assigns upload.id without committing

    text = raw_bytes.decode("utf-8", errors="replace")
    parsed = parse_logs(text)  # raises ValueError on unrecognized format

    rows = [
        LogEntry(
            upload_id=upload.id,
            ts=e.ts,
            src_ip=e.src_ip,
            user=e.user,
            url=e.url,
            action=e.action,
            status_code=e.status_code,
            bytes_sent=e.bytes_sent,
            bytes_recv=e.bytes_recv,
            user_agent=e.user_agent,
            raw=e.raw,
        )
        for e in parsed.entries
    ]
    db.add_all(rows)
    db.flush()  # assigns row ids, which findings reference

    findings = run_detectors(rows)
    shown = top_findings(findings)

    finding_rows = [
        AnomalyFinding(
            upload_id=upload.id,
            entry_id=f.entry_id,
            type=f.type,
            confidence=f.confidence,
            severity=f.severity,
            reason=f.reason,
            source=f.source,
        )
        # Only the top slice is stored and shown; the count below stays honest.
        for f in shown
    ]
    db.add_all(finding_rows)

    aggregates = build_aggregates(rows)
    narrative, llm_ok = _narrate(aggregates, shown, finding_rows, rows)

    upload.llm_ok = llm_ok
    db.add(
        AnalysisSummary(
            upload_id=upload.id,
            total_entries=len(rows),
            # Counted over every finding, not the displayed slice, and over distinct
            # entries, since one row can trip several detectors.
            flagged_count=len(
                {f.entry_id for f in findings if f.entry_id is not None}),
            timeline_json=timeline_json(aggregates),
            top_talkers_json=top_talkers_json(aggregates),
            breakdowns_json=breakdowns_json(rows, finding_rows),
            narrative=narrative,
        )
    )

    upload.status = "done"
    db.commit()
    db.refresh(upload)
    return upload


def _narrate(
    aggregates,
    shown: list[Finding],
    finding_rows: list[AnomalyFinding],
    entries: list[LogEntry],
) -> tuple[str, bool]:
    """Ask Claude to narrate and annotate. Returns (narrative, llm_ok).

    Never raises: the log entries and findings are already correct and stored by the
    time we get here, so a model failure must cost prose, not the upload. `llm_ok`
    tells the UI which kind of narrative it is looking at.
    """
    try:
        analysis = analyse(aggregates, shown, entries)
    except LlmUnavailable as exc:
        logger.info(
            "Claude analysis unavailable, using deterministic narrative: %s", exc)
        return fallback_narrative(aggregates, shown), False
    except Exception:
        # A bug in our own LLM plumbing must not fail an otherwise good upload.
        logger.exception("Unexpected error in the Claude layer; falling back")
        return fallback_narrative(aggregates, shown), False

    # Indexes are validated against len(shown) before we get here, so this cannot
    # write outside the list.
    for item in analysis.explanations:
        row = finding_rows[item.finding_index]
        row.explanation = item.explanation
        row.llm_severity = item.severity

    return analysis.narrative, True
