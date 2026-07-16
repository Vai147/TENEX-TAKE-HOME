"""Analysis orchestration: save file, parse, persist entries + summary.

Anomaly detection (Phase 4) and the Claude layer (Phase 5) hook in here later.
Kept separate from the HTTP route so the pipeline is testable in isolation.
"""
from __future__ import annotations

import os
import uuid

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AnalysisSummary, LogEntry, Upload
from app.parser import parse_logs

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

    for e in parsed.entries:
        db.add(
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
        )

    db.add(
        AnalysisSummary(
            upload_id=upload.id,
            total_entries=len(parsed.entries),
            flagged_count=0,  # populated in Phase 4
        )
    )

    upload.status = "done"
    db.commit()
    db.refresh(upload)
    return upload