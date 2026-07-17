"""Upload + analysis-retrieval routes (JWT-guarded)."""
import json

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.config import get_settings
from app.db import get_db
from app.models import AnalysisSummary, AnomalyFinding, LogEntry, Upload, User
from app.schemas import AnomaliesOut, UploadDetail, UploadOut
from app.service import process_upload

settings = get_settings()
router = APIRouter(prefix="/api/uploads", tags=["uploads"])

ALLOWED_EXT = {".log", ".txt", ".csv"}

# A 10 MB upload is tens of thousands of rows; serializing them all into one JSON
# response is a self-inflicted outage waiting on the upload cap being raised.
DEFAULT_ENTRY_LIMIT = 500
MAX_ENTRY_LIMIT = 5_000


@router.post("", response_model=UploadOut, status_code=status.HTTP_201_CREATED)
async def create_upload(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
) -> Upload:
    filename = file.filename or "upload"
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type '{ext}'. Allowed: {sorted(ALLOWED_EXT)}",
        )

    raw = await file.read()
    if len(raw) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(raw) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {settings.max_upload_bytes} bytes",
        )

    try:
        upload = process_upload(db, current.id, filename, raw)
    except ValueError as exc:  # unrecognized log format from parser
        raise HTTPException(status_code=422, detail=str(exc))

    return upload


@router.get("", response_model=list[UploadOut])
def list_uploads(
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
) -> list[Upload]:
    return (
        db.query(Upload)
        .filter(Upload.user_id == current.id)
        .order_by(Upload.created_at.desc())
        .all()
    )


def _owned_upload(db: Session, upload_id: int, current: User) -> Upload:
    """Fetch an upload the caller owns, or 404.

    Scoped by user_id, not just id: without it any authenticated user could read
    anyone's logs by guessing a number. 404 rather than 403 so the endpoint does not
    confirm that someone else's upload exists.
    """
    upload = (
        db.query(Upload)
        .filter(Upload.id == upload_id, Upload.user_id == current.id)
        .first()
    )
    if upload is None:
        raise HTTPException(status_code=404, detail="Upload not found")
    return upload


@router.get("/{upload_id}", response_model=UploadDetail)
def get_upload(
    upload_id: int,
    limit: int = Query(DEFAULT_ENTRY_LIMIT, ge=1, le=MAX_ENTRY_LIMIT),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
) -> UploadDetail:
    """One upload's analysis. Entries are paged; `summary.total_entries` is the true
    total, and findings are already capped by the detection engine."""
    upload = _owned_upload(db, upload_id, current)

    summary = (
        db.query(AnalysisSummary)
        .filter(AnalysisSummary.upload_id == upload_id)
        .first()
    )
    entries = (
        db.query(LogEntry)
        .filter(LogEntry.upload_id == upload_id)
        .order_by(LogEntry.ts.asc().nullslast(), LogEntry.id.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    findings = (
        db.query(AnomalyFinding)
        .filter(AnomalyFinding.upload_id == upload_id)
        .order_by(AnomalyFinding.confidence.desc(), AnomalyFinding.id.asc())
        .all()
    )

    return UploadDetail(
        upload=upload, summary=summary, entries=entries, findings=findings
    )


@router.get("/{upload_id}/anomalies", response_model=AnomaliesOut)
def get_anomalies(
    upload_id: int,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
) -> AnomaliesOut:
    """The analysis view: findings, Claude's narrative, and the chart aggregates.

    Separate from `GET /{upload_id}` because it is small and bounded — a client can
    poll or re-render this without dragging the whole entries table along.
    """
    upload = _owned_upload(db, upload_id, current)

    summary = (
        db.query(AnalysisSummary)
        .filter(AnalysisSummary.upload_id == upload_id)
        .first()
    )
    findings = (
        db.query(AnomalyFinding)
        .filter(AnomalyFinding.upload_id == upload_id)
        .order_by(AnomalyFinding.confidence.desc(), AnomalyFinding.id.asc())
        .all()
    )

    return AnomaliesOut(
        upload_id=upload.id,
        llm_ok=upload.llm_ok,
        narrative=summary.narrative if summary else None,
        flagged_count=summary.flagged_count if summary else 0,
        total_entries=summary.total_entries if summary else 0,
        findings=findings,
        timeline=json.loads(summary.timeline_json) if summary and summary.timeline_json else [],
        top_talkers=(
            json.loads(summary.top_talkers_json) if summary and summary.top_talkers_json else []
        ),
    )
