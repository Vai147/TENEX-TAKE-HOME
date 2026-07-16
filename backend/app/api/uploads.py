"""Upload + analysis-retrieval routes (JWT-guarded)."""
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.config import get_settings
from app.db import get_db
from app.models import AnalysisSummary, LogEntry, Upload, User
from app.schemas import UploadDetail, UploadOut
from app.service import process_upload

settings = get_settings()
router = APIRouter(prefix="/api/uploads", tags=["uploads"])

ALLOWED_EXT = {".log", ".txt", ".csv"}


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


@router.get("/{upload_id}", response_model=UploadDetail)
def get_upload(
    upload_id: int,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
) -> UploadDetail:
    upload = (
        db.query(Upload)
        .filter(Upload.id == upload_id, Upload.user_id == current.id)
        .first()
    )
    if upload is None:
        raise HTTPException(status_code=404, detail="Upload not found")

    summary = (
        db.query(AnalysisSummary)
        .filter(AnalysisSummary.upload_id == upload_id)
        .first()
    )
    entries = (
        db.query(LogEntry)
        .filter(LogEntry.upload_id == upload_id)
        .order_by(LogEntry.ts.asc().nullslast(), LogEntry.id.asc())
        .all()
    )

    return UploadDetail(upload=upload, summary=summary, entries=entries)