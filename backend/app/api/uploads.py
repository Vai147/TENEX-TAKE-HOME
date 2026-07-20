"""Upload + analysis-retrieval routes (JWT-guarded)."""
import json

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import String, cast, or_
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.aggregates import breakdowns_json
from app.config import get_settings
from app.db import get_db
from app.attack_layer import build_navigator_layer
from app.enrich.service import VtNotConfigured, enrich_upload, get_enrichments
from app.enrich.siem import to_cef_alerts, to_json_alerts
from app.llm import LlmUnavailable, build_chat_context, chat
from app.models import AnalysisSummary, AnomalyFinding, LogEntry, Upload, User
from app.schemas import (
    AnomaliesOut,
    ChatReply,
    ChatRequest,
    EnrichResultOut,
    ThreatIntelOut,
    UploadDetail,
    UploadOut,
)
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
    q: str | None = Query(
        None, max_length=200, description="Filter entries by src IP, user, URL, action, or status."),
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
) -> UploadDetail:
    """One upload's analysis. Entries are paged and optionally filtered by `q`;
    `summary.total_entries` is the true unfiltered total, `entries_total` reflects
    the current filter, and findings are already capped by the detection engine."""
    upload = _owned_upload(db, upload_id, current)

    summary = (
        db.query(AnalysisSummary)
        .filter(AnalysisSummary.upload_id == upload_id)
        .first()
    )

    # Base query for this upload's rows; the optional text search is applied to
    # both the page and its count so pagination stays consistent.
    entry_query = db.query(LogEntry).filter(LogEntry.upload_id == upload_id)
    term = (q or "").strip()
    if term:
        like = f"%{term}%"
        entry_query = entry_query.filter(
            or_(
                LogEntry.src_ip.ilike(like),
                LogEntry.user.ilike(like),
                LogEntry.url.ilike(like),
                LogEntry.action.ilike(like),
                cast(LogEntry.status_code, String).ilike(like),
            )
        )

    entries_total = entry_query.count()
    entries = (
        entry_query.order_by(LogEntry.ts.asc().nullslast(), LogEntry.id.asc())
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
        upload=upload,
        summary=summary,
        entries=entries,
        findings=findings,
        entries_total=entries_total,
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

    if summary and summary.breakdowns_json:
        breakdowns = json.loads(summary.breakdowns_json)
    else:
        # Uploads created before breakdowns_json was introduced have no stored
        # tooltip data. Reconstruct it from the complete upload, rather than
        # making the frontend infer it from only the currently loaded page.
        entries = (
            db.query(LogEntry)
            .filter(LogEntry.upload_id == upload_id)
            .order_by(LogEntry.id.asc())
            .all()
        )
        breakdowns = json.loads(breakdowns_json(entries, findings))

    return AnomaliesOut(
        upload_id=upload.id,
        llm_ok=upload.llm_ok,
        narrative=summary.narrative if summary else None,
        flagged_count=summary.flagged_count if summary else 0,
        total_entries=summary.total_entries if summary else 0,
        findings=findings,
        timeline=json.loads(
            summary.timeline_json) if summary and summary.timeline_json else [],
        top_talkers=(
            json.loads(
                summary.top_talkers_json) if summary and summary.top_talkers_json else []
        ),
        breakdowns=breakdowns,
    )


@router.post("/{upload_id}/enrich", response_model=EnrichResultOut)
def run_enrichment(
    upload_id: int,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
) -> EnrichResultOut:
    """Look up this upload's destination indicators against VirusTotal, store the
    verdicts, and raise `virustotal`-sourced findings for the malicious ones.

    On-demand and idempotent: a re-run replaces the prior results. Returns 503 when
    no VirusTotal key is configured, so the UI can offer the action conditionally.
    """
    upload = _owned_upload(db, upload_id, current)
    try:
        result = enrich_upload(db, upload)
    except VtNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return EnrichResultOut(**result.__dict__)


@router.get("/{upload_id}/threat-intel", response_model=ThreatIntelOut)
def get_threat_intel(
    upload_id: int,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
) -> ThreatIntelOut:
    """Stored VirusTotal enrichments for the Threat Intel tab. `enabled` tells the
    UI whether the enrich action is available at all."""
    _owned_upload(db, upload_id, current)
    return ThreatIntelOut(
        upload_id=upload_id,
        enabled=settings.virustotal_enabled,
        enrichments=get_enrichments(db, upload_id),
    )


@router.post("/{upload_id}/chat", response_model=ChatReply)
def chat_about_upload(
    upload_id: int,
    body: ChatRequest,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
) -> ChatReply:
    """Answer a free-form question about this upload's analysis.

    Grounded in the stored summary, findings and VirusTotal enrichments — the model
    is told to answer only from that context. Multi-turn: the client replays prior
    turns as `history`. Returns 503 when the LLM layer is unavailable (no key or API
    error), so the chat panel degrades gracefully instead of breaking.
    """
    _owned_upload(db, upload_id, current)

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
    context = build_chat_context(
        narrative=summary.narrative if summary else None,
        total_entries=summary.total_entries if summary else 0,
        flagged_count=summary.flagged_count if summary else 0,
        timeline=json.loads(
            summary.timeline_json) if summary and summary.timeline_json else [],
        top_talkers=(
            json.loads(
                summary.top_talkers_json) if summary and summary.top_talkers_json else []
        ),
        findings=findings,
        enrichments=get_enrichments(db, upload_id),
    )
    history = [{"role": turn.role, "content": turn.content}
               for turn in body.history]

    try:
        answer = chat(context, history, body.message)
    except LlmUnavailable as exc:
        raise HTTPException(
            status_code=503, detail=f"Assistant unavailable: {exc}")
    return ChatReply(answer=answer)


@router.get("/{upload_id}/alerts")
def export_alerts(
    upload_id: int,
    format: str = Query("json", pattern="^(json|cef)$"),
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    """SIEM export of the malicious/suspicious indicators — JSON or CEF."""
    _owned_upload(db, upload_id, current)
    rows = get_enrichments(db, upload_id)
    if format == "cef":
        return PlainTextResponse(to_cef_alerts(rows), media_type="text/plain")
    return {"upload_id": upload_id, "alerts": to_json_alerts(rows)}


@router.get("/{upload_id}/attack-layer")
def export_attack_layer(
    upload_id: int,
    db: Session = Depends(get_db),
    current: User = Depends(get_current_user),
):
    """ATT&CK Navigator layer JSON for this upload's findings.

    Downloads as a file the analyst loads into MITRE's Navigator to see the
    matrix light up. Techniques are scored by finding count; unmapped findings
    (e.g. off_hours) are omitted.
    """
    upload = _owned_upload(db, upload_id, current)
    findings = (
        db.query(AnomalyFinding)
        .filter(AnomalyFinding.upload_id == upload_id)
        .order_by(AnomalyFinding.confidence.desc(), AnomalyFinding.id.asc())
        .all()
    )
    layer = build_navigator_layer(upload.filename, upload_id, findings)
    return JSONResponse(
        content=layer,
        headers={
            "Content-Disposition": f'attachment; filename="tenex-attack-{upload_id}.json"'
        },
    )
