"""Pydantic request/response schemas."""
from datetime import datetime

from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    username: str

    model_config = {"from_attributes": True}


class UploadOut(BaseModel):
    """Summary row returned right after an upload / in list views."""
    id: int
    filename: str
    status: str
    llm_ok: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class LogEntryOut(BaseModel):
    id: int
    ts: datetime | None
    src_ip: str | None
    user: str | None
    url: str | None
    action: str | None
    status_code: int | None
    bytes_sent: int | None
    bytes_recv: int | None
    user_agent: str | None

    model_config = {"from_attributes": True}


class SummaryOut(BaseModel):
    total_entries: int
    flagged_count: int

    model_config = {"from_attributes": True}


class AnomalyFindingOut(BaseModel):
    id: int
    entry_id: int | None
    type: str
    confidence: float
    severity: str
    reason: str
    source: str

    model_config = {"from_attributes": True}


class UploadDetail(BaseModel):
    """Full analysis payload for a single upload."""
    upload: UploadOut
    summary: SummaryOut
    entries: list[LogEntryOut]
    findings: list[AnomalyFindingOut]
