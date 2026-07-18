"""Pydantic request/response schemas."""
import json
from datetime import datetime

from pydantic import BaseModel, field_validator, model_validator

from app.attack import finding_attack


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
    narrative: str | None = None

    model_config = {"from_attributes": True}


class AnomalyFindingOut(BaseModel):
    id: int
    entry_id: int | None
    type: str
    confidence: float
    severity: str
    reason: str
    source: str
    # Claude's annotations; null when the LLM layer fell back. `severity` above is
    # always the deterministic engine's, never overwritten.
    explanation: str | None = None
    llm_severity: str | None = None
    # MITRE ATT&CK, derived from `type` on serialization (see app/attack.py).
    # Null for behavioural findings that map to no technique (e.g. off_hours).
    technique_id: str | None = None
    technique_name: str | None = None
    tactic: str | None = None

    model_config = {"from_attributes": True}

    @model_validator(mode="after")
    def _attach_attack(self) -> "AnomalyFindingOut":
        technique = finding_attack(self.type)
        if technique is not None:
            self.technique_id = technique.technique_id
            self.technique_name = technique.technique_name
            self.tactic = technique.tactic
        return self


class TimelineBucketOut(BaseModel):
    start: str
    requests: int
    blocked: int


class TalkerStatOut(BaseModel):
    src_ip: str
    requests: int
    blocked: int
    bytes_recv: int
    bytes_sent: int


class AnomaliesOut(BaseModel):
    """The analysis view: what was found, what it means, and who to believe.

    `llm_ok=False` means `narrative` came from the deterministic fallback and every
    `explanation` is null — the findings themselves are unaffected either way.
    """

    upload_id: int
    llm_ok: bool
    narrative: str | None
    flagged_count: int
    total_entries: int
    findings: list[AnomalyFindingOut]
    timeline: list[TimelineBucketOut]
    top_talkers: list[TalkerStatOut]


class UploadDetail(BaseModel):
    """Full analysis payload for a single upload."""
    upload: UploadOut
    summary: SummaryOut
    entries: list[LogEntryOut]
    findings: list[AnomalyFindingOut]


class IocEnrichmentOut(BaseModel):
    """One VirusTotal verdict for one indicator seen in an upload."""
    id: int
    entry_id: int | None
    indicator_type: str
    indicator: str
    status: str  # ok | not_found | unavailable
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    reputation: int
    threat_labels: list[str] = []
    vt_link: str | None = None

    model_config = {"from_attributes": True}

    @field_validator("threat_labels", mode="before")
    @classmethod
    def _parse_labels(cls, value: object) -> list[str]:
        # Stored as a JSON string column; hand the API a real list.
        if value is None:
            return []
        if isinstance(value, str):
            return json.loads(value) if value else []
        return list(value)  # type: ignore[arg-type]


class EnrichResultOut(BaseModel):
    """Outcome of an enrichment run."""
    indicators_seen: int
    enriched: int
    from_cache: int
    unavailable: int
    alerts: int


class ThreatIntelOut(BaseModel):
    """The Threat Intel tab payload."""
    upload_id: int
    enabled: bool  # whether VirusTotal is configured
    enrichments: list[IocEnrichmentOut]


# --- "Ask Claude" chat -------------------------------------------------------

MAX_CHAT_MESSAGE_LENGTH = 1_000
# Cap the client-supplied transcript so a request cannot carry an unbounded payload;
# the LLM layer additionally replays only its most recent turns.
MAX_CHAT_HISTORY_TURNS = 50


class ChatTurn(BaseModel):
    role: str  # user | assistant
    content: str

    @field_validator("role")
    @classmethod
    def _valid_role(cls, value: str) -> str:
        if value not in ("user", "assistant"):
            raise ValueError("role must be 'user' or 'assistant'")
        return value

    @field_validator("content")
    @classmethod
    def _non_empty_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("content must not be empty")
        return value


class ChatRequest(BaseModel):
    message: str
    history: list[ChatTurn] = []

    @field_validator("message")
    @classmethod
    def _valid_message(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("message must not be empty")
        if len(stripped) > MAX_CHAT_MESSAGE_LENGTH:
            raise ValueError(
                f"message exceeds {MAX_CHAT_MESSAGE_LENGTH} characters"
            )
        return stripped

    @field_validator("history")
    @classmethod
    def _bounded_history(cls, value: list[ChatTurn]) -> list[ChatTurn]:
        if len(value) > MAX_CHAT_HISTORY_TURNS:
            raise ValueError(
                f"history exceeds {MAX_CHAT_HISTORY_TURNS} turns"
            )
        return value


class ChatReply(BaseModel):
    answer: str
