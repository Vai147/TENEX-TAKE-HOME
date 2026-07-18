"""SQLAlchemy ORM models."""
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Upload(Base):
    __tablename__ = "uploads"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(32), default="processing")
    llm_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    entries: Mapped[list["LogEntry"]] = relationship(back_populates="upload", cascade="all, delete-orphan")
    findings: Mapped[list["AnomalyFinding"]] = relationship(back_populates="upload", cascade="all, delete-orphan")
    summary: Mapped["AnalysisSummary"] = relationship(back_populates="upload", uselist=False, cascade="all, delete-orphan")


class LogEntry(Base):
    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id"), index=True)
    ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_sent: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_recv: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw: Mapped[str] = mapped_column(Text)

    upload: Mapped["Upload"] = relationship(back_populates="entries")


class AnomalyFinding(Base):
    __tablename__ = "anomaly_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id"), index=True)
    entry_id: Mapped[int | None] = mapped_column(ForeignKey("log_entries.id"), nullable=True)
    type: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(16))  # deterministic | llm

    # Claude's annotations. Deliberately additive: `severity` and `reason` above stay
    # exactly as the deterministic engine computed them, so a finding remains
    # reproducible and auditable even when the model is wrong, unavailable, or
    # disagrees. The LLM enriches the record; it never edits or authors it.
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)

    upload: Mapped["Upload"] = relationship(back_populates="findings")


class IocEnrichment(Base):
    """One VirusTotal verdict for one indicator (URL / domain / IP) seen in an upload.

    Doubles as the network cache: before calling VirusTotal for an indicator, the
    service looks for a recent row with the same `indicator_type` + `indicator`
    (across any upload) and reuses it, so repeat destinations never re-spend the
    free-tier quota. `status` records how the lookup went so a VT outage is
    distinguishable from a genuinely unknown indicator — never overwritten as a
    clean verdict.
    """

    __tablename__ = "ioc_enrichments"

    id: Mapped[int] = mapped_column(primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id"), index=True)
    # A representative entry the indicator came from, for cross-linking in the UI.
    entry_id: Mapped[int | None] = mapped_column(ForeignKey("log_entries.id"), nullable=True)

    indicator_type: Mapped[str] = mapped_column(String(16))  # url | domain | ip
    indicator: Mapped[str] = mapped_column(Text, index=True)

    # ok | unavailable | not_found — see docstring.
    status: Mapped[str] = mapped_column(String(16), default="ok")

    malicious: Mapped[int] = mapped_column(Integer, default=0)
    suspicious: Mapped[int] = mapped_column(Integer, default=0)
    harmless: Mapped[int] = mapped_column(Integer, default=0)
    undetected: Mapped[int] = mapped_column(Integer, default=0)
    reputation: Mapped[int] = mapped_column(Integer, default=0)
    # JSON-encoded list[str] of popular threat classification labels.
    threat_labels: Mapped[str | None] = mapped_column(Text, nullable=True)
    vt_link: Mapped[str | None] = mapped_column(String(512), nullable=True)

    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AnalysisSummary(Base):
    __tablename__ = "analysis_summary"

    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id"), primary_key=True)
    total_entries: Mapped[int] = mapped_column(Integer, default=0)
    flagged_count: Mapped[int] = mapped_column(Integer, default=0)
    timeline_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    top_talkers_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    # SOC timeline narrative. Written by Claude when the analysis succeeds, and by
    # the deterministic fallback when it does not — `Upload.llm_ok` says which.
    narrative: Mapped[str | None] = mapped_column(Text, nullable=True)

    upload: Mapped["Upload"] = relationship(back_populates="summary")
