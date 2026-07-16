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

    upload: Mapped["Upload"] = relationship(back_populates="findings")


class AnalysisSummary(Base):
    __tablename__ = "analysis_summary"

    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id"), primary_key=True)
    total_entries: Mapped[int] = mapped_column(Integer, default=0)
    flagged_count: Mapped[int] = mapped_column(Integer, default=0)
    timeline_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    top_talkers_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    upload: Mapped["Upload"] = relationship(back_populates="summary")
