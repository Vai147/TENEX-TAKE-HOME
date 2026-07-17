"""Shared test fixtures."""
from __future__ import annotations

import os
import tempfile

# Point the app at throwaway storage before `app.config` is imported anywhere: the
# settings object is lru_cached at first use, and app.db builds its engine from it
# at import time. Tests must never touch the real Postgres or upload volume.
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ.setdefault("UPLOAD_DIR", tempfile.mkdtemp(prefix="tenex-test-uploads-"))

from dataclasses import dataclass  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402
from itertools import count  # noqa: E402

import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

_ids = count(1)

BUSINESS_HOURS_START = datetime(2026, 7, 14, 9, 0, tzinfo=timezone.utc)  # a Tuesday


@dataclass
class StubEntry:
    """Minimal stand-in for `LogEntry`, satisfying the `EntryLike` protocol.

    Detectors only read attributes, so tests never need a database.
    """

    id: int | None = None
    ts: datetime | None = None
    src_ip: str | None = "10.0.0.1"
    user: str | None = "alice@corp.com"
    url: str | None = "https://example.com"
    action: str | None = "Allowed"
    status_code: int | None = 200
    bytes_sent: int | None = 500
    bytes_recv: int | None = 50_000
    user_agent: str | None = "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0"


def entry(**overrides) -> StubEntry:
    """Build one entry: business-hours and unremarkable unless overridden."""
    fields = {"id": next(_ids), "ts": BUSINESS_HOURS_START, **overrides}
    return StubEntry(**fields)


def entries_at(offsets_seconds: list[int], base: datetime | None = None, **overrides):
    """Build entries spaced by second offsets from `base`."""
    start = base or BUSINESS_HOURS_START
    return [
        entry(ts=start + timedelta(seconds=offset), **overrides)
        for offset in offsets_seconds
    ]


@pytest.fixture
def db_session():
    """A real SQLAlchemy session on throwaway sqlite, with the schema created.

    Exercises the actual ORM plumbing — flush-assigns-ids, cascades, column types —
    rather than mocking it, which is the whole point of these tests.
    """
    from app.db import Base
    from app.models import User  # noqa: F401  (registers the mapper before create_all)

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        # One shared in-memory DB for the whole session, not one per connection.
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def analyst(db_session):
    """A persisted user to own uploads."""
    from app.models import User

    user = User(username="analyst", password_hash="not-a-real-hash")
    db_session.add(user)
    db_session.commit()
    return user
