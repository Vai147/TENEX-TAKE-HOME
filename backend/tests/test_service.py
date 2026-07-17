"""Integration tests for the ingest pipeline against a real database session.

The detector unit tests deliberately avoid the DB; these cover the seam the unit
tests cannot see — that ids exist when findings reference them, that findings and
summary rows actually persist, and that the summary's counts are true.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.detectors.engine import MAX_FINDINGS
from app.models import AnalysisSummary, AnomalyFinding, LogEntry
from app.service import process_upload

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
HEADER = "timestamp,user,src_ip,url,action,status,bytes_sent,bytes_recv,user_agent"


def _example(name: str) -> bytes:
    return (EXAMPLES / name).read_bytes()


def _summary(db, upload_id: int) -> AnalysisSummary:
    return db.query(AnalysisSummary).filter_by(upload_id=upload_id).one()


def _findings(db, upload_id: int) -> list[AnomalyFinding]:
    return db.query(AnomalyFinding).filter_by(upload_id=upload_id).all()


def test_process_upload_persists_entries_findings_and_summary(db_session, analyst):
    upload = process_upload(db_session, analyst.id, "a.csv", _example("zscaler_anomalous.csv"))

    entries = db_session.query(LogEntry).filter_by(upload_id=upload.id).all()
    findings = _findings(db_session, upload.id)

    assert upload.status == "done"
    assert len(entries) == 20
    assert findings, "anomalous example must produce findings"
    assert _summary(db_session, upload.id).total_entries == 20


def test_findings_reference_real_persisted_entries(db_session, analyst):
    """Pins the `db.flush()` before detection: without it, entry_id would be None."""
    upload = process_upload(db_session, analyst.id, "a.csv", _example("zscaler_anomalous.csv"))

    entry_ids = {e.id for e in db_session.query(LogEntry).filter_by(upload_id=upload.id)}
    findings = _findings(db_session, upload.id)

    assert all(f.entry_id is not None for f in findings)
    assert {f.entry_id for f in findings} <= entry_ids


def test_clean_example_persists_no_findings(db_session, analyst):
    upload = process_upload(db_session, analyst.id, "c.csv", _example("zscaler_clean.csv"))

    assert _findings(db_session, upload.id) == []
    assert _summary(db_session, upload.id).flagged_count == 0


def test_flagged_count_counts_distinct_entries_not_findings(db_session, analyst):
    upload = process_upload(db_session, analyst.id, "a.csv", _example("zscaler_anomalous.csv"))

    findings = _findings(db_session, upload.id)
    summary = _summary(db_session, upload.id)

    # The attacker's rows each trip several detectors, so findings outnumber entries.
    assert len(findings) > summary.flagged_count
    assert summary.flagged_count == len({f.entry_id for f in findings})


def test_flagged_count_is_not_capped_by_the_display_limit(db_session, analyst):
    """A big incident must not be under-reported just because the UI shows 50.

    Regression test: the count used to be derived from the already-truncated
    findings list, so a 60-IP scan reported exactly 50 flagged entries.
    """
    ip_count = MAX_FINDINGS + 10
    rows = [HEADER]
    for n in range(ip_count):
        # Each IP independently trips ip_burst: 6 requests inside one second.
        for second in range(6):
            rows.append(
                f"2026-07-14T09:00:{second:02d}Z,u,10.9.{n // 256}.{n % 256},"
                f"https://x.com,Allowed,200,500,50000,Chrome/126.0"
            )
    raw = "\n".join(rows).encode()

    upload = process_upload(db_session, analyst.id, "big.csv", raw)
    summary = _summary(db_session, upload.id)

    assert len(_findings(db_session, upload.id)) == MAX_FINDINGS, "display cap still applies"
    assert summary.flagged_count == ip_count, "but the summary reports the whole incident"


def test_a_file_with_a_utf8_bom_still_detects_time_based_anomalies(db_session, analyst):
    """Excel's "CSV UTF-8" export prefixes a BOM; it must not mute the detectors."""
    plain = _example("zscaler_anomalous.csv")
    with_bom = b"\xef\xbb\xbf" + plain

    upload = process_upload(db_session, analyst.id, "bom.csv", with_bom)

    entries = db_session.query(LogEntry).filter_by(upload_id=upload.id).all()
    types = {f.type for f in _findings(db_session, upload.id)}

    assert all(e.ts is not None for e in entries), "BOM must not break timestamp parsing"
    assert {"ip_burst", "off_hours"} <= types


def test_unrecognized_format_raises_before_persisting_anything(db_session, analyst):
    with pytest.raises(ValueError):
        process_upload(db_session, analyst.id, "junk.csv", b"foo,bar,baz\n1,2,3")

    db_session.rollback()
    assert db_session.query(LogEntry).count() == 0


def test_a_detector_blowing_up_does_not_fail_the_upload(db_session, analyst, monkeypatch):
    """Detection is best-effort: entries parsed fine, so the upload must survive."""
    import app.detectors.engine as engine

    def exploding_detector(entries):
        raise RuntimeError("detector bug")

    monkeypatch.setattr(engine, "DETECTORS", (exploding_detector, *engine.DETECTORS))

    upload = process_upload(db_session, analyst.id, "a.csv", _example("zscaler_anomalous.csv"))

    assert upload.status == "done"
    # The surviving detectors still did their job.
    assert _findings(db_session, upload.id)