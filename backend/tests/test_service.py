"""Integration tests for the ingest pipeline against a real database session.

The detector unit tests deliberately avoid the DB; these cover the seam the unit
tests cannot see — that ids exist when findings reference them, that findings and
summary rows actually persist, and that the summary's counts are true.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.detectors.engine import MAX_FINDINGS
from app.llm import LlmUnavailable
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


# --- the Claude layer, from the pipeline's side --------------------------------


def _fake_analysis(explanations):
    return SimpleNamespace(
        narrative="Claude's timeline of the incident.", explanations=explanations
    )


def test_a_successful_analysis_annotates_findings_and_sets_llm_ok(
    db_session, analyst, monkeypatch
):
    def fake_analyse(aggregates, findings, entries=()):
        return _fake_analysis(
            [
                SimpleNamespace(finding_index=i, explanation=f"Because {i}.", severity="high")
                for i in range(len(findings))
            ]
        )

    monkeypatch.setattr("app.service.analyse", fake_analyse)

    upload = process_upload(db_session, analyst.id, "a.csv", _example("zscaler_anomalous.csv"))
    findings = _findings(db_session, upload.id)

    assert upload.llm_ok is True
    assert _summary(db_session, upload.id).narrative == "Claude's timeline of the incident."
    assert all(f.explanation is not None for f in findings)
    assert all(f.llm_severity == "high" for f in findings)


def test_claude_annotations_never_overwrite_the_deterministic_verdict(
    db_session, analyst, monkeypatch
):
    """The engine's severity is the auditable one; the model only adds an opinion."""

    def contrarian_analyse(aggregates, findings, entries=()):
        return _fake_analysis(
            [
                SimpleNamespace(finding_index=i, explanation="Harmless.", severity="low")
                for i in range(len(findings))
            ]
        )

    monkeypatch.setattr("app.service.analyse", contrarian_analyse)

    upload = process_upload(db_session, analyst.id, "a.csv", _example("zscaler_anomalous.csv"))
    findings = _findings(db_session, upload.id)
    top = max(findings, key=lambda f: f.confidence)

    assert top.severity == "critical", "deterministic severity survives disagreement"
    assert top.llm_severity == "low", "and the model's dissent is recorded alongside"


def test_an_unavailable_llm_falls_back_without_failing_the_upload(
    db_session, analyst, monkeypatch
):
    def unavailable(aggregates, findings, entries=()):
        raise LlmUnavailable("no key")

    monkeypatch.setattr("app.service.analyse", unavailable)

    upload = process_upload(db_session, analyst.id, "a.csv", _example("zscaler_anomalous.csv"))
    summary = _summary(db_session, upload.id)

    assert upload.status == "done"
    assert upload.llm_ok is False
    assert summary.narrative, "the fallback still writes a real narrative"
    assert all(f.explanation is None for f in _findings(db_session, upload.id))


def test_an_unexpected_llm_crash_still_falls_back(db_session, analyst, monkeypatch):
    """A bug in our own plumbing must not cost the user their upload."""

    def exploding(aggregates, findings, entries=()):
        raise TypeError("bug in the llm layer")

    monkeypatch.setattr("app.service.analyse", exploding)

    upload = process_upload(db_session, analyst.id, "a.csv", _example("zscaler_anomalous.csv"))

    assert upload.status == "done"
    assert upload.llm_ok is False
    assert _findings(db_session, upload.id), "findings are unaffected by LLM failure"


def test_aggregates_are_persisted_for_the_charts(db_session, analyst, monkeypatch):
    monkeypatch.setattr("app.service.analyse", lambda a, f, e=(): _fake_analysis([]))

    upload = process_upload(db_session, analyst.id, "a.csv", _example("zscaler_anomalous.csv"))
    summary = _summary(db_session, upload.id)

    timeline = json.loads(summary.timeline_json)
    talkers = json.loads(summary.top_talkers_json)

    assert sum(b["requests"] for b in timeline) == 20
    assert talkers[0]["src_ip"] == "192.168.9.66"