"""HTTP-level tests for the analysis endpoints.

Covers the wiring the service tests cannot see: auth, ownership scoping, and the
JSON contract the frontend will code against.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.auth import get_current_user
from app.db import get_db
from app.main import app
from app.models import User
from app.service import process_upload

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


@pytest.fixture
def client(db_session, analyst, monkeypatch):
    """A TestClient wired to the throwaway session and authenticated as `analyst`."""
    monkeypatch.setattr(
        "app.service.analyse",
        lambda aggregates, findings, entries=(): SimpleNamespace(
            narrative="Claude's timeline.",
            explanations=[
                SimpleNamespace(finding_index=i,
                                explanation=f"Because {i}.", severity="high")
                for i in range(len(findings))
            ],
        ),
    )
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_user] = lambda: analyst
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def upload(db_session, analyst):
    return process_upload(
        db_session, analyst.id, "a.csv", (EXAMPLES /
                                          "zscaler_anomalous.csv").read_bytes()
    )


def test_anomalies_endpoint_returns_the_full_analysis(client, upload):
    body = client.get(f"/api/uploads/{upload.id}/anomalies").json()

    assert body["upload_id"] == upload.id
    assert body["llm_ok"] is True
    assert body["narrative"] == "Claude's timeline."
    assert body["total_entries"] == 20
    assert body["flagged_count"] > 0
    assert body["findings"], "findings must be present"
    assert body["timeline"], "chart data must be present"
    assert body["top_talkers"][0]["src_ip"] == "192.168.9.66"
    assert body["breakdowns"]["hour_ips"]
    assert body["breakdowns"]["talker_dests"]
    assert body["breakdowns"]["detector_ips"]


def test_anomalies_endpoint_includes_breakdowns(client, upload):
    body = client.get(f"/api/uploads/{upload.id}/anomalies").json()

    assert isinstance(body["breakdowns"], dict)
    assert all(key in body["breakdowns"]
               for key in ["hour_ips", "talker_dests", "detector_ips"])
    assert all(isinstance(body["breakdowns"][key], list)
               for key in body["breakdowns"])


def test_anomalies_reconstructs_breakdowns_for_legacy_upload(
    client, db_session, upload
):
    summary = upload.summary
    summary.breakdowns_json = None
    db_session.commit()

    body = client.get(f"/api/uploads/{upload.id}/anomalies").json()

    assert body["breakdowns"]["hour_ips"]
    assert body["breakdowns"]["talker_dests"]
    assert body["breakdowns"]["detector_ips"]


def test_findings_carry_both_verdicts(client, upload):
    finding = client.get(
        f"/api/uploads/{upload.id}/anomalies").json()["findings"][0]

    assert finding["severity"] in {
        "low", "medium", "high", "critical"}  # deterministic
    assert finding["llm_severity"] == "high"  # Claude's opinion, kept separate
    assert finding["explanation"].startswith("Because")
    assert finding["source"] == "deterministic"


def test_findings_are_ranked_worst_first(client, upload):
    findings = client.get(
        f"/api/uploads/{upload.id}/anomalies").json()["findings"]
    confidences = [f["confidence"] for f in findings]

    assert confidences == sorted(confidences, reverse=True)


def test_a_missing_upload_is_404(client):
    assert client.get("/api/uploads/9999/anomalies").status_code == 404


def test_another_users_upload_is_not_readable(client, db_session, upload):
    """Ownership is scoped by user_id, so a valid id from another account still 404s."""
    intruder = User(username="mallory", password_hash="x")
    db_session.add(intruder)
    db_session.commit()
    app.dependency_overrides[get_current_user] = lambda: intruder

    assert client.get(f"/api/uploads/{upload.id}/anomalies").status_code == 404


def test_anomalies_requires_authentication(db_session, upload):
    """Without the auth override the real JWT dependency must reject the request."""
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        response = TestClient(app).get(f"/api/uploads/{upload.id}/anomalies")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 401


def test_entries_endpoint_paginates(client, upload):
    body = client.get(f"/api/uploads/{upload.id}?limit=5").json()

    assert len(body["entries"]) == 5
    assert body["summary"]["total_entries"] == 20, "the true total is still reported"


def test_entry_limit_is_bounded(client, upload):
    assert client.get(
        f"/api/uploads/{upload.id}?limit=99999").status_code == 422


def _haystack(entry: dict) -> str:
    fields = ("src_ip", "user", "url", "action", "status_code")
    return " ".join(str(entry.get(f) or "") for f in fields)


def test_entries_total_reports_full_count_without_q(client, upload):
    body = client.get(f"/api/uploads/{upload.id}?limit=5").json()

    assert len(body["entries"]) == 5
    assert body["entries_total"] == 20, "filtered total defaults to the full count"
    assert body["summary"]["total_entries"] == 20


def test_q_filters_entries_and_total(client, upload):
    full = client.get(f"/api/uploads/{upload.id}?limit=1000").json()
    term = full["entries"][0]["src_ip"]

    body = client.get(f"/api/uploads/{upload.id}",
                      params={"q": term, "limit": 1000}).json()

    assert 0 < body["entries_total"] < 20, "search narrows the set"
    assert len(body["entries"]) == body["entries_total"]
    assert all(term in _haystack(e) for e in body["entries"])
    assert body["summary"]["total_entries"] == 20, "the true total is untouched"


def test_q_is_case_insensitive(client, upload):
    full = client.get(f"/api/uploads/{upload.id}?limit=1000").json()
    user = next(e["user"] for e in full["entries"] if e["user"])

    lower = client.get(
        f"/api/uploads/{upload.id}", params={"q": user.lower()}).json()
    upper = client.get(
        f"/api/uploads/{upload.id}", params={"q": user.upper()}).json()

    assert lower["entries_total"] == upper["entries_total"] > 0


def test_q_with_no_match_is_empty(client, upload):
    body = client.get(f"/api/uploads/{upload.id}",
                      params={"q": "zzq-no-such-term"}).json()

    assert body["entries_total"] == 0
    assert body["entries"] == []
