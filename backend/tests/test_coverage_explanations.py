"""Cache and grounding contract for Coverage-board explanations."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.auth import get_current_user
from app.db import get_db
from app.main import app
from app.service import process_upload

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


@pytest.fixture
def client(db_session, analyst, monkeypatch):
    monkeypatch.setattr(
        "app.service.analyse",
        lambda aggregates, findings, entries=(): SimpleNamespace(
            narrative="Claude's timeline.",
            explanations=[
                SimpleNamespace(
                    finding_index=index,
                    explanation=f"Because {index}.",
                    severity="high",
                )
                for index in range(len(findings))
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
        db_session,
        analyst.id,
        "a.csv",
        (EXAMPLES / "zscaler_anomalous.csv").read_bytes(),
    )


def test_explanation_is_generated_once_and_returned_from_cache(
    client, upload, monkeypatch
):
    calls = []

    def fake_explain(capability, findings):
        calls.append((capability.technique_id, len(findings)))
        return "Grounded cached explanation.", "ai"

    monkeypatch.setattr("app.api.uploads.explain_coverage", fake_explain)
    path = f"/api/uploads/{upload.id}/coverage-explanations/T1110"

    first = client.post(path)
    second = client.post(path)
    cached = client.get(f"/api/uploads/{upload.id}/coverage-explanations")

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert calls == [("T1110", 1)]
    assert cached.json() == [first.json()]


def test_partial_explanation_receives_no_fabricated_findings(
    client, upload, monkeypatch
):
    seen = {}

    def fake_explain(capability, findings):
        seen["tier"] = capability.tier
        seen["findings"] = list(findings)
        return "Signal exists, but no detector claims it.", "ai"

    monkeypatch.setattr("app.api.uploads.explain_coverage", fake_explain)
    response = client.post(
        f"/api/uploads/{upload.id}/coverage-explanations/T1566"
    )

    assert response.status_code == 200
    assert seen == {"tier": "partial", "findings": []}


def test_none_tier_is_not_explainable_by_ai(client, upload):
    response = client.post(
        f"/api/uploads/{upload.id}/coverage-explanations/T1059"
    )

    assert response.status_code == 404
