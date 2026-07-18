"""ATT&CK Navigator layer builder + its export endpoint."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.attack_layer import (
    ATTACK_VERSION,
    DOMAIN,
    LAYER_VERSION,
    build_navigator_layer,
)
from app.auth import get_current_user
from app.db import get_db
from app.main import app
from app.models import User
from app.service import process_upload

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


def _finding(type_: str, severity: str = "high"):
    return SimpleNamespace(type=type_, severity=severity)


# --- builder ------------------------------------------------------------------


def test_layer_has_valid_envelope():
    layer = build_navigator_layer("a.csv", 3, [_finding("ip_burst")])

    assert layer["domain"] == DOMAIN
    assert layer["versions"] == {
        "attack": ATTACK_VERSION,
        "navigator": layer["versions"]["navigator"],
        "layer": LAYER_VERSION,
    }
    assert layer["name"] == "Tenex — a.csv (#3)"
    assert layer["gradient"]["colors"][0] == "#ffffff"


def test_score_is_finding_count_per_technique():
    findings = [
        _finding("blocked_spike"),
        _finding("blocked_spike"),
        _finding("blocked_spike"),
        _finding("ip_burst"),
    ]
    layer = build_navigator_layer("a.csv", 1, findings)
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}

    assert by_id["T1595"]["score"] == 3  # blocked_spike ×3
    assert by_id["T1110"]["score"] == 1  # ip_burst ×1
    assert layer["gradient"]["maxValue"] == 3


def test_unmapped_findings_are_omitted():
    layer = build_navigator_layer("a.csv", 1, [_finding("off_hours")])
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1  # never zero, so the gradient is valid


def test_cell_reports_its_worst_severity():
    findings = [_finding("byte_volume", "medium"), _finding("byte_volume", "critical")]
    layer = build_navigator_layer("a.csv", 1, findings)
    cell = layer["techniques"][0]

    meta = {m["name"]: m["value"] for m in cell["metadata"]}
    assert meta["max_severity"] == "critical"
    assert meta["findings"] == "2"


# --- endpoint -----------------------------------------------------------------


@pytest.fixture
def client(db_session, analyst, monkeypatch):
    monkeypatch.setattr(
        "app.service.analyse",
        lambda aggregates, findings, entries=(): SimpleNamespace(
            narrative="n.",
            explanations=[
                SimpleNamespace(finding_index=i, explanation="x", severity="high")
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
        db_session, analyst.id, "a.csv", (EXAMPLES / "zscaler_anomalous.csv").read_bytes()
    )


def test_endpoint_returns_a_downloadable_layer(client, upload):
    res = client.get(f"/api/uploads/{upload.id}/attack-layer")

    assert res.status_code == 200
    assert "attachment" in res.headers["content-disposition"]
    assert f"tenex-attack-{upload.id}.json" in res.headers["content-disposition"]
    body = res.json()
    assert body["domain"] == DOMAIN
    assert body["techniques"], "the anomalous sample maps to techniques"


def test_endpoint_scopes_by_owner(client, db_session, upload):
    intruder = User(username="mallory", password_hash="x")
    db_session.add(intruder)
    db_session.commit()
    app.dependency_overrides[get_current_user] = lambda: intruder

    assert client.get(f"/api/uploads/{upload.id}/attack-layer").status_code == 404


def test_endpoint_requires_auth(db_session, upload):
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        res = TestClient(app).get(f"/api/uploads/{upload.id}/attack-layer")
    finally:
        app.dependency_overrides.clear()
    assert res.status_code == 401
