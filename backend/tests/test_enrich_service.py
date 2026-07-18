"""Enrichment orchestration against a real (sqlite) session and a fake VT client."""
from __future__ import annotations

import pytest

from app.enrich import service as enrich_service
from app.enrich.verdict import FINDING_SOURCE
from app.enrich.virustotal import VtVerdict
from app.models import AnomalyFinding, IocEnrichment, LogEntry, Upload


class FakeVtClient:
    """Stands in for VirusTotalClient: canned verdicts, counts network calls."""

    verdicts: dict[tuple[str, str], VtVerdict] = {}
    calls: list[tuple[str, str]] = []

    def __init__(self, **_kw):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def lookup(self, indicator_type: str, value: str) -> VtVerdict:
        FakeVtClient.calls.append((indicator_type, value))
        return FakeVtClient.verdicts.get(
            (indicator_type, value),
            VtVerdict(indicator_type=indicator_type, indicator=value, status="ok"),
        )


@pytest.fixture
def vt_enabled(monkeypatch):
    monkeypatch.setattr(enrich_service.settings, "virustotal_api_key", "test-key")
    monkeypatch.setattr(enrich_service, "VirusTotalClient", FakeVtClient)
    FakeVtClient.calls = []
    FakeVtClient.verdicts = {
        ("ip", "185.22.14.9"): VtVerdict(
            indicator_type="ip", indicator="185.22.14.9", status="ok",
            malicious=6, harmless=50, threat_labels=["malware"],
        ),
    }
    yield


def _make_upload(db, user, urls_actions) -> Upload:
    upload = Upload(user_id=user.id, filename="f.csv", stored_path="/tmp/f", status="done")
    db.add(upload)
    db.flush()
    for url, action in urls_actions:
        db.add(LogEntry(upload_id=upload.id, url=url, action=action, raw=""))
    db.commit()
    return upload


def test_enrich_persists_verdicts_and_raises_findings(db_session, analyst, vt_enabled):
    upload = _make_upload(
        db_session,
        analyst,
        [("http://185.22.14.9/admin", "Blocked"), ("https://good.example.com/", "Allowed")],
    )

    result = enrich_service.enrich_upload(db_session, upload)

    enrichments = db_session.query(IocEnrichment).filter_by(upload_id=upload.id).all()
    assert len(enrichments) == result.enriched > 0

    vt_findings = (
        db_session.query(AnomalyFinding)
        .filter_by(upload_id=upload.id, source=FINDING_SOURCE)
        .all()
    )
    # The malicious IP produces exactly one alert finding; the clean domain does not.
    assert result.alerts == 1
    assert len(vt_findings) == 1
    assert vt_findings[0].severity == "critical"  # 6 malicious -> critical band (>=5)
    assert "185.22.14.9" in vt_findings[0].reason


def test_re_enrich_is_idempotent(db_session, analyst, vt_enabled):
    upload = _make_upload(db_session, analyst, [("http://185.22.14.9/x", "Blocked")])

    enrich_service.enrich_upload(db_session, upload)
    first = db_session.query(IocEnrichment).filter_by(upload_id=upload.id).count()
    enrich_service.enrich_upload(db_session, upload)
    second = db_session.query(IocEnrichment).filter_by(upload_id=upload.id).count()

    assert first == second  # replaced, not duplicated
    findings = (
        db_session.query(AnomalyFinding)
        .filter_by(upload_id=upload.id, source=FINDING_SOURCE)
        .count()
    )
    assert findings == 1


def test_second_upload_reuses_cache_and_skips_network(db_session, analyst, vt_enabled):
    up1 = _make_upload(db_session, analyst, [("http://185.22.14.9/x", "Blocked")])
    enrich_service.enrich_upload(db_session, up1)
    calls_after_first = len(FakeVtClient.calls)

    up2 = _make_upload(db_session, analyst, [("http://185.22.14.9/y", "Blocked")])
    result = enrich_service.enrich_upload(db_session, up2)

    # The IP verdict is served from cache; only the new URL indicator hits the network.
    assert result.from_cache >= 1
    ip_calls = [c for c in FakeVtClient.calls if c == ("ip", "185.22.14.9")]
    assert len(ip_calls) == 1  # never looked up the IP a second time
    assert len(FakeVtClient.calls) > calls_after_first - 1


def test_not_configured_raises(db_session, analyst, monkeypatch):
    monkeypatch.setattr(enrich_service.settings, "virustotal_api_key", "")
    upload = _make_upload(db_session, analyst, [("http://185.22.14.9/x", "Blocked")])
    with pytest.raises(enrich_service.VtNotConfigured):
        enrich_service.enrich_upload(db_session, upload)
