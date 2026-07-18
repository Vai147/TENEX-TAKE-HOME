"""SIEM export formatting (JSON + CEF)."""
from __future__ import annotations

import json

from app.enrich.siem import to_cef_alerts, to_json_alerts
from app.models import IocEnrichment


def row(**kw) -> IocEnrichment:
    base = dict(
        upload_id=1,
        entry_id=7,
        indicator_type="domain",
        indicator="evil.example.com",
        status="ok",
        malicious=8,
        suspicious=1,
        harmless=60,
        undetected=5,
        reputation=-42,
        threat_labels=json.dumps(["trojan.generic"]),
        vt_link="https://www.virustotal.com/gui/domain/evil.example.com",
    )
    base.update(kw)
    return IocEnrichment(**base)


def test_json_export_includes_only_alerts():
    rows = [row(), row(indicator="clean.example.com", malicious=0, suspicious=0)]
    alerts = to_json_alerts(rows)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["indicator"] == "evil.example.com"
    assert alert["severity"] == "critical"
    assert alert["detections"]["malicious"] == 8
    assert alert["threat_labels"] == ["trojan.generic"]
    assert alert["source_entry_id"] == 7


def test_json_export_skips_unavailable():
    assert to_json_alerts([row(status="unavailable", malicious=9)]) == []


def test_json_alert_carries_attack_technique():
    alert = to_json_alerts([row()])[0]
    assert alert["attack"] == {
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
    }


def test_cef_line_shape_and_severity():
    cef = to_cef_alerts([row()])
    assert cef.startswith("CEF:0|Tenex|Console|1.0|vt-domain|")
    assert "|10|" in cef  # critical -> CEF severity 10
    assert "destinationDnsDomain=evil.example.com" in cef
    assert "cn1=8" in cef


def test_cef_empty_when_no_alerts():
    assert to_cef_alerts([row(malicious=0, suspicious=0)]) == ""


def test_cef_carries_attack_technique():
    cef = to_cef_alerts([row()])
    assert "cs2Label=mitreTechnique" in cef
    assert "cs2=T1071 Application Layer Protocol" in cef
    assert "cs3Label=mitreTactic" in cef
    assert "cs3=Command and Control" in cef
