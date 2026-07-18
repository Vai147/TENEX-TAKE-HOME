"""Verdict → severity / alertability / finding mapping."""
from __future__ import annotations

import pytest

from app.enrich.verdict import confidence_for, is_alertable, severity_for, to_finding
from app.enrich.virustotal import VtVerdict


def verdict(**kw) -> VtVerdict:
    base = dict(indicator_type="domain", indicator="x.example.com", status="ok")
    base.update(kw)
    return VtVerdict(**base)


@pytest.mark.parametrize(
    "malicious,expected",
    [(0, "low"), (1, "medium"), (2, "medium"), (3, "high"), (5, "critical"), (12, "critical")],
)
def test_severity_bands(malicious, expected):
    assert severity_for(verdict(malicious=malicious)) == expected


def test_not_alertable_when_status_not_ok():
    assert is_alertable(verdict(status="unavailable", malicious=9), 1) is False


def test_alertable_at_or_above_min_malicious():
    assert is_alertable(verdict(malicious=1), 1) is True
    assert is_alertable(verdict(malicious=0, suspicious=0), 1) is False


def test_alertable_when_suspicious_plus_one_malicious():
    assert is_alertable(verdict(malicious=1, suspicious=2), 3) is True


def test_confidence_rises_with_detections_and_is_bounded():
    assert confidence_for(verdict(malicious=0)) == pytest.approx(0.5)
    assert confidence_for(verdict(malicious=100)) <= 0.99


def test_finding_reason_is_plain_text_and_names_the_indicator():
    v = verdict(indicator="evil.example.com", malicious=7, suspicious=1, threat_labels=["trojan"])
    fields = to_finding(v, entry_id=42)
    assert fields.type == "threat_intel"
    assert fields.source == "virustotal"
    assert fields.severity == "critical"
    assert fields.entry_id == 42
    assert "evil.example.com" in fields.reason
    assert "7 malicious" in fields.reason
    assert "trojan" in fields.reason
    assert "<" not in fields.reason  # plain text, no markup
