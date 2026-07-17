"""End-to-end checks against the shipped example logs.

These are the files a reviewer will actually upload, so they are worth asserting
on directly: the clean one must stay quiet, and the anomalous one must surface
every scenario it was built to contain.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from tests.conftest import StubEntry

from app.detectors import run_detectors
from app.parser import parse_logs

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
ATTACKER_IP = "192.168.9.66"


def _findings_for(filename: str):
    parsed = parse_logs((EXAMPLES / filename).read_text())
    # Detectors key findings to entry ids; the parser has no DB, so stand in for one.
    entries = [
        StubEntry(
            id=index,
            ts=e.ts,
            src_ip=e.src_ip,
            user=e.user,
            url=e.url,
            action=e.action,
            status_code=e.status_code,
            bytes_sent=e.bytes_sent,
            bytes_recv=e.bytes_recv,
            user_agent=e.user_agent,
        )
        for index, e in enumerate(parsed.entries)
    ]
    return entries, run_detectors(entries)


def test_clean_example_produces_no_findings():
    _, findings = _findings_for("zscaler_clean.csv")

    assert findings == [], f"false positives on clean traffic: {[f.reason for f in findings]}"


@pytest.mark.parametrize(
    "detector_type",
    ["ip_burst", "blocked_spike", "rare_user_agent", "byte_volume", "off_hours"],
)
def test_anomalous_example_triggers_every_detector(detector_type):
    _, findings = _findings_for("zscaler_anomalous.csv")

    assert any(f.type == detector_type for f in findings)


def test_anomalous_example_ranks_the_attacker_first():
    entries, findings = _findings_for("zscaler_anomalous.csv")
    by_id = {e.id: e for e in entries}
    top = findings[0]

    assert top.severity == "critical"
    assert by_id[top.entry_id].src_ip == ATTACKER_IP


def test_anomalous_example_flags_the_data_dump_rows():
    entries, findings = _findings_for("zscaler_anomalous.csv")
    by_id = {e.id: e for e in entries}
    flagged_urls = {
        by_id[f.entry_id].url for f in findings if f.type == "byte_volume"
    }

    assert flagged_urls == {
        "https://internal.corp.com/api/users/export",
        "https://internal.corp.com/api/db/dump",
    }


def test_anomalous_example_leaves_normal_users_alone():
    entries, findings = _findings_for("zscaler_anomalous.csv")
    by_id = {e.id: e for e in entries}
    flagged_ips = {by_id[f.entry_id].src_ip for f in findings if f.entry_id is not None}

    # bob trips the C2 beacon block spike; alice, carol, dave and eve are clean.
    assert flagged_ips == {ATTACKER_IP, "10.0.4.22"}
