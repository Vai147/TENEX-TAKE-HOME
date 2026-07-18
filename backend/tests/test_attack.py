"""MITRE ATT&CK mapping + its surfacing on the findings schema."""
from __future__ import annotations

import pytest

from app.attack import THREAT_INTEL_ATTACK, finding_attack
from app.schemas import AnomalyFindingOut


@pytest.mark.parametrize(
    "finding_type, technique_id, tactic",
    [
        ("blocked_spike", "T1595", "Reconnaissance"),
        ("rare_user_agent", "T1190", "Initial Access"),
        ("ip_burst", "T1110", "Credential Access"),
        ("threat_intel", "T1071", "Command and Control"),
        ("byte_volume", "T1048", "Exfiltration"),
    ],
)
def test_each_finding_type_maps_to_its_technique(finding_type, technique_id, tactic):
    technique = finding_attack(finding_type)
    assert technique is not None
    assert technique.technique_id == technique_id
    assert technique.tactic == tactic


def test_off_hours_is_intentionally_unmapped():
    assert finding_attack("off_hours") is None


def test_unknown_type_is_unmapped():
    assert finding_attack("does_not_exist") is None


def test_threat_intel_constant_is_command_and_control():
    assert THREAT_INTEL_ATTACK.technique_id == "T1071"
    assert THREAT_INTEL_ATTACK.tactic_id == "TA0011"


def _finding(**kw) -> dict:
    base = dict(
        id=1, entry_id=5, type="ip_burst", confidence=0.9, severity="critical",
        reason="burst", source="deterministic",
    )
    base.update(kw)
    return base


def test_schema_attaches_attack_fields_from_type():
    out = AnomalyFindingOut.model_validate(_finding(type="byte_volume"))
    assert out.technique_id == "T1048"
    assert out.technique_name == "Exfiltration Over Alternative Protocol"
    assert out.tactic == "Exfiltration"


def test_schema_leaves_attack_null_for_unmapped_finding():
    out = AnomalyFindingOut.model_validate(_finding(type="off_hours"))
    assert out.technique_id is None
    assert out.technique_name is None
    assert out.tactic is None
