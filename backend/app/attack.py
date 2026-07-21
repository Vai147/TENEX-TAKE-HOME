"""MITRE ATT&CK mapping for findings — the single source of truth.

A finding's `type` (which detector, or `threat_intel` for a VirusTotal hit) maps
to exactly one ATT&CK technique. The mapping is fixed domain knowledge, not
anything computed from the log data, so it lives in one small lookup table that
both the API serializer and the SIEM export read. Keeping it here — rather than in
the frontend — means the ATT&CK codes are part of the data contract: they flow
into the JSON/CEF alert exports so a downstream SOAR can pivot and trigger
playbooks on the T-code.

`off_hours` is deliberately unmapped: activity outside business hours is a
behavioural time signal that corroborates other findings, not an ATT&CK technique
in its own right. It returns `None` and renders as "behavioural / unmapped".
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackTechnique:
    tactic: str
    tactic_id: str
    technique_id: str
    technique_name: str


# finding.type -> the ATT&CK technique it evidences.
_FINDING_ATTACK: dict[str, AttackTechnique] = {
    "blocked_spike": AttackTechnique(
        "Reconnaissance", "TA0043", "T1595", "Active Scanning"
    ),
    "rare_user_agent": AttackTechnique(
        "Initial Access", "TA0001", "T1190", "Exploit Public-Facing Application"
    ),
    "ip_burst": AttackTechnique(
        "Credential Access", "TA0006", "T1110", "Brute Force"
    ),
    "threat_intel": AttackTechnique(
        "Command and Control", "TA0011", "T1071", "Application Layer Protocol"
    ),
    "byte_volume": AttackTechnique(
        "Exfiltration", "TA0010", "T1048", "Exfiltration Over Alternative Protocol"
    ),
    "host_sweep": AttackTechnique(
        "Discovery", "TA0007", "T1046", "Network Service Discovery"
    ),
    "tool_download": AttackTechnique(
        "Command and Control", "TA0011", "T1105", "Ingress Tool Transfer"
    ),
    "cloud_upload": AttackTechnique(
        "Exfiltration", "TA0010", "T1567", "Exfiltration Over Web Service"
    ),
    # "off_hours" is intentionally absent — see module docstring.
}


def finding_attack(finding_type: str) -> AttackTechnique | None:
    """The ATT&CK technique for a finding type, or None if unmapped."""
    return _FINDING_ATTACK.get(finding_type)


# VirusTotal-flagged destinations are malware/C2 communication; every SIEM alert
# the enrichment layer emits is this technique.
THREAT_INTEL_ATTACK: AttackTechnique = _FINDING_ATTACK["threat_intel"]
