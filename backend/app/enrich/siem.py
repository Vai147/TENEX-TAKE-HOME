"""Format malicious enrichments as SIEM alerts (JSON and CEF).

Consumes stored `IocEnrichment` rows so the export reflects exactly what was
persisted, not a fresh network call.
"""
from __future__ import annotations

import json
from collections.abc import Sequence

from app.attack import THREAT_INTEL_ATTACK
from app.enrich.verdict import severity_for
from app.enrich.virustotal import VtVerdict
from app.models import IocEnrichment

CEF_VERSION = "CEF:0"
CEF_VENDOR = "Tenex"
CEF_PRODUCT = "Console"
CEF_DEVICE_VERSION = "1.0"

# CEF severity is 0–10; map our labels onto it.
_CEF_SEVERITY = {"critical": 10, "high": 8, "medium": 5, "low": 3}


def _as_verdict(row: IocEnrichment) -> VtVerdict:
    return VtVerdict(
        indicator_type=row.indicator_type,
        indicator=row.indicator,
        status=row.status,
        malicious=row.malicious,
        suspicious=row.suspicious,
        harmless=row.harmless,
        undetected=row.undetected,
        reputation=row.reputation,
        threat_labels=json.loads(row.threat_labels) if row.threat_labels else [],
        link=row.vt_link,
    )


def _is_alert(row: IocEnrichment) -> bool:
    return row.status == "ok" and (row.malicious >= 1 or row.suspicious >= 1)


def to_json_alerts(rows: Sequence[IocEnrichment]) -> list[dict]:
    """One structured alert per malicious/suspicious indicator."""
    alerts = []
    for row in rows:
        if not _is_alert(row):
            continue
        alerts.append(
            {
                "indicator_type": row.indicator_type,
                "indicator": row.indicator,
                "severity": severity_for(_as_verdict(row)),
                "detections": {
                    "malicious": row.malicious,
                    "suspicious": row.suspicious,
                    "harmless": row.harmless,
                    "undetected": row.undetected,
                },
                "reputation": row.reputation,
                "threat_labels": json.loads(row.threat_labels) if row.threat_labels else [],
                # ATT&CK so a SOAR can pivot/trigger on the technique. A VT-flagged
                # destination is malware/C2 communication (T1071).
                "attack": {
                    "tactic": THREAT_INTEL_ATTACK.tactic,
                    "tactic_id": THREAT_INTEL_ATTACK.tactic_id,
                    "technique_id": THREAT_INTEL_ATTACK.technique_id,
                    "technique_name": THREAT_INTEL_ATTACK.technique_name,
                },
                "source_entry_id": row.entry_id,
                "reference": row.vt_link,
                "observed_at": row.fetched_at.isoformat() if row.fetched_at else None,
            }
        )
    return alerts


def _cef_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _cef_extension_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


def to_cef_alerts(rows: Sequence[IocEnrichment]) -> str:
    """CEF lines, one per alert — the lingua franca most SIEMs ingest."""
    lines = []
    for row in rows:
        if not _is_alert(row):
            continue
        severity = severity_for(_as_verdict(row))
        labels = json.loads(row.threat_labels) if row.threat_labels else []
        header = "|".join(
            _cef_escape(part)
            for part in (
                CEF_VERSION,
                CEF_VENDOR,
                CEF_PRODUCT,
                CEF_DEVICE_VERSION,
                f"vt-{row.indicator_type}",
                f"VirusTotal detection: {row.indicator_type}",
                str(_CEF_SEVERITY.get(severity, 3)),
            )
        )
        ext_pairs = {
            "destinationDnsDomain" if row.indicator_type != "ip" else "dst": row.indicator,
            "cs1Label": "threatLabels",
            "cs1": ", ".join(labels) if labels else "n/a",
            "cn1Label": "maliciousEngines",
            "cn1": str(row.malicious),
            # ATT&CK technique + tactic in CEF custom-string fields so a SOAR can
            # key playbooks off the T-code.
            "cs2Label": "mitreTechnique",
            "cs2": f"{THREAT_INTEL_ATTACK.technique_id} {THREAT_INTEL_ATTACK.technique_name}",
            "cs3Label": "mitreTactic",
            "cs3": THREAT_INTEL_ATTACK.tactic,
            "reference": row.vt_link or "n/a",
        }
        extension = " ".join(
            f"{k}={_cef_extension_escape(str(v))}" for k, v in ext_pairs.items()
        )
        lines.append(f"{header}|{extension}")
    return "\n".join(lines)
