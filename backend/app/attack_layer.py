"""Build an ATT&CK Navigator layer JSON from an upload's findings.

The layer file is MITRE's own format for the Navigator matrix
(mitre-attack.github.io/attack-navigator): an analyst loads it and the techniques
this upload exercised light up, scored by activity. Pure `(findings) -> dict`, so
it is unit-testable without a DB or the network, like the detectors.

Score = number of findings mapped to the technique. Severity and count travel in
per-cell metadata. Findings that map to no technique (e.g. off_hours) are omitted —
the matrix only shows real techniques.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.attack import finding_attack

# Pinned so a Navigator version bump can't silently change our output. Older
# layers still load in newer Navigator.
LAYER_VERSION = "4.5"
ATTACK_VERSION = "14"
NAVIGATOR_VERSION = "4.9.5"
DOMAIN = "enterprise-attack"

# Heat ramp: unseen (white) → hottest (the console's danger red).
GRADIENT_COLORS = ["#ffffff", "#e5484d"]

# Rank severities so a technique's cell can report its worst finding.
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class _Cell:
    __slots__ = ("technique_id", "tactic", "count", "severity")

    def __init__(self, technique_id: str, tactic: str) -> None:
        self.technique_id = technique_id
        self.tactic = tactic
        self.count = 0
        self.severity = "low"

    def add(self, severity: str) -> None:
        self.count += 1
        if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(self.severity, 0):
            self.severity = severity


def build_navigator_layer(
    filename: str, upload_id: int, findings: Sequence[Any]
) -> dict[str, Any]:
    """An ATT&CK Navigator layer dict for one upload's findings."""
    cells: dict[str, _Cell] = {}
    for finding in findings:
        technique = finding_attack(finding.type)
        if technique is None:
            continue
        cell = cells.get(technique.technique_id)
        if cell is None:
            cell = _Cell(technique.technique_id, technique.tactic)
            cells[technique.technique_id] = cell
        cell.add(finding.severity)

    techniques = [
        {
            "techniqueID": cell.technique_id,
            "score": cell.count,
            "enabled": True,
            "comment": cell.tactic,
            "metadata": [
                {"name": "max_severity", "value": cell.severity},
                {"name": "findings", "value": str(cell.count)},
            ],
        }
        for cell in cells.values()
    ]

    max_score = max((cell.count for cell in cells.values()), default=1)

    return {
        "name": f"Tenex — {filename} (#{upload_id})",
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": DOMAIN,
        "description": f"Tenex Console analysis of {filename}",
        "techniques": techniques,
        "gradient": {
            "colors": GRADIENT_COLORS,
            "minValue": 0,
            "maxValue": max_score,
        },
        "sorting": 0,
        "hideDisabled": False,
        "legendItems": [],
    }
