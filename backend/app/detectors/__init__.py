"""Deterministic anomaly detection.

`run_detectors` is the entry point; individual detectors live one per module and
stay importable on their own for testing.
"""
from app.detectors.base import EntryLike, Finding, severity_for
from app.detectors.blocked_spike import detect_blocked_spike
from app.detectors.byte_volume import detect_byte_volume
from app.detectors.engine import (
    DETECTOR_WEIGHTS,
    MAX_FINDINGS,
    run_detectors,
    score,
    top_findings,
)
from app.detectors.ip_burst import detect_ip_burst
from app.detectors.off_hours import detect_off_hours
from app.detectors.rare_user_agent import detect_rare_user_agent

__all__ = [
    "DETECTOR_WEIGHTS",
    "MAX_FINDINGS",
    "EntryLike",
    "Finding",
    "detect_blocked_spike",
    "detect_byte_volume",
    "detect_ip_burst",
    "detect_off_hours",
    "detect_rare_user_agent",
    "run_detectors",
    "score",
    "severity_for",
    "top_findings",
]
