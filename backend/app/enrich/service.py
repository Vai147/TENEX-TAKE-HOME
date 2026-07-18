"""Enrichment orchestration: extract → (cache | VirusTotal) → persist → alert.

Runs on demand, off the ingest path. Never mutates the deterministic findings or
the log entries — it only adds `IocEnrichment` rows and `virustotal`-sourced
`AnomalyFinding`s, mirroring how the LLM layer only ever annotates.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.config import get_settings
from app.enrich.extract import extract_indicators
from app.enrich.verdict import FINDING_SOURCE, is_alertable, to_finding
from app.enrich.virustotal import VirusTotalClient, VtUnavailable, VtVerdict
from app.models import AnomalyFinding, IocEnrichment, LogEntry, Upload

logger = logging.getLogger(__name__)
settings = get_settings()


class VtNotConfigured(Exception):
    """No VirusTotal API key is set, so enrichment cannot run."""


@dataclass(frozen=True)
class EnrichResult:
    indicators_seen: int
    enriched: int
    from_cache: int
    unavailable: int
    alerts: int


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _cached_verdict(db: Session, indicator_type: str, value: str) -> VtVerdict | None:
    """A recent verdict for this indicator from any upload, within the TTL, so a
    repeated destination never re-spends the free-tier quota. Only real answers
    ('ok'/'not_found') are reused — a prior 'unavailable' is retried."""
    cutoff = _utcnow() - timedelta(hours=settings.virustotal_cache_ttl_hours)
    row = (
        db.query(IocEnrichment)
        .filter(
            IocEnrichment.indicator_type == indicator_type,
            IocEnrichment.indicator == value,
            IocEnrichment.status.in_(("ok", "not_found")),
            IocEnrichment.fetched_at >= cutoff,
        )
        .order_by(IocEnrichment.fetched_at.desc())
        .first()
    )
    if row is None:
        return None
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


def _persist_enrichment(
    db: Session, upload_id: int, entry_id: int | None, verdict: VtVerdict
) -> IocEnrichment:
    row = IocEnrichment(
        upload_id=upload_id,
        entry_id=entry_id,
        indicator_type=verdict.indicator_type,
        indicator=verdict.indicator,
        status=verdict.status,
        malicious=verdict.malicious,
        suspicious=verdict.suspicious,
        harmless=verdict.harmless,
        undetected=verdict.undetected,
        reputation=verdict.reputation,
        threat_labels=json.dumps(verdict.threat_labels) if verdict.threat_labels else None,
        vt_link=verdict.link,
    )
    db.add(row)
    return row


def _clear_previous(db: Session, upload_id: int) -> None:
    """Make re-enriching idempotent: drop this upload's prior VT rows and findings
    so a re-run replaces rather than duplicates."""
    db.query(IocEnrichment).filter(IocEnrichment.upload_id == upload_id).delete()
    db.query(AnomalyFinding).filter(
        AnomalyFinding.upload_id == upload_id,
        AnomalyFinding.source == FINDING_SOURCE,
    ).delete()


def enrich_upload(db: Session, upload: Upload) -> EnrichResult:
    """Enrich one upload's destination indicators against VirusTotal.

    Raises `VtNotConfigured` if no API key is set. Never raises on a VirusTotal
    outage: an unreachable lookup is recorded as `unavailable`, distinct from a
    clean verdict, so an alert is never silently suppressed.
    """
    if not settings.virustotal_enabled:
        raise VtNotConfigured("VIRUSTOTAL_API_KEY is not set")

    _clear_previous(db, upload.id)

    entries = db.query(LogEntry).filter(LogEntry.upload_id == upload.id).all()
    indicators = extract_indicators(entries)

    budget = settings.virustotal_max_indicators
    enriched = from_cache = unavailable = alerts = 0

    with VirusTotalClient(
        api_key=settings.virustotal_api_key,
        base_url=settings.virustotal_api_base,
        timeout=settings.virustotal_timeout_seconds,
        rate_per_min=settings.virustotal_rate_per_min,
    ) as client:
        for indicator in indicators:
            cached = _cached_verdict(db, indicator.type, indicator.value)
            if cached is not None:
                verdict = cached
                from_cache += 1
            else:
                if budget <= 0:
                    # Out of network quota for this run; leave the rest un-enriched
                    # rather than partially and unpredictably spending the daily cap.
                    break
                budget -= 1
                try:
                    verdict = client.lookup(indicator.type, indicator.value)
                except VtUnavailable as exc:
                    logger.info("VirusTotal lookup failed for %s: %s", indicator.value, exc)
                    verdict = VtVerdict(
                        indicator_type=indicator.type,
                        indicator=indicator.value,
                        status="unavailable",
                    )
                    unavailable += 1

            _persist_enrichment(db, upload.id, indicator.representative_entry_id, verdict)
            enriched += 1

            if is_alertable(verdict, settings.virustotal_alert_min_malicious):
                fields = to_finding(verdict, indicator.representative_entry_id)
                db.add(
                    AnomalyFinding(
                        upload_id=upload.id,
                        entry_id=fields.entry_id,
                        type=fields.type,
                        confidence=fields.confidence,
                        severity=fields.severity,
                        reason=fields.reason,
                        source=fields.source,
                    )
                )
                alerts += 1

    db.commit()
    return EnrichResult(
        indicators_seen=len(indicators),
        enriched=enriched,
        from_cache=from_cache,
        unavailable=unavailable,
        alerts=alerts,
    )


def get_enrichments(db: Session, upload_id: int) -> list[IocEnrichment]:
    """Stored enrichments for an upload, most-malicious first — feeds the Threat
    Intel tab and the SIEM export."""
    return (
        db.query(IocEnrichment)
        .filter(IocEnrichment.upload_id == upload_id)
        .order_by(IocEnrichment.malicious.desc(), IocEnrichment.suspicious.desc(), IocEnrichment.id.asc())
        .all()
    )
