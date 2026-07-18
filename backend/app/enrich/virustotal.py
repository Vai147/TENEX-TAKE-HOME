"""A thin, synchronous VirusTotal API v3 client.

All network I/O for enrichment lives here so the rest of the pipeline stays pure
and testable against a fake. Failures raise `VtUnavailable` (reach/quota problems)
rather than returning a fake-clean verdict, so the caller can record "we could not
tell" instead of silently downgrading a threat to harmless. A genuinely unknown
indicator (HTTP 404) is a real answer and comes back as a `not_found` verdict.
"""
from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


class VtUnavailable(Exception):
    """VirusTotal could not be reached or refused the request (network error,
    timeout, rate limit, auth, 5xx). Distinct from a 404 'not found'."""


@dataclass(frozen=True)
class VtVerdict:
    indicator_type: str
    indicator: str
    status: str  # "ok" | "not_found"
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int = 0
    threat_labels: list[str] = field(default_factory=list)
    link: str | None = None


# VT resource path + GUI path per indicator type. The URL id is a base64url of the
# URL itself (VT's documented addressing), computed in `_resource_path`.
_GUI_BASE = "https://www.virustotal.com/gui"


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")


def _resource_path(indicator_type: str, value: str) -> str:
    if indicator_type == "domain":
        return f"/domains/{value}"
    if indicator_type == "ip":
        return f"/ip_addresses/{value}"
    if indicator_type == "url":
        return f"/urls/{_url_id(value)}"
    raise ValueError(f"Unknown indicator type: {indicator_type}")


def _gui_link(indicator_type: str, value: str) -> str:
    if indicator_type == "ip":
        return f"{_GUI_BASE}/ip-address/{value}"
    if indicator_type == "url":
        return f"{_GUI_BASE}/url/{_url_id(value)}"
    return f"{_GUI_BASE}/domain/{value}"


def _threat_labels(attributes: dict) -> list[str]:
    classification = attributes.get("popular_threat_classification") or {}
    labels: list[str] = []
    suggested = classification.get("suggested_threat_label")
    if suggested:
        labels.append(str(suggested))
    for item in classification.get("popular_threat_name") or []:
        name = item.get("value") if isinstance(item, dict) else None
        if name and name not in labels:
            labels.append(str(name))
    return labels


class RateLimiter:
    """Spaces calls to at most `per_minute`, by blocking until the next slot.

    Deliberately simple: the free VirusTotal tier is 4/min, so a fixed minimum gap
    between calls keeps us under it without tracking a sliding window.
    """

    def __init__(self, per_minute: int) -> None:
        self._min_gap = 60.0 / per_minute if per_minute > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self._min_gap <= 0:
            return
        elapsed = time.monotonic() - self._last
        if elapsed < self._min_gap:
            time.sleep(self._min_gap - elapsed)
        self._last = time.monotonic()


class VirusTotalClient:
    """Context manager wrapping one `httpx.Client`. Use with `with`."""

    def __init__(self, api_key: str, base_url: str, timeout: float, rate_per_min: int) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._limiter = RateLimiter(rate_per_min)
        self._client: httpx.Client | None = None

    def __enter__(self) -> "VirusTotalClient":
        self._client = httpx.Client(
            timeout=self._timeout,
            headers={"x-apikey": self._api_key, "accept": "application/json"},
        )
        return self

    def __exit__(self, *exc: object) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def lookup(self, indicator_type: str, value: str) -> VtVerdict:
        if self._client is None:
            raise RuntimeError("VirusTotalClient used outside its context manager")

        path = _resource_path(indicator_type, value)
        self._limiter.wait()
        try:
            response = self._client.get(f"{self._base_url}{path}")
        except httpx.HTTPError as exc:
            raise VtUnavailable(f"request failed: {exc}") from exc

        if response.status_code == 404:
            return VtVerdict(
                indicator_type=indicator_type,
                indicator=value,
                status="not_found",
                link=_gui_link(indicator_type, value),
            )
        if response.status_code == 429:
            raise VtUnavailable("rate limited (429)")
        if response.status_code in (401, 403):
            raise VtUnavailable(f"auth error ({response.status_code})")
        if response.status_code >= 400:
            raise VtUnavailable(f"unexpected status {response.status_code}")

        attributes = (response.json().get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        return VtVerdict(
            indicator_type=indicator_type,
            indicator=value,
            status="ok",
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            reputation=int(attributes.get("reputation", 0)),
            threat_labels=_threat_labels(attributes),
            link=_gui_link(indicator_type, value),
        )
