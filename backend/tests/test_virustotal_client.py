"""VirusTotal client against a mocked transport — no real network."""
from __future__ import annotations

import base64

import httpx
import pytest

from app.enrich.virustotal import VirusTotalClient, VtUnavailable


def _client_with(handler) -> VirusTotalClient:
    """A client wired to a mock transport, ready to `lookup` without a `with` block
    (entering the real context manager would build a live httpx.Client)."""
    client = VirusTotalClient(
        api_key="test-key",
        base_url="https://vt.test/api/v3",
        timeout=5.0,
        rate_per_min=0,  # no throttling in tests
    )
    client._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        headers={"x-apikey": "test-key"},
    )
    return client


def test_domain_ok_parses_stats_labels_and_link():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v3/domains/evil.example.com"
        assert request.headers["x-apikey"] == "test-key"
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 8,
                            "suspicious": 1,
                            "harmless": 60,
                            "undetected": 5,
                        },
                        "reputation": -42,
                        "popular_threat_classification": {
                            "suggested_threat_label": "trojan.generic",
                            "popular_threat_name": [{"value": "emotet"}],
                        },
                    }
                }
            },
        )

    client = _client_with(handler)
    v = client.lookup("domain", "evil.example.com")

    assert v.status == "ok"
    assert (v.malicious, v.suspicious, v.harmless, v.undetected) == (8, 1, 60, 5)
    assert v.reputation == -42
    assert v.threat_labels == ["trojan.generic", "emotet"]
    assert v.link == "https://www.virustotal.com/gui/domain/evil.example.com"


def test_404_is_not_found_not_an_error():
    v = _client_with(lambda r: httpx.Response(404, json={})).lookup("ip", "185.22.14.9")
    assert v.status == "not_found"
    assert v.malicious == 0


def test_429_raises_unavailable():
    client = _client_with(lambda r: httpx.Response(429, json={}))
    with pytest.raises(VtUnavailable):
        client.lookup("domain", "x.example.com")


def test_transport_error_raises_unavailable():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    client = _client_with(boom)
    with pytest.raises(VtUnavailable):
        client.lookup("domain", "x.example.com")


def test_url_indicator_uses_base64_id():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        return httpx.Response(200, json={"data": {"attributes": {}}})

    url = "https://evil.example.com/malware"
    expected_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    _client_with(handler).lookup("url", url)
    assert captured["path"] == f"/api/v3/urls/{expected_id}"
