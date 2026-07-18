"""IOC extraction: dedup, host classification, private-IP skipping, ranking."""
from __future__ import annotations

from app.enrich.extract import extract_indicators
from tests.conftest import entry


def _by_type(indicators):
    out: dict[str, list[str]] = {}
    for ind in indicators:
        out.setdefault(ind.type, []).append(ind.value)
    return out


def test_extracts_domain_and_url_from_a_hostname_url():
    indicators = extract_indicators([entry(url="https://evil.example.com/path?q=1")])
    by_type = _by_type(indicators)
    assert "evil.example.com" in by_type["domain"]
    assert any(v.startswith("https://evil.example.com/path") for v in by_type["url"])


def test_public_ip_host_is_an_ip_indicator():
    indicators = extract_indicators([entry(url="http://185.22.14.9/admin")])
    by_type = _by_type(indicators)
    assert by_type["ip"] == ["185.22.14.9"]


def test_private_ip_host_is_skipped():
    indicators = extract_indicators([entry(url="http://10.0.0.5/internal")])
    by_type = _by_type(indicators)
    assert "ip" not in by_type  # 10.x is internal, no external reputation


def test_deduplicates_across_entries_and_merges_entry_ids():
    e1 = entry(id=1, url="https://dup.example.com/a")
    e2 = entry(id=2, url="https://dup.example.com/a")
    indicators = extract_indicators([e1, e2])
    domain = next(i for i in indicators if i.type == "domain")
    assert domain.entry_ids == (1, 2)


def test_blocked_indicators_rank_before_clean_ones():
    clean = entry(id=1, url="https://clean.example.com/", action="Allowed")
    bad = entry(id=2, url="https://bad.example.com/", action="Blocked")
    indicators = extract_indicators([clean, bad])
    # First indicator overall should come from the blocked entry.
    assert indicators[0].blocked is True
    assert indicators[0].value == "bad.example.com"


def test_entry_without_url_yields_nothing():
    assert extract_indicators([entry(url=None)]) == []
