"""Unit tests for the log aggregates."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from tests.conftest import entries_at, entry

from app.aggregates import (
    TOP_TALKER_LIMIT,
    build_aggregates,
    timeline_json,
    top_talkers_json,
)

NINE_AM = datetime(2026, 7, 14, 9, 0, tzinfo=timezone.utc)


def test_counts_totals_and_distinct_dimensions():
    entries = [
        entry(src_ip="10.0.0.1", user="alice@corp.com"),
        entry(src_ip="10.0.0.1", user="alice@corp.com"),
        entry(src_ip="10.0.0.2", user="bob@corp.com"),
    ]
    aggregates = build_aggregates(entries)

    assert aggregates.total_entries == 3
    assert aggregates.unique_ips == 2
    assert aggregates.unique_users == 2


def test_counts_blocked_by_action_and_status():
    entries = [
        entry(action="Blocked", status_code=403),
        entry(action="Allowed", status_code=401),  # blocked by status alone
        entry(action="Allowed", status_code=200),
    ]

    assert build_aggregates(entries).blocked_entries == 2


def test_time_window_spans_first_to_last_timestamp():
    aggregates = build_aggregates(entries_at([0, 600, 60], base=NINE_AM))

    assert aggregates.first_seen == NINE_AM.isoformat()
    assert aggregates.last_seen == (NINE_AM + timedelta(seconds=600)).isoformat()


def test_time_window_is_null_when_nothing_has_a_timestamp():
    aggregates = build_aggregates([entry(ts=None), entry(ts=None)])

    assert aggregates.first_seen is None
    assert aggregates.last_seen is None


def test_timeline_buckets_by_hour():
    entries = (
        entries_at([0, 60, 120], base=NINE_AM)
        + entries_at([0], base=NINE_AM + timedelta(hours=1))
    )
    timeline = build_aggregates(entries).timeline

    assert [b.requests for b in timeline] == [3, 1]
    assert timeline[0].start == NINE_AM.isoformat()


def test_timeline_counts_blocked_per_bucket():
    entries = entries_at([0, 60], base=NINE_AM, action="Blocked") + entries_at(
        [120], base=NINE_AM
    )
    bucket = build_aggregates(entries).timeline[0]

    assert bucket.requests == 3
    assert bucket.blocked == 2


def test_timeline_omits_empty_hours_rather_than_inventing_zeroes():
    """A gap in traffic is not a measurement of zero traffic."""
    entries = entries_at([0], base=NINE_AM) + entries_at(
        [0], base=NINE_AM + timedelta(hours=5)
    )
    timeline = build_aggregates(entries).timeline

    assert len(timeline) == 2


def test_timeline_skips_entries_with_no_timestamp():
    assert build_aggregates([entry(ts=None)]).timeline == []


def test_top_talkers_rank_by_request_count():
    entries = (
        [entry(src_ip="10.0.0.1") for _ in range(5)]
        + [entry(src_ip="10.0.0.2") for _ in range(9)]
        + [entry(src_ip="10.0.0.3")]
    )
    talkers = build_aggregates(entries).top_talkers

    assert [t.src_ip for t in talkers] == ["10.0.0.2", "10.0.0.1", "10.0.0.3"]
    assert talkers[0].requests == 9


def test_top_talkers_sum_bytes_per_ip():
    entries = [
        entry(src_ip="10.0.0.1", bytes_recv=100, bytes_sent=10),
        entry(src_ip="10.0.0.1", bytes_recv=200, bytes_sent=20),
    ]
    talker = build_aggregates(entries).top_talkers[0]

    assert talker.bytes_recv == 300
    assert talker.bytes_sent == 30


def test_top_talkers_tolerate_null_byte_counts():
    entries = [entry(src_ip="10.0.0.1", bytes_recv=None, bytes_sent=None)]

    assert build_aggregates(entries).top_talkers[0].bytes_recv == 0


def test_top_talkers_are_capped():
    entries = [entry(src_ip=f"10.0.0.{i}") for i in range(TOP_TALKER_LIMIT + 5)]

    assert len(build_aggregates(entries).top_talkers) == TOP_TALKER_LIMIT


def test_empty_input_produces_an_empty_but_valid_aggregate():
    aggregates = build_aggregates([])

    assert aggregates.total_entries == 0
    assert aggregates.timeline == []
    assert aggregates.top_talkers == []


def test_json_serializers_round_trip():
    aggregates = build_aggregates(entries_at([0, 60], base=NINE_AM, src_ip="10.0.0.1"))

    timeline = json.loads(timeline_json(aggregates))
    talkers = json.loads(top_talkers_json(aggregates))

    assert timeline[0]["requests"] == 2
    assert talkers[0]["src_ip"] == "10.0.0.1"