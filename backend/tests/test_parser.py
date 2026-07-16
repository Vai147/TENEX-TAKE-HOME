"""Unit tests for the ZScaler log parser."""
from datetime import timezone

import pytest

from app.parser import parse_logs

HEADER = "timestamp,user,src_ip,url,action,status,bytes_sent,bytes_recv,user_agent"


def test_parses_well_formed_rows():
    text = (
        HEADER
        + "\n2026-07-14T09:01:12Z,alice@corp.com,10.0.4.21,https://x.com,Allowed,200,100,200,Chrome"
    )
    result = parse_logs(text)
    assert len(result.entries) == 1
    e = result.entries[0]
    assert e.src_ip == "10.0.4.21"
    assert e.action == "Allowed"
    assert e.status_code == 200
    assert e.bytes_sent == 100
    assert e.ts is not None
    assert e.ts.tzinfo == timezone.utc


def test_handles_missing_and_empty_fields():
    text = HEADER + "\n,,,,,,,,"
    result = parse_logs(text)
    assert len(result.entries) == 1
    e = result.entries[0]
    assert e.ts is None
    assert e.src_ip is None
    assert e.status_code is None


def test_bad_timestamp_and_ints_become_none():
    text = HEADER + "\nnot-a-date,u,1.2.3.4,url,Allowed,abc,xyz,-,UA"
    e = parse_logs(text).entries[0]
    assert e.ts is None
    assert e.status_code is None
    assert e.bytes_sent is None


def test_rejects_unrecognized_header():
    with pytest.raises(ValueError):
        parse_logs("foo,bar,baz\n1,2,3")


def test_empty_input_returns_no_entries():
    assert parse_logs("").entries == []