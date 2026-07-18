"""Tests for the grounded chat layer.

No network: a scripted fake client returns whatever the code under test must
survive. Chat has no deterministic fallback (an arbitrary question has no
rules-engine answer), so the contract here is narrower than `analyse`'s: a good
response is returned as text, and every unavailable path raises `LlmUnavailable`
for the endpoint to turn into a 503.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from anthropic import APIError

from app.llm import (
    CHAT_MAX_FINDINGS,
    CHAT_MAX_IOCS,
    MAX_CHAT_HISTORY,
    LlmUnavailable,
    build_chat_context,
    chat,
)


def _finding(**overrides):
    base = {
        "type": "ip_burst",
        "severity": "critical",
        "confidence": 0.9,
        "reason": "10.0.0.1 made 9 requests within 10s",
        "explanation": None,
        "llm_severity": None,
    }
    return SimpleNamespace(**{**base, **overrides})


def _ioc(**overrides):
    base = {
        "indicator_type": "domain",
        "indicator": "malware.wicar.org",
        "status": "ok",
        "malicious": 14,
        "suspicious": 2,
        "harmless": 43,
        "undetected": 32,
        "reputation": -59,
        "threat_labels": '["trojan"]',
        "vt_link": "https://vt/domain/malware.wicar.org",
    }
    return SimpleNamespace(**{**base, **overrides})


def _context(**overrides):
    base = dict(
        narrative="A host beaconed to a known-bad domain.",
        total_entries=20,
        flagged_count=3,
        timeline=[{"start": "09:00", "requests": 5, "blocked": 1}],
        top_talkers=[{"src_ip": "10.0.4.24", "requests": 6, "blocked": 5}],
        findings=[_finding()],
        enrichments=[_ioc()],
    )
    return build_chat_context(**{**base, **overrides})


# --- build_chat_context -------------------------------------------------------


def test_context_carries_summary_findings_and_threat_intel():
    ctx = _context()

    assert ctx["file_statistics"] == {"total_requests": 20, "flagged_requests": 3}
    assert ctx["narrative"].startswith("A host beaconed")
    assert ctx["findings"][0]["evidence"] == "10.0.0.1 made 9 requests within 10s"
    assert ctx["threat_intel"][0]["indicator"] == "malware.wicar.org"
    assert ctx["threat_intel"][0]["threat_labels"] == ["trojan"]


def test_analyst_annotations_included_only_when_present():
    plain = _context(findings=[_finding()])["findings"][0]
    assert "analyst_note" not in plain
    assert "analyst_severity" not in plain

    annotated = _context(
        findings=[_finding(explanation="Credential stuffing.", llm_severity="high")]
    )["findings"][0]
    assert annotated["analyst_note"] == "Credential stuffing."
    assert annotated["analyst_severity"] == "high"


def test_clean_and_unavailable_iocs_are_excluded():
    ctx = _context(
        enrichments=[
            _ioc(indicator="clean.com", malicious=0, suspicious=0),
            _ioc(indicator="down.com", status="unavailable", malicious=0, suspicious=0),
            _ioc(indicator="bad.com", malicious=5, suspicious=0),
        ]
    )
    indicators = [i["indicator"] for i in ctx["threat_intel"]]

    assert indicators == ["bad.com"]


def test_context_caps_findings_and_iocs():
    ctx = _context(
        findings=[_finding() for _ in range(CHAT_MAX_FINDINGS + 10)],
        enrichments=[_ioc(indicator=f"bad{i}.com") for i in range(CHAT_MAX_IOCS + 10)],
    )

    assert len(ctx["findings"]) == CHAT_MAX_FINDINGS
    assert len(ctx["threat_intel"]) == CHAT_MAX_IOCS


def test_labels_survive_a_real_list_or_missing_value():
    as_list = _context(enrichments=[_ioc(threat_labels=["worm", "c2"])])
    assert as_list["threat_intel"][0]["threat_labels"] == ["worm", "c2"]

    missing = _context(enrichments=[_ioc(threat_labels=None)])
    assert missing["threat_intel"][0]["threat_labels"] == []


# --- chat ---------------------------------------------------------------------


def _text(value):
    return SimpleNamespace(type="text", text=value)


def _response(*blocks):
    return SimpleNamespace(content=list(blocks))


class FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        nxt = self._responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


@pytest.fixture
def fake_claude(monkeypatch):
    def _install(*responses):
        messages = FakeMessages(responses)
        monkeypatch.setattr(
            "app.llm.settings",
            SimpleNamespace(anthropic_api_key="test-key", anthropic_model="claude-x"),
        )
        monkeypatch.setattr(
            "app.llm._client", lambda: SimpleNamespace(messages=messages)
        )
        return messages

    return _install


def test_chat_returns_the_model_text(fake_claude):
    fake_claude(_response(_text("The top talker is 10.0.4.24.")))

    answer = chat(_context(), [], "who is the top talker?")

    assert answer == "The top talker is 10.0.4.24."


def test_context_is_placed_in_the_system_prompt(fake_claude):
    messages = fake_claude(_response(_text("ok")))

    chat(_context(), [], "anything malicious?")
    call = messages.calls[0]

    assert "ANALYSIS CONTEXT" in call["system"]
    assert "malware.wicar.org" in call["system"]  # grounding is present
    # The new question is the final user turn.
    assert call["messages"][-1] == {"role": "user", "content": "anything malicious?"}


def test_history_is_replayed_then_the_new_message(fake_claude):
    messages = fake_claude(_response(_text("It was blocked five times.")))

    history = [
        {"role": "user", "content": "top talker?"},
        {"role": "assistant", "content": "10.0.4.24."},
    ]
    chat(_context(), history, "why blocked?")
    sent = messages.calls[0]["messages"]

    assert [m["content"] for m in sent] == ["top talker?", "10.0.4.24.", "why blocked?"]


def test_history_is_trimmed_to_the_recent_turns(fake_claude):
    messages = fake_claude(_response(_text("ok")))

    history = [{"role": "user", "content": f"q{i}"} for i in range(MAX_CHAT_HISTORY + 8)]
    chat(_context(), history, "latest")
    sent = messages.calls[0]["messages"]

    # Trimmed history + the new message.
    assert len(sent) == MAX_CHAT_HISTORY + 1
    assert sent[-1]["content"] == "latest"


def test_no_api_key_raises_unavailable(fake_claude, monkeypatch):
    fake_claude(_response(_text("unused")))
    monkeypatch.setattr(
        "app.llm.settings",
        SimpleNamespace(anthropic_api_key="", anthropic_model="claude-x"),
    )

    with pytest.raises(LlmUnavailable):
        chat(_context(), [], "hi")


def test_api_error_raises_unavailable(fake_claude):
    fake_claude(APIError("boom", request=SimpleNamespace(), body=None))

    with pytest.raises(LlmUnavailable):
        chat(_context(), [], "hi")


def test_empty_answer_raises_unavailable(fake_claude):
    fake_claude(_response(_text("   ")))

    with pytest.raises(LlmUnavailable):
        chat(_context(), [], "hi")
