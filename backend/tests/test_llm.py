"""Tests for the Claude layer.

No network: a fake client returns whatever shape each rung of the safety ladder is
supposed to survive. The point of these tests is that *every* rung has a floor —
the pipeline must never raise, whatever the model does.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from anthropic import APIError
from tests.conftest import entry

from app.aggregates import build_aggregates
from app.detectors.base import Finding
from app.llm import (
    ANALYSIS_TOOL,
    MAX_EXPLANATION_LENGTH,
    LlmAnalysis,
    LlmUnavailable,
    analyse,
    fallback_narrative,
)

FINDINGS = [
    Finding(
        type="ip_burst",
        entry_id=1,
        confidence=0.9,
        severity="critical",
        reason="10.0.0.1 made 9 requests within 10s",
    ),
    Finding(
        type="off_hours",
        entry_id=2,
        confidence=0.6,
        severity="medium",
        reason="10.0.0.1 made 11 requests in the middle of the night",
    ),
]

VALID_INPUT = {
    "narrative": "At 02:14 UTC a single host made nine authentication attempts in ten seconds.",
    "explanations": [
        {"finding_index": 0, "explanation": "Looks like credential stuffing.", "severity": "high"},
        {"finding_index": 1, "explanation": "Consistent with automation.", "severity": "medium"},
    ],
}


def _valid_input_for(finding_count: int) -> dict:
    """A well-formed response explaining exactly `finding_count` findings."""
    return {
        "narrative": "At 02:14 UTC a single host made nine attempts in ten seconds.",
        "explanations": [
            {"finding_index": i, "explanation": f"Explanation {i}.", "severity": "high"}
            for i in range(finding_count)
        ],
    }


def _tool_use(payload):
    return SimpleNamespace(type="tool_use", name=ANALYSIS_TOOL["name"], input=payload)


def _response(*blocks):
    return SimpleNamespace(content=list(blocks))


class FakeMessages:
    """Returns a scripted response per call, recording what it was sent."""

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
    """Install a scripted Claude and a dummy API key."""

    def _install(*responses):
        messages = FakeMessages(responses)
        monkeypatch.setattr("app.llm.settings", SimpleNamespace(
            anthropic_api_key="test-key", anthropic_model="claude-haiku-4-5-20251001"
        ))
        monkeypatch.setattr("app.llm._client", lambda: SimpleNamespace(messages=messages))
        return messages

    return _install


@pytest.fixture
def aggregates():
    return build_aggregates([entry(src_ip="10.0.0.1") for _ in range(3)])


# --- the happy path -----------------------------------------------------------


def test_valid_response_is_returned(fake_claude, aggregates):
    fake_claude(_response(_tool_use(VALID_INPUT)))

    analysis = analyse(aggregates, FINDINGS)

    assert isinstance(analysis, LlmAnalysis)
    assert analysis.narrative.startswith("At 02:14 UTC")
    assert [e.finding_index for e in analysis.explanations] == [0, 1]


def test_the_model_is_forced_to_call_the_tool(fake_claude, aggregates):
    messages = fake_claude(_response(_tool_use(VALID_INPUT)))

    analyse(aggregates, FINDINGS)

    assert messages.calls[0]["tool_choice"] == {"type": "tool", "name": "record_analysis"}


def test_claude_receives_aggregates_and_findings_but_never_raw_log_lines(
    fake_claude, aggregates
):
    messages = fake_claude(_response(_tool_use(VALID_INPUT)))

    analyse(aggregates, FINDINGS)
    prompt = messages.calls[0]["messages"][0]["content"]

    assert "10.0.0.1 made 9 requests within 10s" in prompt  # finding evidence
    assert "total_requests" in prompt  # aggregate statistics
    assert "raw" not in prompt


def test_every_finding_carries_the_facts_of_the_entry_it_is_anchored_to(
    fake_claude, aggregates
):
    """Regression: a live run misattributed a byte_volume finding to the wrong IP.

    Its evidence prose quotes a byte count and never names a host, so the model
    inferred one and guessed wrong. The anchor entry must supply the attribution.
    """
    anchored = entry(id=1, src_ip="192.168.9.66", url="https://internal/api/db/dump")
    byte_finding = Finding(
        type="byte_volume",
        entry_id=1,
        confidence=1.0,
        severity="critical",
        reason="142,880,422 bytes downloaded — 896.1 interquartile ranges above...",
    )
    messages = fake_claude(_response(_tool_use(_valid_input_for(1))))

    analyse(aggregates, [byte_finding], [anchored])
    prompt = messages.calls[0]["messages"][0]["content"]

    assert "anchor_entry" in prompt
    assert "192.168.9.66" in prompt, "the finding must name its own host"
    assert "https://internal/api/db/dump" in prompt


def test_a_finding_without_an_anchor_entry_still_builds_a_prompt(fake_claude, aggregates):
    orphan = Finding(
        type="ip_burst", entry_id=None, confidence=0.9, severity="critical", reason="x"
    )
    fake_claude(_response(_tool_use(_valid_input_for(1))))

    assert analyse(aggregates, [orphan], []).narrative


# --- rung 1: extract ----------------------------------------------------------


def test_prose_instead_of_a_tool_call_is_repaired(fake_claude, aggregates):
    prose_only = _response(SimpleNamespace(type="text", text="Here is my analysis..."))
    messages = fake_claude(prose_only, _response(_tool_use(VALID_INPUT)))

    analysis = analyse(aggregates, FINDINGS)

    assert analysis.narrative  # recovered on the retry
    assert len(messages.calls) == 2


# --- rung 3: schema validation ------------------------------------------------


def test_a_schema_violation_is_repaired(fake_claude, aggregates):
    wrong_type = _tool_use({"narrative": "ok " * 10, "explanations": "not-a-list"})
    fake_claude(_response(wrong_type), _response(_tool_use(VALID_INPUT)))

    assert analyse(aggregates, FINDINGS).explanations


def test_a_missing_field_is_repaired(fake_claude, aggregates):
    incomplete = _tool_use({"narrative": "A burst occurred at 02:14 UTC on one host."})
    fake_claude(_response(incomplete), _response(_tool_use(VALID_INPUT)))

    assert analyse(aggregates, FINDINGS).explanations


# --- rung 4: semantic checks --------------------------------------------------


def test_an_invented_finding_index_is_rejected(fake_claude, aggregates):
    """The model must not explain findings that do not exist."""
    hallucinated = _tool_use(
        {
            "narrative": "A burst occurred at 02:14 UTC on a single host.",
            "explanations": [
                {"finding_index": 47, "explanation": "Data exfil.", "severity": "critical"}
            ],
        }
    )
    messages = fake_claude(_response(hallucinated), _response(_tool_use(VALID_INPUT)))

    analyse(aggregates, FINDINGS)
    repair_prompt = messages.calls[1]["messages"][-1]["content"]

    assert "47" in repair_prompt and "does not exist" in repair_prompt


def test_a_duplicated_finding_index_is_rejected(fake_claude, aggregates):
    duplicated = _tool_use(
        {
            "narrative": "A burst occurred at 02:14 UTC on a single host.",
            "explanations": [
                {"finding_index": 0, "explanation": "First take.", "severity": "high"},
                {"finding_index": 0, "explanation": "Second take.", "severity": "low"},
            ],
        }
    )
    fake_claude(_response(duplicated), _response(_tool_use(VALID_INPUT)))

    assert len(analyse(aggregates, FINDINGS).explanations) == 2


def test_an_empty_narrative_is_rejected(fake_claude, aggregates):
    empty = _tool_use({"narrative": "   ", "explanations": []})
    fake_claude(_response(empty), _response(_tool_use(VALID_INPUT)))

    assert analyse(aggregates, FINDINGS).narrative.strip()


def test_an_absurdly_long_explanation_is_rejected(fake_claude, aggregates):
    bloated = _tool_use(
        {
            "narrative": "A burst occurred at 02:14 UTC on a single host.",
            "explanations": [
                {
                    "finding_index": 0,
                    "explanation": "x" * (MAX_EXPLANATION_LENGTH + 1),
                    "severity": "high",
                }
            ],
        }
    )
    fake_claude(_response(bloated), _response(_tool_use(VALID_INPUT)))

    assert analyse(aggregates, FINDINGS).explanations


def test_an_invalid_severity_is_rejected(fake_claude, aggregates):
    bad_severity = _tool_use(
        {
            "narrative": "A burst occurred at 02:14 UTC on a single host.",
            "explanations": [
                {"finding_index": 0, "explanation": "Bad.", "severity": "apocalyptic"}
            ],
        }
    )
    fake_claude(_response(bad_severity), _response(_tool_use(VALID_INPUT)))

    assert analyse(aggregates, FINDINGS).explanations[0].severity in {"high", "medium"}


# --- rung 5: repair, then give up ---------------------------------------------


def test_the_repair_prompt_carries_the_error_and_the_assistant_turn(fake_claude, aggregates):
    """A retry that does not show the model its own output is just a re-roll."""
    broken = _tool_use({"narrative": "hi", "explanations": []})
    messages = fake_claude(_response(broken), _response(_tool_use(VALID_INPUT)))

    analyse(aggregates, FINDINGS)
    retry_messages = messages.calls[1]["messages"]

    assert retry_messages[1]["role"] == "assistant"
    assert "rejected" in retry_messages[2]["content"]
    assert "exactly 2 findings" in retry_messages[2]["content"]


def test_two_bad_responses_exhaust_the_ladder(fake_claude, aggregates):
    broken = _response(_tool_use({"narrative": "no", "explanations": []}))
    messages = fake_claude(broken, broken)

    with pytest.raises(LlmUnavailable):
        analyse(aggregates, FINDINGS)

    assert len(messages.calls) == 2, "one repair attempt, not an infinite loop"


# --- API and configuration failures -------------------------------------------


def test_an_api_error_is_not_repaired(fake_claude, aggregates):
    """No retry prompt fixes a 401 or a rate limit; fail straight to the fallback."""
    error = APIError("rate limited", request=None, body=None)
    messages = fake_claude(error, _response(_tool_use(VALID_INPUT)))

    with pytest.raises(LlmUnavailable):
        analyse(aggregates, FINDINGS)

    assert len(messages.calls) == 1


def test_no_api_key_short_circuits(monkeypatch, aggregates):
    monkeypatch.setattr(
        "app.llm.settings", SimpleNamespace(anthropic_api_key="", anthropic_model="m")
    )

    with pytest.raises(LlmUnavailable, match="No ANTHROPIC_API_KEY"):
        analyse(aggregates, FINDINGS)


# --- the bottom rung ----------------------------------------------------------


def test_fallback_narrative_reports_the_real_numbers(aggregates):
    text = fallback_narrative(aggregates, FINDINGS)

    assert "3 requests" in text
    assert "2 finding(s)" in text
    assert "ip_burst" in text and "off_hours" in text


def test_fallback_narrative_without_findings_says_so(aggregates):
    assert "No anomalies" in fallback_narrative(aggregates, [])


def test_fallback_narrative_handles_an_empty_file():
    assert "No log entries" in fallback_narrative(build_aggregates([]), [])