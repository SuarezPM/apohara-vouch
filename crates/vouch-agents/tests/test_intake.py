"""S-02: Intake agent tests (5 ACs total).

Tests are organized as 1 test per AC + per-fixture cases:

* test_build_extraction_llm_targets_aiml_api        (AC-2.1)
* test_build_crewai_agent_uses_intake_role          (AC-2.1)
* test_procurement_case_schema_has_nine_fields      (AC-2.2)
* test_parse_clean_fixture_emits_valid_case         (AC-2.3)
* test_parse_clean_fixture_populates_all_fields     (AC-2.3)
* test_parse_violations_fixture_emits_valid_case    (AC-2.5: 3 violations, schema-valid)
* test_parse_malformed_input_returns_none           (AC-2.4)
* test_parse_empty_input_returns_none               (AC-2.4)
* test_post_error_to_band_uses_error_message_type   (AC-2.4)
* test_parse_violations_case_does_not_advance_via_error_path
                                                     (AC-2.4 contract — case
                                                      is parsed OK but if a
                                                      downstream agent rejects,
                                                      intake has not advanced)

Every public function in intake.py has at least one test (hard rule #2).
The CrewAI Agent is mocked with ``unittest.mock.MagicMock`` per hint #5 —
no network calls in tests. The pydantic schema is exercised for real.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

THIS_DIR = Path(__file__).resolve().parent
SRC_DIR = THIS_DIR.parent / "src"
FIXTURES = THIS_DIR.parent / "fixtures"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from intake import (  # noqa: E402
    IntakeAgent,
    ProcurementCase,
    build_crewai_agent,
    build_extraction_llm,
    load_secrets,
)


# ---------------------------------------------------------------------------
# AC-2.1 — CrewAI-backed LLM via AI/ML API (claude-haiku-4-5)
# ---------------------------------------------------------------------------


def test_build_extraction_llm_targets_aiml_api() -> None:
    """AC-2.1: LLM is built against AIML API base_url with claude-haiku-4-5."""
    llm = build_extraction_llm(
        secrets={
            "AIML_API_KEY": "test-key",
            "AIML_API_BASE_URL": "https://api.aimlapi.com/v1",
        }
    )
    # CrewAI's LLM exposes model + base_url + api_key as attributes.
    assert "claude-haiku-4-5" in llm.model, llm.model
    assert "aimlapi.com" in str(llm.base_url), llm.base_url
    assert llm.api_key == "test-key", llm.api_key
    # We route through LiteLLM with the openai/ prefix so the AIML
    # gateway (which is OpenAI-compatible) handles the call.
    assert "openai/" in llm.model, llm.model


def test_build_crewai_agent_uses_intake_role() -> None:
    """AC-2.1: Agent is wired with role='intake-analyst' + the AIML LLM."""
    llm = build_extraction_llm(
        secrets={
            "AIML_API_KEY": "test-key",
            "AIML_API_BASE_URL": "https://api.aimlapi.com/v1",
        }
    )
    agent = build_crewai_agent(llm=llm)
    assert agent.role == "intake-analyst", agent.role
    assert "ProcurementCase" in agent.goal, agent.goal
    assert "procurement-intake" in agent.backstory.lower(), agent.backstory
    # The LLM is the same one we built — proves the wire.
    assert agent.llm is llm, agent.llm


# ---------------------------------------------------------------------------
# AC-2.2 — ProcurementCase schema: 9 required fields
# ---------------------------------------------------------------------------


def test_procurement_case_schema_has_nine_fields() -> None:
    """AC-2.2: schema has case_id, buyer, vendor_name, vendor_id,
    amount_eur, category, requested_action, attachments, urgency."""
    expected = {
        "case_id",
        "buyer",
        "vendor_name",
        "vendor_id",
        "amount_eur",
        "category",
        "requested_action",
        "attachments",
        "urgency",
    }
    actual = set(ProcurementCase.model_fields.keys())
    assert actual == expected, (actual, expected)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _make_mock_crewai(json_payload: dict) -> MagicMock:
    """Mock CrewAI Agent whose kickoff returns the given JSON payload."""
    mock_agent = MagicMock()
    result = MagicMock()
    result.raw = json.dumps(json_payload, sort_keys=True)
    mock_agent.kickoff.return_value = result
    return mock_agent


# ---------------------------------------------------------------------------
# AC-2.3 — Clean fixture emits valid ProcurementCase with all fields populated
# ---------------------------------------------------------------------------


def test_parse_clean_fixture_emits_valid_case() -> None:
    """AC-2.3: given procurement_clean.json, emit valid ProcurementCase."""
    clean_text = _load_fixture("procurement_clean.json")
    clean_obj = json.loads(clean_text)
    mock_agent = _make_mock_crewai(clean_obj)
    intake = IntakeAgent(crewai_agent=mock_agent)
    case = intake.parse_request(clean_text)
    assert case is not None, "parse_request returned None on clean fixture"
    # Round-trip: model_dump -> JSON preserves the 9 fields.
    dumped = case.model_dump(mode="json")
    assert dumped["case_id"] == "PC-2026-0001", dumped
    assert dumped["vendor_id"] == "DE-271828-BERLIN", dumped
    assert dumped["amount_eur"] == 12450.0, dumped


def test_parse_clean_fixture_populates_all_fields() -> None:
    """AC-2.3: every required field is non-empty on the clean fixture."""
    clean_text = _load_fixture("procurement_clean.json")
    clean_obj = json.loads(clean_text)
    mock_agent = _make_mock_crewai(clean_obj)
    intake = IntakeAgent(crewai_agent=mock_agent)
    case = intake.parse_request(clean_text)
    assert case is not None
    dumped = case.model_dump(mode="json")
    # No empty strings, no None for the required scalars.
    assert dumped["case_id"], dumped
    assert dumped["buyer"], dumped
    assert dumped["vendor_name"], dumped
    assert dumped["vendor_id"], dumped
    assert dumped["amount_eur"] > 0, dumped
    assert dumped["category"], dumped
    assert dumped["requested_action"], dumped
    # attachments is a list; urgency is one of {standard, urgent, emergency}.
    assert isinstance(dumped["attachments"], list), dumped
    assert dumped["attachments"], dumped
    assert dumped["urgency"] in {"standard", "urgent", "emergency"}, dumped


def test_parse_clean_fixture_posts_thought_to_band() -> None:
    """AC-2.3: parsed case is posted to Band via send_event(message_type='thought')."""
    clean_text = _load_fixture("procurement_clean.json")
    clean_obj = json.loads(clean_text)
    mock_agent = _make_mock_crewai(clean_obj)
    mock_tools = MagicMock()
    intake = IntakeAgent(crewai_agent=mock_agent)
    case = intake.parse_request(clean_text)
    assert case is not None
    result = intake.post_to_band(case, mock_tools)
    # send_event was called exactly once with message_type='thought'.
    assert mock_tools.send_event.call_count == 1, mock_tools.send_event.call_args_list
    kwargs = mock_tools.send_event.call_args.kwargs
    assert kwargs["message_type"] == "thought", kwargs
    # The posted content is the ProcurementCase as JSON.
    posted = json.loads(kwargs["content"])
    assert posted["case_id"] == "PC-2026-0001", posted
    # Metadata addresses @vendor-researcher.
    assert kwargs["metadata"]["to"] == "vendor-researcher", kwargs


# ---------------------------------------------------------------------------
# AC-2.5 — 1 violation fixture + 3 violation fixture produce valid schema
# ---------------------------------------------------------------------------


def test_parse_violations_fixture_emits_valid_case() -> None:
    """AC-2.5: the 3-violation fixture (shell company + sanctions-adjacent
    + missing COI) still parses as a valid ProcurementCase — violations
    are downstream concerns (vendor-researcher catches them), not intake.
    """
    violations_text = _load_fixture("procurement_violations.json")
    violations_obj = json.loads(violations_text)
    mock_agent = _make_mock_crewai(violations_obj)
    intake = IntakeAgent(crewai_agent=mock_agent)
    case = intake.parse_request(violations_text)
    assert case is not None, "intake must NOT block on downstream violations"
    dumped = case.model_dump(mode="json")
    # All 9 fields are populated.
    assert dumped["case_id"] == "PC-2026-0002", dumped
    assert dumped["amount_eur"] == 487500.0, dumped
    assert dumped["urgency"] == "urgent", dumped
    assert dumped["category"] == "consulting_services", dumped


def test_parse_violations_1_case_emits_valid_case() -> None:
    """AC-2.5: a 1-violation case still produces valid schema.

    We synthesize a 1-violation fixture inline (shell-company vendor
    with missing COI declaration) and confirm intake parses it
    successfully. Vendor-researcher will flag the violation
    downstream; intake's job is only the schema.
    """
    one_violation = {
        "case_id": "PC-2026-0003",
        "buyer": "Stark Industries EU Sp.z.o.o.",
        "vendor_name": "Quick Shelf LLC",
        "vendor_id": "US-DE-2026-NEW",
        "amount_eur": 24000.00,
        "category": "office_supplies",
        "requested_action": "approve",
        "attachments": [],
        "urgency": "standard",
    }
    mock_agent = _make_mock_crewai(one_violation)
    intake = IntakeAgent(crewai_agent=mock_agent)
    raw = json.dumps(one_violation, sort_keys=True)
    case = intake.parse_request(raw)
    assert case is not None
    assert case.case_id == "PC-2026-0003"
    assert case.vendor_id == "US-DE-2026-NEW"


# ---------------------------------------------------------------------------
# AC-2.4 — Malformed input -> error event, case does NOT advance
# ---------------------------------------------------------------------------


def test_parse_malformed_input_returns_none() -> None:
    """AC-2.4: malformed input returns None — caller posts an error event."""
    mock_agent = MagicMock()
    intake = IntakeAgent(crewai_agent=mock_agent)
    # Garbage non-JSON string with no extractable fields.
    case = intake.parse_request("just a bunch of words with no structure xyzzy")
    assert case is None, case


def test_parse_empty_input_returns_none() -> None:
    """AC-2.4: empty/whitespace input returns None."""
    mock_agent = MagicMock()
    intake = IntakeAgent(crewai_agent=mock_agent)
    assert intake.parse_request("") is None
    assert intake.parse_request("   \n  ") is None


def test_parse_bytes_with_invalid_utf8_returns_none() -> None:
    """AC-2.4: bytes that fail UTF-8 decode return None."""
    mock_agent = MagicMock()
    intake = IntakeAgent(crewai_agent=mock_agent)
    case = intake.parse_request(b"\xff\xfe\xfd invalid utf-8 \xc3\x28")
    assert case is None


def test_parse_schema_violation_returns_none() -> None:
    """AC-2.4: JSON missing required fields returns None (schema gate).

    The LLM returns JSON but the schema validator rejects it because
    amount_eur is missing. Caller MUST post an error event and the
    case MUST NOT advance.
    """
    incomplete_obj = {
        "case_id": "PC-2026-9999",
        "buyer": "Test Buyer",
        # vendor_name MISSING
        "vendor_id": "X-1",
        "amount_eur": 100.0,
        "category": "office_supplies",
        "requested_action": "approve",
        "attachments": [],
        "urgency": "standard",
    }
    mock_agent = _make_mock_crewai(incomplete_obj)
    intake = IntakeAgent(crewai_agent=mock_agent)
    case = intake.parse_request(json.dumps(incomplete_obj))
    assert case is None, case


def test_post_error_to_band_uses_error_message_type() -> None:
    """AC-2.4: post_error_to_band calls send_event(message_type='error')."""
    mock_agent = MagicMock()
    mock_tools = MagicMock()
    intake = IntakeAgent(crewai_agent=mock_agent)
    result = intake.post_error_to_band(
        raw="garbage input",
        reason="schema validation failed",
        tools=mock_tools,
    )
    assert mock_tools.send_event.call_count == 1, mock_tools.send_event.call_args_list
    kwargs = mock_tools.send_event.call_args.kwargs
    assert kwargs["message_type"] == "error", kwargs
    body = json.loads(kwargs["content"])
    assert body["reason"] == "schema validation failed", body
    assert "garbage input" in body["raw_preview"], body
    # Metadata identifies the error envelope.
    assert kwargs["metadata"]["schema"] == "IntakeError", kwargs
    assert kwargs["metadata"]["to"] == "vendor-researcher", kwargs


def test_malformed_input_does_not_advance_case() -> None:
    """AC-2.4: malformed input triggers ONLY the error path — no thought event.

    The full error contract: when parse_request returns None, the
    orchestrator MUST call post_error_to_band and MUST NOT call
    post_to_band. We simulate the orchestrator's branching and assert
    that exactly one send_event was issued, and it was message_type='error'.
    """
    mock_agent = MagicMock()
    mock_tools = MagicMock()
    intake = IntakeAgent(crewai_agent=mock_agent)

    case = intake.parse_request("@@@ not a procurement request @@@")
    assert case is None

    # The orchestrator's branching logic (mirrored here from the S-02
    # story): if case is None, post error; else post the parsed case.
    if case is None:
        intake.post_error_to_band(
            raw="@@@ not a procurement request @@@",
            reason="schema validation failed",
            tools=mock_tools,
        )
    else:  # pragma: no cover — defensive
        intake.post_to_band(case, mock_tools)

    # Exactly one event was sent, and it was an error.
    assert mock_tools.send_event.call_count == 1
    kwargs = mock_tools.send_event.call_args.kwargs
    assert kwargs["message_type"] == "error", kwargs


# ---------------------------------------------------------------------------
# Hard-rule #2: every public function has at least one test.
# ---------------------------------------------------------------------------


def test_load_secrets_reads_aiml_keys() -> None:
    """Every public function must have a test. load_secrets -> AIML keys."""
    secrets = load_secrets()
    assert "AIML_API_KEY" in secrets
    assert "AIML_API_BASE_URL" in secrets
