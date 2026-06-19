"""S-09: ApprovalManager agent tests (5 ACs total, >=6 tests).

Tests are organized as 1+ test per AC plus integration coverage:

* test_build_approval_llm_targets_aiml_api             (AC-9.1)
* test_build_approval_llm_uses_claude_sonnet_4_6       (AC-9.1)
* test_build_crewai_agent_uses_approval_role           (AC-9.1)
* test_decision_memo_schema_has_required_fields        (AC-9.2)
* test_decision_memo_validator_rejects_unknown_verdict (AC-9.2)
* test_decision_memo_validates_eu_ai_act_art12         (AC-9.2 + AC-9.3)
* test_render_memo_pdf_writes_all_art12_fields         (AC-9.3)
* test_render_memo_pdf_embeds_qr_code_to_verify        (AC-9.3)
* test_render_memo_pdf_contains_blake3_chain_root      (AC-9.3)
* test_render_memo_pdf_contains_c2pa_manifest          (AC-9.3)
* test_request_human_signoff_uses_task_message_type    (AC-9.4)
* test_request_human_signoff_blocks_until_approved     (AC-9.4)
* test_approve_with_valid_code_releases_gate           (AC-9.4)
* test_approve_with_invalid_code_does_not_release      (AC-9.4)
* test_signoff_request_metadata_requires_signoff       (AC-9.4)
* test_emit_vouched_event_uses_vouched_message_type    (AC-9.5)
* test_emit_vouched_event_content_has_vouched_true     (AC-9.5)
* test_run_full_pipeline_closes_case_with_vouched      (AC-9.5 + integration)

Every public function in approval_manager.py has at least one test
(hard rule #2). The CrewAI Agent is mocked with
``unittest.mock.MagicMock`` per hint #5 — no network calls in tests.
PDF generation runs against ``reportlab`` in-process; the QR code is
verified by inspecting the rendered PDF byte stream for the embedded
PNG (PDFs with a single Image XObject reference ``/XObject ... /Im0``
in their content stream).
"""

from __future__ import annotations

import base64
import io
import json
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pdfplumber
import pytest

THIS_DIR = Path(__file__).resolve().parent
SRC_DIR = THIS_DIR.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from approval_manager import (  # noqa: E402
    ApprovalManager,
    C2paManifest,
    DEFAULT_AGENT_ROLE,
    DEFAULT_MODEL,
    DEFAULT_VALID_CODE,
    DEFAULT_VERIFY_URL,
    DecisionMemo,
    EuAiActArt12,
    EU_AI_ACT_ART12_FIELDS,
    HumanRole,
    PDF_RENDERER,
    build_approval_llm,
    build_crewai_agent,
    emit_vouched_event,
    parse_memo_payload,
    render_memo_pdf,
    request_human_signoff,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _sample_art12() -> EuAiActArt12:
    return EuAiActArt12(
        start_time="2026-06-18T10:00:00+00:00",
        end_time="2026-06-18T10:15:00+00:00",
        reference_database="stanford-invoicenet-50",
        input_data="PC-2026-0001",
        natural_person_id="operator@apohara.dev",
        decision_id="11111111-1111-1111-1111-111111111111",
        policy_version="apohara-vouch-1",
        hash_chain_prev="0" * 64,
    )


def _sample_c2pa() -> C2paManifest:
    return C2paManifest(
        manifest_id="m-001",
        claim_generator="approval-manager",
        algorithm="Ed25519+BLAKE3",
        claim_hex="a" * 128,
    )


def _sample_memo(
    *,
    verdict: str = "Approve",
    confidence: float = 0.92,
    required_signoffs: list[HumanRole] | None = None,
) -> DecisionMemo:
    return DecisionMemo(
        verdict=verdict,
        confidence=confidence,
        rationale="All four upstream findings agree; risk below threshold.",
        citations=[
            "EU Directive 2014/24/EU Art. 56",
            "vouch-orchestrator/finding-3",
        ],
        required_signoffs=required_signoffs or [HumanRole.PROCUREMENT_LEAD],
        case_id="PC-2026-0001",
        eu_ai_act_art12=_sample_art12(),
        c2pa_manifest=_sample_c2pa(),
        blake3_chain_root="d" * 64,
        packet_hash="abc123",
    )


def _make_mock_crewai(memo: DecisionMemo) -> MagicMock:
    """Mock CrewAI Agent whose kickoff returns a JSON DecisionMemo."""
    mock_agent = MagicMock()
    result = MagicMock()
    result.raw = memo.model_dump_json()
    mock_agent.kickoff.return_value = result
    return mock_agent


def _pdf_text(pdf_bytes: bytes) -> str:
    """Extract text from a (possibly compressed) PDF via pdfplumber."""
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        return "\n".join((page.extract_text() or "") for page in pdf.pages)


# ---------------------------------------------------------------------------
# AC-9.1 — CrewAI Agent on AI/ML API Sonnet 4.6
# ---------------------------------------------------------------------------


def test_build_approval_llm_targets_aiml_api() -> None:
    """AC-9.1: LLM is built against AIML API base_url with claude-sonnet-4-6."""
    llm = build_approval_llm(
        secrets={
            "AIML_API_KEY": "test-key",
            "AIML_API_BASE_URL": "https://api.aimlapi.com/v1",
        }
    )
    assert "claude-sonnet-4-6" in llm.model, llm.model
    assert "openai/" in llm.model, llm.model  # LiteLLM routing prefix
    assert "aimlapi.com" in str(llm.base_url), llm.base_url
    assert llm.api_key == "test-key", llm.api_key


def test_build_approval_llm_uses_default_model() -> None:
    """AC-9.1: default model is claude-sonnet-4-6 (matches the S-09 plan)."""
    llm = build_approval_llm(
        secrets={
            "AIML_API_KEY": "test-key",
            "AIML_API_BASE_URL": "https://api.aimlapi.com/v1",
        }
    )
    assert llm.model == f"openai/{DEFAULT_MODEL}", llm.model


def test_build_crewai_agent_uses_approval_role() -> None:
    """AC-9.1: Agent is wired with role='approval-manager' + the AIML LLM."""
    llm = build_approval_llm(
        secrets={
            "AIML_API_KEY": "test-key",
            "AIML_API_BASE_URL": "https://api.aimlapi.com/v1",
        }
    )
    agent = build_crewai_agent(llm=llm)
    assert agent.role == DEFAULT_AGENT_ROLE, agent.role
    assert "DecisionMemo" in agent.goal, agent.goal
    assert "approval manager" in agent.backstory.lower(), agent.backstory
    assert agent.llm is llm, agent.llm


# ---------------------------------------------------------------------------
# AC-9.2 — DecisionMemo schema
# ---------------------------------------------------------------------------


def test_decision_memo_schema_has_required_fields() -> None:
    """AC-9.2: DecisionMemo has verdict, confidence, rationale, citations,
    required_signoffs (+ the AC-9.3 crypto + Art. 12 fields)."""
    expected = {
        "verdict",
        "confidence",
        "rationale",
        "citations",
        "required_signoffs",
        "case_id",
        "eu_ai_act_art12",
        "c2pa_manifest",
        "blake3_chain_root",
        "packet_hash",
    }
    actual = set(DecisionMemo.model_fields.keys())
    assert expected.issubset(actual), (expected - actual, actual)


def test_decision_memo_validator_rejects_unknown_verdict() -> None:
    """AC-9.2: verdict is constrained to the 4 legal values."""
    with pytest.raises(Exception):
        DecisionMemo(
            verdict="Approveish",  # type: ignore[arg-type]
            confidence=0.5,
            rationale="x",
            citations=[],
            required_signoffs=[],
            case_id="PC-2026-0001",
            eu_ai_act_art12=_sample_art12(),
            c2pa_manifest=_sample_c2pa(),
            blake3_chain_root="d" * 64,
            packet_hash="abc",
        )


def test_decision_memo_validator_rejects_out_of_range_confidence() -> None:
    """AC-9.2: confidence must be in [0.0, 1.0]."""
    with pytest.raises(Exception):
        DecisionMemo(
            verdict="Approve",
            confidence=1.5,
            rationale="x",
            citations=[],
            required_signoffs=[],
            case_id="PC-2026-0001",
            eu_ai_act_art12=_sample_art12(),
            c2pa_manifest=_sample_c2pa(),
            blake3_chain_root="d" * 64,
            packet_hash="abc",
        )


def test_decision_memo_accepts_all_four_verdicts() -> None:
    """AC-9.2: every verdict in the Literal is accepted."""
    for v in ("Approve", "Conditional", "Reject", "Escalate"):
        memo = _sample_memo(verdict=v)  # type: ignore[arg-type]
        assert memo.verdict == v, v


def test_parse_memo_payload_strips_json_fences() -> None:
    """AC-9.2: parse_memo_payload tolerates ```json ... ``` fences
    (common CrewAI kickoff shape)."""
    wrapped = "```json\n" + json.dumps({"k": 1}) + "\n```"
    assert parse_memo_payload(wrapped) == {"k": 1}


# ---------------------------------------------------------------------------
# AC-9.3 — One-page PDF: 8 EU AI Act Art. 12 fields + chain root + C2PA + QR
# ---------------------------------------------------------------------------


def test_render_memo_pdf_returns_pdf_bytes(tmp_path: Path) -> None:
    """AC-9.3: render_memo_pdf writes a real PDF and returns bytes."""
    memo = _sample_memo()
    out = tmp_path / "memo.pdf"
    pdf_bytes = render_memo_pdf(memo, pdf_out=out)
    assert out.exists(), out
    assert pdf_bytes[:5] == b"%PDF-", pdf_bytes[:16]
    assert out.read_bytes() == pdf_bytes


def test_render_memo_pdf_writes_all_art12_fields(tmp_path: Path) -> None:
    """AC-9.3: every one of the 8 EU AI Act Art. 12 fields appears
    in the PDF body."""
    memo = _sample_memo()
    out = tmp_path / "memo.pdf"
    pdf_bytes = render_memo_pdf(memo, pdf_out=out)
    text = _pdf_text(pdf_bytes)
    art12 = memo.eu_ai_act_art12
    for f in EU_AI_ACT_ART12_FIELDS:
        # The column header is the field name; the value is rendered too.
        assert f in text, f"missing field header {f!r} in PDF: {text!r}"
        value = getattr(art12, f)
        if value:
            # Use a stable substring to avoid reportlab text-shaping issues.
            snippet = value[:10]
            assert snippet in text, (
                f"missing value snippet {snippet!r} for {f} in PDF"
            )


def test_render_memo_pdf_contains_blake3_chain_root(tmp_path: Path) -> None:
    """AC-9.3: BLAKE3 chain root is embedded in the PDF."""
    memo = _sample_memo()
    out = tmp_path / "memo.pdf"
    pdf_bytes = render_memo_pdf(memo, pdf_out=out)
    text = _pdf_text(pdf_bytes)
    assert "BLAKE3 chain root" in text, text[:500]
    # First 8 hex chars of the chain root must appear.
    assert "dddddddd" in text, "BLAKE3 chain root value not rendered"


def test_render_memo_pdf_contains_c2pa_manifest(tmp_path: Path) -> None:
    """AC-9.3: C2PA manifest id + algorithm + claim generator are embedded."""
    memo = _sample_memo()
    out = tmp_path / "memo.pdf"
    pdf_bytes = render_memo_pdf(memo, pdf_out=out)
    text = _pdf_text(pdf_bytes)
    c2pa = memo.c2pa_manifest
    assert c2pa.manifest_id in text, f"C2PA manifest id missing: {text!r}"
    assert c2pa.algorithm in text, "C2PA algorithm missing"
    assert c2pa.claim_generator in text, "C2PA claim generator missing"


def test_render_memo_pdf_embeds_qr_code_to_verify(tmp_path: Path) -> None:
    """AC-9.3: QR code target URL points at vouch-verify (per hint #4)."""
    memo = _sample_memo()
    out = tmp_path / "memo.pdf"
    pdf_bytes = render_memo_pdf(memo, pdf_out=out)
    # The PDF contains an inline PNG image (the QR code). reportlab
    # embeds images via the /XObject resource.
    assert b"/Subtype /Image" in pdf_bytes or b"/Subtype/Image" in pdf_bytes, (
        "no /Image XObject in PDF"
    )
    text = _pdf_text(pdf_bytes)
    expected_url = f"{DEFAULT_VERIFY_URL}?packet={memo.packet_hash}"
    assert expected_url in text, f"vouch-verify URL missing: {expected_url}"


def test_render_memo_pdf_uses_reportlab() -> None:
    """Documented deviation: PDF renderer is reportlab (no Rust binary)."""
    assert PDF_RENDERER == "reportlab", PDF_RENDERER


# ---------------------------------------------------------------------------
# AC-9.4 — Human sign-off gate (message_type='task', blocks on Event)
# ---------------------------------------------------------------------------


def test_request_human_signoff_uses_task_message_type() -> None:
    """AC-9.4: send_event is invoked with message_type='task'."""
    memo = _sample_memo()
    mock_tools = MagicMock()
    gate = threading.Event()

    def _release() -> None:
        gate.set()

    threading.Thread(target=_release, daemon=True).start()

    result = request_human_signoff(memo, tools=mock_tools, gate=gate)
    assert result["opened"] is True, result
    assert mock_tools.send_event.call_count == 1
    kwargs = mock_tools.send_event.call_args.kwargs
    assert kwargs["message_type"] == "task", kwargs
    assert kwargs["metadata"]["requires_signoff"] is True, kwargs
    assert kwargs["metadata"]["to"] == "human-procurement-lead", kwargs


def test_request_human_signoff_blocks_until_approved() -> None:
    """AC-9.4: the call does not return until the gate is released."""
    memo = _sample_memo()
    mock_tools = MagicMock()
    gate = threading.Event()

    def _release_later() -> None:
        time.sleep(0.1)
        gate.set()

    threading.Thread(target=_release_later, daemon=True).start()
    started = time.monotonic()
    result = request_human_signoff(memo, tools=mock_tools, gate=gate)
    elapsed = time.monotonic() - started
    assert result["opened"] is True, result
    assert elapsed >= 0.05, f"returned too fast: {elapsed:.3f}s"


def test_request_human_signoff_times_out_when_no_approval() -> None:
    """AC-9.4: with signoff_timeout_s>0 and no approval, returns timed_out."""
    memo = _sample_memo()
    mock_tools = MagicMock()
    gate = threading.Event()
    result = request_human_signoff(
        memo,
        tools=mock_tools,
        gate=gate,
        signoff_timeout_s=0.1,
    )
    assert result["opened"] is False, result
    assert result["timed_out"] is True, result


def test_request_human_signoff_carries_pdf_in_metadata() -> None:
    """AC-9.4: PDF is base64-encoded into the metadata for in-band download."""
    memo = _sample_memo()
    mock_tools = MagicMock()
    gate = threading.Event()
    gate.set()  # release immediately
    pdf_bytes = b"%PDF-1.4\n%fake\n%%EOF"
    request_human_signoff(
        memo, tools=mock_tools, gate=gate, pdf_bytes=pdf_bytes
    )
    kwargs = mock_tools.send_event.call_args.kwargs
    assert kwargs["metadata"]["pdf_b64"] == base64.b64encode(pdf_bytes).decode(
        "ascii"
    )


def test_approve_with_valid_code_releases_gate() -> None:
    """AC-9.4: approve(code) with a valid code opens the gate."""
    manager = ApprovalManager(valid_codes=("OK",))
    mock_tools = MagicMock()

    # request_signoff would block forever without a release — instead
    # we exercise the gate directly.
    manager._reset_gate()
    gate = manager._signoff_event

    def _release() -> None:
        time.sleep(0.05)
        manager.approve("OK", role=HumanRole.PROCUREMENT_LEAD)

    threading.Thread(target=_release, daemon=True).start()
    opened = gate.wait(timeout=2.0)
    assert opened is True
    assert manager._accepted_code == "OK"
    assert manager._accepted_role == HumanRole.PROCUREMENT_LEAD


def test_approve_with_invalid_code_does_not_release_gate() -> None:
    """AC-9.4: an unknown code does NOT open the gate."""
    manager = ApprovalManager(valid_codes=("OK",))
    manager._reset_gate()
    released = manager.approve("WRONG")
    assert released is False
    assert not manager._signoff_event.is_set()


# ---------------------------------------------------------------------------
# AC-9.5 — vouched: true event closes the case
# ---------------------------------------------------------------------------


def test_emit_vouched_event_uses_vouched_message_type() -> None:
    """AC-9.5: send_event is invoked with message_type='vouched'."""
    memo = _sample_memo()
    mock_tools = MagicMock()
    payload = emit_vouched_event(
        memo, tools=mock_tools, approver_code=DEFAULT_VALID_CODE
    )
    assert mock_tools.send_event.call_count == 1
    kwargs = mock_tools.send_event.call_args.kwargs
    assert kwargs["message_type"] == "vouched", kwargs
    assert kwargs["metadata"]["to"] == "all", kwargs
    assert payload["metadata"]["case_id"] == "PC-2026-0001"


def test_emit_vouched_event_content_has_vouched_true() -> None:
    """AC-9.5: payload content is ``{"vouched": true, ...}``."""
    memo = _sample_memo()
    mock_tools = MagicMock()
    emit_vouched_event(memo, tools=mock_tools)
    kwargs = mock_tools.send_event.call_args.kwargs
    content = json.loads(kwargs["content"])
    assert content["vouched"] is True, content
    assert content["case_id"] == memo.case_id, content
    assert content["verdict"] == memo.verdict, content


# ---------------------------------------------------------------------------
# Integration — end-to-end ApprovalManager.run()
# ---------------------------------------------------------------------------


def test_run_full_pipeline_closes_case_with_vouched(tmp_path: Path) -> None:
    """End-to-end: synthesize memo → render PDF → request sign-off
    (auto-released by approve()) → emit vouched event."""
    memo = _sample_memo()
    mock_agent = _make_mock_crewai(memo)
    mock_tools = MagicMock()
    manager = ApprovalManager(crewai_agent=mock_agent)

    out = tmp_path / "memo.pdf"
    result = manager.run(
        packet={"case_id": memo.case_id, "summary": "demo"},
        tools=mock_tools,
        pdf_out=out,
        approver_code=DEFAULT_VALID_CODE,
        approver_role=HumanRole.PROCUREMENT_LEAD,
    )

    # PDF rendered
    assert out.exists()
    assert result["pdf_bytes"][:5] == b"%PDF-"
    # Memo parsed
    assert result["memo"].case_id == memo.case_id
    # Sign-off request posted (message_type='task')
    assert result["signoff_request"]["opened"] is True
    # Vouched event posted (message_type='vouched')
    vouched = result["vouched_event"]
    assert vouched["metadata"]["case_id"] == memo.case_id

    # Inspect every send_event call: at least one 'task' + one 'vouched'.
    types = [
        c.kwargs.get("message_type")
        for c in mock_tools.send_event.call_args_list
    ]
    assert "task" in types, types
    assert "vouched" in types, types
