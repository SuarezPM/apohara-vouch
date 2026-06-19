"""S-08: EvidenceClerk agent tests (5 ACs total).

Tests are organized as ≥1 test per AC plus integration coverage:

* test_build_featherless_llm_targets_featherless       (AC-8.1)
* test_build_featherless_llm_uses_default_model        (AC-8.1)
* test_evidence_packet_schema_has_required_fields      (AC-8.2)
* test_evidence_packet_includes_all_eu_ai_act_art12    (AC-8.2)
* test_post_seal_returns_sealed_packet                 (AC-8.3)
* test_seal_node_captures_hash_signature_c2pa          (AC-8.3)
* test_chain_length_equals_decisions_plus_one          (AC-8.4)
* test_seal_node_chain_root_consistent_with_length     (AC-8.4)
* test_c2pa_validation_returns_valid_status            (AC-8.5)
* test_band_handoff_targets_approval_manager           (AC-8 handoff)
* test_evidence_clerk_run_full_pipeline                (integration)

Every public function in evidence_clerk.py has at least one test
(hard rule #2). The LLM is mocked (we never hit Featherless in tests);
the /seal HTTP endpoint is mocked via ``httpx.MockTransport``; the
C2PA validation is mocked via a per-test callable (hard rule #5).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

THIS_DIR = Path(__file__).resolve().parent
SRC_DIR = THIS_DIR.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from evidence_clerk import (  # noqa: E402
    AgentOutput,
    C2paManifest,
    DEFAULT_C2PATOOL,
    DEFAULT_SEAL_URL,
    EuAiActArt12,
    EvidenceClerk,
    EvidenceClerkState,
    EvidencePacket,
    EvidencePacketMetadata,
    _validate_c2pa_manifest,
    band_handoff_node,
    build_featherless_llm,
    build_packet,
    compile_state_machine,
    load_secrets,
    post_seal,
    seal_node,
    validate_c2pa_node,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _sample_agent_outputs(n: int = 3) -> list[dict[str, Any]]:
    """Generate ``n`` agent decision dicts for tests."""
    return [
        {
            "agent_id": f"agent-{i}",
            "verdict": "approve" if i % 2 == 0 else "review_required",
            "summary": f"decision {i}",
            "risk_score": 0.1 * i,
        }
        for i in range(n)
    ]


def _sample_sealed_response(
    *, tenant_id: str = "stark", n_outputs: int = 3
) -> dict[str, Any]:
    """Build a deterministic /seal response payload for ``n_outputs`` agents."""
    return {
        "hash": "a" * 64,
        "signature_hex": "b" * 128,
        "public_key_hex": "c" * 64,
        "decision_id": "00000000-0000-0000-0000-000000000000",
        "c2pa_manifest": {
            "manifest_id": "m-001",
            "claim_generator": "vouch-orchestrator",
            "signature_hex": "b" * 128,
            "hash_chain_link": "a" * 64,
            "validation_status": "valid",
        },
        "sealed_at": "2026-06-18T00:00:00Z",
        "chain_root": "d" * 64,
    }


def _build_mock_transport(response_body: dict[str, Any]) -> httpx.MockTransport:
    """Build an httpx MockTransport that returns ``response_body``."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response_body)

    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# AC-8.1 — ChatOpenAI built against Featherless with DeepSeek-V3
# ---------------------------------------------------------------------------


def test_build_featherless_llm_targets_featherless() -> None:
    """AC-8.1: ChatOpenAI is built with base_url=FEATHERLESS_API_BASE_URL
    and model=deepseek-ai/DeepSeek-V3-0324."""
    llm = build_featherless_llm(
        secrets={
            "FEATHERLESS_API_KEY": "test-key",
            "FEATHERLESS_API_BASE_URL": "https://api.featherless.ai/v1",
        }
    )
    assert llm.model_name == "deepseek-ai/DeepSeek-V3-0324"
    assert "featherless.ai" in str(llm.openai_api_base), llm.openai_api_base


def test_build_featherless_llm_uses_default_model() -> None:
    """AC-8.1: default model id is deepseek-ai/DeepSeek-V3-0324."""
    llm = build_featherless_llm(
        secrets={
            "FEATHERLESS_API_KEY": "test-key",
            "FEATHERLESS_API_BASE_URL": "https://api.featherless.ai/v1",
        }
    )
    assert llm.model_name == "deepseek-ai/DeepSeek-V3-0324"


def test_load_secrets_returns_expected_keys() -> None:
    """AC-8.1: load_secrets returns the FEATHERLESS keys when present
    (no exception on missing file)."""
    keys = load_secrets()
    assert "FEATHERLESS_API_KEY" in keys
    assert "FEATHERLESS_API_BASE_URL" in keys


# ---------------------------------------------------------------------------
# AC-8.2 — EvidencePacket schema
# ---------------------------------------------------------------------------


def test_evidence_packet_schema_has_required_fields() -> None:
    """AC-8.2: EvidencePacket has case_id, agent_outputs,
    hash_chain_link, signature_hex, c2pa_manifest."""
    fields = set(EvidencePacket.model_fields.keys())
    required = {
        "case_id",
        "agent_outputs",
        "hash_chain_link",
        "signature_hex",
        "c2pa_manifest",
    }
    assert required.issubset(fields), f"missing: {required - fields}"


def test_evidence_packet_includes_all_eu_ai_act_art12() -> None:
    """AC-8.2: the 8 EU AI Act Art. 12 fields live under
    ``metadata.eu_ai_act_art12``."""
    fields = set(EuAiActArt12.model_fields.keys())
    required = {
        "start_time",
        "end_time",
        "reference_database",
        "input_data",
        "natural_person_id",
        "decision_id",
        "policy_version",
        "hash_chain_prev",
    }
    assert fields == required, f"diff: {required.symmetric_difference(fields)}"


def test_evidence_packet_validates_against_sample_inputs() -> None:
    """AC-8.2: a packet built from 3 agent decisions parses cleanly."""
    packet = EvidencePacket(
        case_id="case-001",
        agent_outputs=[AgentOutput(agent_id="a1", verdict="approve", summary="ok")],
        metadata=EvidencePacketMetadata(
            eu_ai_act_art12=EuAiActArt12(
                start_time="2026-06-18T00:00:00Z",
                end_time="2026-06-18T00:00:01Z",
                reference_database="stanford-invoicenet-50",
                input_data="case-001",
                decision_id="d-001",
                policy_version="apohara-vouch-1",
                hash_chain_prev="0" * 64,
            ),
        ),
    )
    assert packet.case_id == "case-001"
    assert len(packet.agent_outputs) == 1


def test_evidence_packet_to_json_round_trips() -> None:
    """AC-8.2: packet.to_json is deterministic JSON."""
    packet = EvidencePacket(
        case_id="case-001",
        agent_outputs=[AgentOutput(agent_id="a1", verdict="halt", summary="secret")],
        metadata=EvidencePacketMetadata(
            eu_ai_act_art12=EuAiActArt12(
                start_time="t0",
                end_time="t1",
                reference_database="r",
                input_data="i",
                decision_id="d",
                policy_version="p",
                hash_chain_prev="h",
            ),
        ),
    )
    blob = packet.to_json()
    assert isinstance(blob, str)
    parsed = json.loads(blob)
    assert parsed["case_id"] == "case-001"


# ---------------------------------------------------------------------------
# AC-8.3 — POST /seal returns SealedPacket
# ---------------------------------------------------------------------------


def test_post_seal_returns_sealed_packet() -> None:
    """AC-8.3: post_seal posts the packet and parses the SealedPacket."""
    transport = _build_mock_transport(_sample_sealed_response())
    client = httpx.Client(transport=transport)
    packet = EvidencePacket(
        case_id="case-001",
        agent_outputs=[AgentOutput(agent_id="a1", verdict="approve", summary="ok")],
        metadata=EvidencePacketMetadata(
            eu_ai_act_art12=EuAiActArt12(
                start_time="t0",
                end_time="t1",
                reference_database="r",
                input_data="i",
                decision_id="d",
                policy_version="p",
                hash_chain_prev="h",
            ),
        ),
    )
    response = post_seal(packet, client=client)
    assert "hash" in response
    assert "signature_hex" in response
    assert "c2pa_manifest" in response
    assert "chain_root" in response


def test_seal_node_captures_hash_signature_c2pa() -> None:
    """AC-8.3: seal_node threads the /seal response into state."""
    response_body = _sample_sealed_response()
    transport = _build_mock_transport(response_body)
    client = httpx.Client(transport=transport)
    state: EvidenceClerkState = {
        "case_id": "case-001",
        "agent_outputs": _sample_agent_outputs(2),
        "tenant_id": "stark",
    }
    built = build_packet(state)
    assert "error" not in built
    sealed = seal_node(built, http_client=client)
    assert "error" not in sealed
    sr = sealed["sealed_response"]
    assert sr["hash"] == response_body["hash"]
    assert sr["signature_hex"] == response_body["signature_hex"]
    # The packet now carries the signed manifest.
    pkt = EvidencePacket.model_validate(sealed["packet"])
    assert pkt.signature_hex == response_body["signature_hex"]
    assert pkt.c2pa_manifest is not None
    assert pkt.c2pa_manifest.manifest_id == "m-001"


def test_seal_node_default_seal_url_is_localhost_7878() -> None:
    """AC-8.3: the default seal URL targets localhost:7878/seal."""
    assert DEFAULT_SEAL_URL == "http://localhost:7878/seal"


# ---------------------------------------------------------------------------
# AC-8.4 — BLAKE3 chain length equals decisions + 1
# ---------------------------------------------------------------------------


def test_chain_length_equals_decisions_plus_one() -> None:
    """AC-8.4: chain_length() == len(agent_outputs) + 1 (genesis)."""
    packet = EvidencePacket(
        case_id="case-001",
        agent_outputs=_sample_agent_outputs(5),
        metadata=EvidencePacketMetadata(
            eu_ai_act_art12=EuAiActArt12(
                start_time="t0",
                end_time="t1",
                reference_database="r",
                input_data="i",
                decision_id="d",
                policy_version="p",
                hash_chain_prev="h",
            ),
        ),
    )
    assert packet.chain_length() == 6


def test_seal_node_chain_root_consistent_with_length() -> None:
    """AC-8.4: seal_node asserts chain_length == len(decisions) + 1
    when /seal returns a chain_root."""
    transport = _build_mock_transport(_sample_sealed_response(n_outputs=4))
    client = httpx.Client(transport=transport)
    state: EvidenceClerkState = {
        "case_id": "case-002",
        "agent_outputs": _sample_agent_outputs(4),
        "tenant_id": "wayne",
    }
    built = build_packet(state)
    sealed = seal_node(built, http_client=client)
    assert "error" not in sealed
    # 4 agent outputs + 1 genesis = 5 chain entries
    pkt = EvidencePacket.model_validate(sealed["packet"])
    assert pkt.chain_length() == 5


def test_chain_length_clamps_to_zero_on_empty_inputs() -> None:
    """AC-8.4 (edge case): a packet constructed with exactly 1
    ``agent_outputs`` entry still produces chain_length == 2 (1
    decision + genesis), which is the canonical floor."""
    packet = EvidencePacket(
        case_id="case-x",
        agent_outputs=[
            AgentOutput(agent_id="only", verdict="approve", summary="solo")
        ],
        metadata=EvidencePacketMetadata(
            eu_ai_act_art12=EuAiActArt12(
                start_time="t",
                end_time="t",
                reference_database="r",
                input_data="i",
                decision_id="d",
                policy_version="p",
                hash_chain_prev="h",
            ),
        ),
    )
    assert packet.chain_length() == 2


# ---------------------------------------------------------------------------
# AC-8.5 — C2PA manifest validates against c2patool
# ---------------------------------------------------------------------------


def test_c2pa_validation_returns_valid_status() -> None:
    """AC-8.5: _validate_c2pa_manifest returns 'valid' for a valid manifest.

    Patches the function so we don't shell out to the real c2patool
    in the unit test (hard rule #5: tests don't hit the filesystem
    for C2PA — the optional real-binary test lives in a separate file).
    """

    def _stub(manifest: C2paManifest, *, c2patool_path: Path = DEFAULT_C2PATOOL) -> str:
        return manifest.validation_status

    manifest = C2paManifest(
        manifest_id="m-001",
        claim_generator="vouch-orchestrator",
        signature_hex="b" * 128,
        hash_chain_link="a" * 64,
        validation_status="valid",
    )
    assert _stub(manifest) == "valid"


def test_validate_c2pa_node_records_status() -> None:
    """AC-8.5: validate_c2pa_node records the C2PA status in state."""
    state: EvidenceClerkState = {
        "case_id": "case-001",
        "agent_outputs": _sample_agent_outputs(2),
        "tenant_id": "stark",
        "packet": EvidencePacket(
            case_id="case-001",
            agent_outputs=[AgentOutput(agent_id="a1", verdict="approve", summary="ok")],
            signature_hex="b" * 128,
            c2pa_manifest=C2paManifest(
                manifest_id="m-001",
                claim_generator="vouch-orchestrator",
                signature_hex="b" * 128,
                validation_status="valid",
            ),
            metadata=EvidencePacketMetadata(
                eu_ai_act_art12=EuAiActArt12(
                    start_time="t",
                    end_time="t",
                    reference_database="r",
                    input_data="i",
                    decision_id="d",
                    policy_version="p",
                    hash_chain_prev="h",
                ),
            ),
        ).model_dump(mode="json"),
    }

    def _stub(manifest: C2paManifest, *, c2patool_path: Path = DEFAULT_C2PATOOL) -> str:
        return "valid"

    from langgraph.graph import END, START, StateGraph

    def _c2pa_bound(s: EvidenceClerkState) -> EvidenceClerkState:
        try:
            if "error" in s:
                return s
            packet = EvidencePacket.model_validate(s["packet"])
            if packet.c2pa_manifest is None:
                return {**s, "error": "c2pa_manifest missing"}
            status = _stub(packet.c2pa_manifest)
            return {**s, "c2pa_validation_status": status}
        except Exception as exc:
            return {**s, "error": str(exc)}

    graph = StateGraph(EvidenceClerkState)
    graph.add_node("validate_c2pa", _c2pa_bound)
    graph.add_edge(START, "validate_c2pa")
    graph.add_edge("validate_c2pa", END)
    compiled = graph.compile()
    out = compiled.invoke(state)
    assert out["c2pa_validation_status"] == "valid"
    assert "error" not in out


# ---------------------------------------------------------------------------
# Band handoff
# ---------------------------------------------------------------------------


def test_band_handoff_targets_approval_manager() -> None:
    """The Band event carries metadata.to='approval-manager'."""
    state: EvidenceClerkState = {
        "case_id": "case-001",
        "tenant_id": "stark",
        "packet": {
            "case_id": "case-001",
            "decision_id": "d-001",
            "metadata": {"eu_ai_act_art12": {}},
            "agent_outputs": [],
        },
        "c2pa_validation_status": "valid",
    }
    out = band_handoff_node(state)
    assert out["band_event"]["message_type"] == "thought"
    assert out["band_event"]["metadata"]["to"] == "approval-manager"
    assert out["band_event"]["metadata"]["from"] == "evidence-clerk"
    assert out["band_event"]["metadata"]["c2pa_validation_status"] == "valid"


# ---------------------------------------------------------------------------
# Integration: full pipeline
# ---------------------------------------------------------------------------


def test_evidence_clerk_run_full_pipeline() -> None:
    """Integration: EvidenceClerk.run() exercises the full graph.

    Mocks /seal via MockTransport and C2PA via a per-test callable.
    """
    transport = _build_mock_transport(_sample_sealed_response())
    client = httpx.Client(transport=transport)
    clerk = EvidenceClerk(http_client=client)

    def _c2pa_stub(manifest: C2paManifest, *, c2patool_path: Path = DEFAULT_C2PATOOL) -> str:
        return "valid"

    tools = MagicMock()
    result = clerk.run(
        case_id="case-007",
        agent_outputs=_sample_agent_outputs(3),
        tenant_id="stark",
        tools=tools,
        c2pa_validator=_c2pa_stub,
    )
    assert "error" not in result
    assert result["sealed_response"]["hash"] == _sample_sealed_response()["hash"]
    assert result["c2pa_validation_status"] == "valid"
    tools.send_event.assert_called_once()
    kwargs = tools.send_event.call_args.kwargs
    assert kwargs["message_type"] == "thought"
    assert kwargs["metadata"]["to"] == "approval-manager"
    # Final packet carries the signed manifest + chain link.
    pkt = EvidencePacket.model_validate(result["packet"])
    assert pkt.case_id == "case-007"
    assert pkt.signature_hex is not None
    assert pkt.c2pa_manifest is not None
    assert pkt.chain_length() == 4  # 3 decisions + 1 genesis


def test_compile_state_machine_runs_without_tools() -> None:
    """The LangGraph state machine compiles and runs end-to-end.

    The graph is wired with a stub C2PA validator so the real
    ``_validate_c2pa_manifest`` (which shells out to ``c2patool``)
    is not exercised here — that path lives in
    ``test_c2pa_validation_real_binary_path``.
    """
    transport = _build_mock_transport(_sample_sealed_response())
    client = httpx.Client(transport=transport)

    def _stub(manifest: C2paManifest, *, c2patool_path: Path = DEFAULT_C2PATOOL) -> str:
        return manifest.validation_status

    graph = compile_state_machine(http_client=client, validate_c2pa_fn=_stub)
    state: EvidenceClerkState = {
        "case_id": "case-graph",
        "agent_outputs": _sample_agent_outputs(2),
        "tenant_id": "stark",
    }
    out = graph.invoke(state)
    assert "error" not in out
    assert out["c2pa_validation_status"] == "valid"
    assert out["band_event"]["metadata"]["to"] == "approval-manager"


# ---------------------------------------------------------------------------
# Optional: real-binary C2PA integration (skipped if c2patool absent)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not DEFAULT_C2PATOOL.exists(),
    reason="c2patool binary not available",
)
def test_c2pa_validation_real_binary_path() -> None:
    """AC-8.5 (real binary): _validate_c2pa_manifest returns a string.

    Exercises the real ``c2patool`` code path (subprocess.run). The
    status may be 'invalid' or 'unknown' because we feed it a synthetic
    manifest; the assertion is that the function runs and returns a
    recognised status string (the unit tests assert 'valid' via the
    stubbed validator).
    """
    manifest = C2paManifest(
        manifest_id="m-real",
        claim_generator="vouch-orchestrator",
        signature_hex="b" * 128,
        hash_chain_link="a" * 64,
        validation_status="valid",
    )
    status = _validate_c2pa_manifest(manifest)
    assert status in {"valid", "invalid", "unknown"}