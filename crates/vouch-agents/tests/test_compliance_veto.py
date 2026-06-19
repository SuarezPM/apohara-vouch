"""S-07b: Tests for the cross-account Compliance Veto agent.

AC matrix (one test per AC + helpers)
-------------------------------------
* AC-7b.1  test_pydantic_ai_agent_uses_haiku_4_5_via_aiml
* AC-7b.2  test_veto_decision_schema + test_load_second_account_block +
          test_fallback_provides_degraded_mode
* AC-7b.3  test_recruit_compliance_veto_uses_lookup_and_add_participant
* AC-7b.4  test_deterministic_routing_proptest (Hypothesis 100/100)
          + test_node_compliance_escalation_sets_state
* AC-7b.5  covered by tests/test_compliance_fallback_chaos.py
* AC-7b.6  test_participant_metadata_carries_account_id

The chaos harness in test_compliance_fallback_chaos.py is the
AC-7b.5 gate; this file covers AC-7b.1, 7b.2, 7b.3, 7b.4, 7b.6 with
deterministic unit + property tests.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

# Hypothesis is required for AC-7b.4 (100/100 proptest).
from hypothesis import given, settings, strategies as st

THIS_DIR = Path(__file__).resolve().parent
SRC_DIR = THIS_DIR.parent / "src"
ORCH_SRC = (THIS_DIR.parent.parent / "vouch-orchestrator" / "src")
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(ORCH_SRC) not in sys.path:
    sys.path.insert(0, str(ORCH_SRC))

import compliance_veto  # noqa: E402
from compliance_veto import (  # noqa: E402
    ComplianceVeto,
    VetoDecision,
    Verdict,
    RegulatoryClock,
    agent_config_path,
    build_pydantic_ai_agent,
    load_secrets,
    load_second_account,
    recruit_compliance_veto,
)
from compliance_fallback import ComplianceFallback  # noqa: E402
from orchestrator import (  # noqa: E402
    ORCHESTRATOR_STATES,
    OrchestratorState,
    _route_to_compliance_escalation,
    build_state_graph,
    compile_state_machine,
    node_compliance_escalation,
    register_tools,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


class _StubRisk:
    def __init__(self, severity: str) -> None:
        self.severity = severity


class _StubFinding:
    def __init__(self, severity: str) -> None:
        self.severity = severity


class _StubPolicy:
    def __init__(self, findings: list[_StubFinding]) -> None:
        self.findings = findings


class _StubCase:
    def __init__(self, case_id: str, text: str = "") -> None:
        self.case_id = case_id
        self.raw_procurement_request = text


# ---------------------------------------------------------------------------
# AC-7b.1 — Pydantic AI Agent uses claude-haiku-4-5 via AI/ML API
# ---------------------------------------------------------------------------


def test_pydantic_ai_agent_uses_haiku_4_5_via_aiml() -> None:
    """AC-7b.1: the Agent is wired to claude-haiku-4-5 via AI/ML API."""
    import pydantic_ai

    captured: dict[str, Any] = {}

    class _FakeChatModel:
        def __init__(self, model_id: str, provider: Any) -> None:
            captured["model"] = model_id
            captured["provider"] = provider

    class _FakeAgent:
        def __init__(self, model: Any, output_type: Any) -> None:
            captured["agent_model"] = model
            captured["output_type"] = output_type

    class _FakeProvider:
        def __init__(self, base_url: str, api_key: str) -> None:
            captured["base_url"] = base_url
            captured["api_key"] = api_key

    # Monkeypatch the symbols imported inside build_pydantic_ai_agent.
    import pydantic_ai.models.openai as _openai_mod
    import pydantic_ai.providers.openai as _provider_mod

    real_agent = pydantic_ai.Agent
    real_chat = _openai_mod.OpenAIChatModel
    real_provider = _provider_mod.OpenAIProvider
    pydantic_ai.Agent = _FakeAgent  # type: ignore
    _openai_mod.OpenAIChatModel = _FakeChatModel  # type: ignore
    _provider_mod.OpenAIProvider = _FakeProvider  # type: ignore
    try:
        agent = build_pydantic_ai_agent(
            secrets={
                "AIML_API_KEY": "test-haiku-key",
                "AIML_API_BASE_URL": "https://api.aimlapi.com/v1",
            }
        )
    finally:
        pydantic_ai.Agent = real_agent
        _openai_mod.OpenAIChatModel = real_chat
        _provider_mod.OpenAIProvider = real_provider

    assert isinstance(agent, _FakeAgent)
    assert captured["model"] == "claude-haiku-4-5", captured
    assert captured["base_url"] == "https://api.aimlapi.com/v1", captured
    assert captured["api_key"] == "test-haiku-key", captured
    assert captured["output_type"] is VetoDecision, captured


# ---------------------------------------------------------------------------
# AC-7b.2 — VetoDecision schema + second-account block + fallback
# ---------------------------------------------------------------------------


def test_veto_decision_schema() -> None:
    """AC-7b.2: VetoDecision has verdict/reason/regulatory_clock."""
    d = VetoDecision(
        case_id="cv-test-1",
        verdict="veto",
        reason="DORA ICT-risk incident",
        regulatory_clock="DORA-Art-17",
    )
    assert d.verdict in ("veto", "approve")
    assert d.regulatory_clock in ("DORA-Art-17", "GDPR-Art-33", "SOX-404")
    # Deterministic JSON
    j = d.to_json()
    assert json.loads(j)["verdict"] == "veto"
    # Reject malformed
    with pytest.raises(Exception):
        VetoDecision(
            case_id="bad",
            verdict="not-a-verdict",  # type: ignore[arg-type]
            reason="r",
            regulatory_clock="DORA-Art-17",
        )


def test_load_second_account_block() -> None:
    """AC-7b.2: the second_account: block is loadable from agent_config.yaml."""
    cfg = load_second_account()
    assert cfg.get("handle"), cfg
    assert "compliance" in cfg["handle"].lower(), cfg
    assert cfg.get("account_id"), cfg
    assert cfg.get("api_key"), cfg
    assert cfg.get("llm_model") == "claude-haiku-4-5", cfg
    assert cfg.get("cross_account") is True, cfg


def test_fallback_provides_degraded_mode() -> None:
    """AC-7b.2: the local fallback agent emits the same VetoDecision schema."""
    fb = ComplianceFallback()
    decision = fb.evaluate(
        case=_StubCase("cfb-1"),
        risk=_StubRisk("CRITICAL"),
        policy=_StubPolicy([_StubFinding("CRITICAL")]),
    )
    # The fallback lives in a separate module so ``isinstance`` against
    # the primary agent's VetoDecision fails by design. Compare
    # structurally: the plan says "same VetoDecision schema, different
    # transport" — the SCHEMA (verdict/reason/regulatory_clock +
    # fallback flag) is the contract.
    assert decision.__class__.__name__ == "VetoDecision", decision
    assert hasattr(decision, "verdict")
    assert hasattr(decision, "reason")
    assert hasattr(decision, "regulatory_clock")
    assert hasattr(decision, "fallback")
    assert decision.verdict == "veto"
    assert decision.regulatory_clock in (
        "DORA-Art-17",
        "GDPR-Art-33",
        "SOX-404",
    )
    assert decision.fallback is True
    # JSON-serializable (Orchestrator consumes JSON regardless of class)
    j = json.loads(decision.to_json())
    assert j["verdict"] == "veto"
    assert j["fallback"] is True


# ---------------------------------------------------------------------------
# AC-7b.3 — Recruitment via lookup_peers + add_participant
# ---------------------------------------------------------------------------


class _FakeBandTools:
    """Mimics band.testing.fake_tools.FakeAgentTools for recruitment."""

    def __init__(self) -> None:
        self.lookup_calls = 0
        self.added: list[tuple[str, str]] = []

    async def lookup_peers(self) -> list[dict[str, Any]]:
        self.lookup_calls += 1
        return [
            {
                "id": "PLACEHOLDER_compliance_veto_account_id",
                "handle": "@apohara-themis/compliance-veto-acme",
            }
        ]

    async def add_participant(self, identifier: str, role: str) -> None:
        self.added.append((identifier, role))


@pytest.mark.asyncio
async def test_recruit_compliance_veto_uses_lookup_and_add_participant() -> None:
    """AC-7b.3: recruited via thenvoi_lookup_peers + thenvoi_add_participant."""
    tools = _FakeBandTools()
    handle = "@apohara-themis/compliance-veto-acme"
    result = await recruit_compliance_veto(tools, handle)
    assert result["recruited"] is True, result
    assert tools.lookup_calls == 1, tools.lookup_calls
    assert (handle, "regulatory_veto") in tools.added, tools.added


# ---------------------------------------------------------------------------
# AC-7b.4 — Deterministic routing (100/100 Hypothesis proptest)
# ---------------------------------------------------------------------------


_verdict_st = st.sampled_from(["veto", "approve"])
_clock_st = st.sampled_from(["DORA-Art-17", "GDPR-Art-33", "SOX-404"])


@settings(max_examples=100, deadline=None)
@given(
    verdict=st.sampled_from(["veto", "approve", None]),
    clock=st.sampled_from(["DORA-Art-17", "GDPR-Art-33", "SOX-404", None]),
    fallback=st.booleans(),
)
def test_deterministic_routing_proptest(
    verdict: Any, clock: Any, fallback: bool
) -> None:
    """AC-7b.4: 100/100 — routing depends ONLY on verdict=='veto'.

    No matter what clock + fallback flags are set, the routing must
    be True iff ``verdict == "veto"``.
    """
    veto: dict[str, Any] | None
    if verdict is None:
        veto = None
    else:
        veto = {
            "verdict": verdict,
            "reason": "synthetic",
            "regulatory_clock": clock or "SOX-404",
            "fallback": fallback,
        }
    routed = _route_to_compliance_escalation(veto)
    if verdict == "veto":
        assert routed is True
    else:
        assert routed is False


@pytest.mark.asyncio
async def test_node_compliance_escalation_sets_state() -> None:
    """AC-7b.4: node_compliance_escalation sets state + carries verdict."""
    state: OrchestratorState = {
        "state": "REDTEAM",
        "case_id": "case-cv-1",
        "tenant_id": "stark",
        "veto_decision": {
            "verdict": "veto",
            "reason": "GDPR breach",
            "regulatory_clock": "GDPR-Art-33",
        },
    }
    out = await node_compliance_escalation(state)
    assert out["state"] == "COMPLIANCE_ESCALATION", out
    assert out["veto_decision"]["escalated"] is True, out
    transitions = out.get("transitions", [])
    assert transitions, transitions
    last = transitions[-1]
    assert "COMPLIANCE_ESCALATION" in last["content"], last


# ---------------------------------------------------------------------------
# AC-7b.5 — chaos harness lives in test_compliance_fallback_chaos.py
# ---------------------------------------------------------------------------


# AC-7b.5 is covered by tests/test_compliance_fallback_chaos.py
# (10 runs, 3 kills each, fallback fires 10/10 AND DEGRADED visible).


# ---------------------------------------------------------------------------
# AC-7b.6 — account_id on participant metadata
# ---------------------------------------------------------------------------


class _CapturingTools:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def send_event(
        self,
        content: str,
        message_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.events.append(
            {"content": content, "message_type": message_type, "metadata": metadata}
        )


def test_participant_metadata_carries_account_id() -> None:
    """AC-7b.6: events carry ``from_account_id`` so app.band.ai shows 2 accounts."""
    agent = ComplianceVeto(
        secrets={
            "AIML_API_KEY": "test",
            "AIML_API_BASE_URL": "https://api.aimlapi.com/v1",
        }
    )
    tools = _CapturingTools()
    decision = agent.evaluate(
        case=_StubCase("cv-acct"),
        risk=_StubRisk("CRITICAL"),
        policy=_StubPolicy([_StubFinding("CRITICAL")]),
        tools=tools,
    )
    assert decision.verdict == "veto"
    # The send_event was sync (no event loop) — capture directly.
    assert tools.events, "send_event was not called"
    metadata = tools.events[0]["metadata"]
    assert metadata["from_account_id"], metadata
    assert metadata["from_account_id"] == agent.agent_id, metadata
    assert metadata["cross_account"] is True, metadata
    assert metadata["verdict"] == "veto", metadata


# ---------------------------------------------------------------------------
# Helpers: end-to-end graph runs including the new node
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_state_machine_includes_compliance_escalation() -> None:
    """The 11-node graph (S-07b added COMPLIANCE_ESCALATION) runs to DONE."""
    from band.testing.fake_tools import FakeAgentTools  # type: ignore

    os.environ.setdefault("VOUCH_SEAL_URL", "http://127.0.0.1:1/seal")
    tools = FakeAgentTools(room_id="vouch-procurement-court")
    case_id = "case-cv-graph"
    register_tools(case_id, tools)
    sm = compile_state_machine()
    initial: OrchestratorState = {
        "state": "IDLE",
        "case_id": case_id,
        "tenant_id": "stark",
        "procurement_request": "test compliance veto routing",
        "veto_decision": {
            "verdict": "veto",
            "reason": "GDPR breach",
            "regulatory_clock": "GDPR-Art-33",
        },
        "transitions": [],
    }
    result = await sm.ainvoke(initial, {"configurable": {"thread_id": "t-cv"}})
    assert result["state"] == "DONE"
    seen = [t.get("from") for t in result.get("transitions", [])]
    assert "COMPLIANCE_ESCALATION" in seen
    assert seen == list(ORCHESTRATOR_STATES), seen
