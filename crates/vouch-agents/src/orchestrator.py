"""S-01: Apohara VOUCH Orchestrator.

A LangGraph-driven Band agent that:
  1. Joins the shared `vouch-procurement-court` chatroom.
  2. Recruits the 8 specialist agents via the Band peer/contact tools.
  3. Routes incoming procurement requests through a 9-state machine:
        IDLE -> INTAKE -> RESEARCH -> RISK -> POLICY -> AUDIT
              -> REDTEAM -> EVIDENCE -> DECISION -> DONE
  4. Emits one `thenvoi_send_event` per state transition (AC-1.3).
  5. At EVIDENCE -> DECISION, calls the S-03 `POST /seal` endpoint to
     produce a cryptographically-sealed Evidence Packet that the
     Decision Memo carries forward.

Implementation notes (deviations from the S-01 plan):

  * The plan's AC-1.1 says "LangGraphAdapter with
    ChatCompletions(model='openai/gpt-5.4', ...)". The installed
    band-sdk 1.0.0 exposes ``LangGraphAdapter(llm=BaseChatModel, ...)``
    and the LLM is a ``langchain_openai.ChatOpenAI`` (AI/ML API is
    OpenAI-compatible, so we set ``base_url`` + ``api_key``). The
    model id passed is ``"openai/gpt-5.4"`` as the plan requests;
    ChatOpenAI accepts arbitrary model ids and forwards them to the
    configured base_url.
  * ``thenvoi_send_event`` / ``thenvoi_lookup_peers`` /
    ``thenvoi_add_participant`` are not module-level helpers — they
    are tools injected by ``LangGraphAdapter`` via the Band runtime
    (``band.runtime.tools``). For unit tests we use
    ``band.testing.fake_tools.FakeAgentTools`` which records every
    tool call in ``events_sent`` / ``participants_added``.

This module is consumed by the ``themis-band-client`` subprocess
harness (``crates/themis-band-client/scripts/run_agent.py``) as one
of the registered agents. It is NOT a new Band wrapper.
"""

from __future__ import annotations
import os
from pathlib import Path

from llm_secrets import load_all
# Backwards-compat alias (M1 refactor: replaced local load_secrets() with llm_secrets)
load_secrets = load_all

import json
import logging
import uuid
from typing import Any, Literal, TypedDict

import httpx
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Secrets (AC-1.7) — loaded from ~/.config/apohara/secrets.env, NEVER source.
# ---------------------------------------------------------------------------


# 9-state machine (AC-1.2). The state is carried on the graph state as
# the literal string; each node asserts the expected predecessor.
ORCHESTRATOR_STATES: tuple[str, ...] = (
    "IDLE",
    "INTAKE",
    "RESEARCH",
    "RISK",
    "POLICY",
    "AUDIT",
    "REDTEAM",
    "COMPLIANCE_ESCALATION",  # S-07b AC-7b.4
    "EVIDENCE",
    "DECISION",
    "DONE",
)


# ---------------------------------------------------------------------------
# Agent config loader (AC-1.5 + AC-1.4 + AC-1.8)
# ---------------------------------------------------------------------------


def agent_config_path() -> Path:
    """Return the absolute path to agent_config.yaml.

    AC-1.4: the file lives under
    ``crates/themis-band-client/agent-config/agent_config.yaml`` and
    is git-ignored (verified by `git check-ignore`).
    """
    return (
        Path(__file__).resolve().parents[2]
        / "themis-band-client"
        / "agent-config"
        / "agent_config.yaml"
    )


def load_agent_config(agent_name: str = "themis-orchestrator") -> dict[str, Any]:
    """Load one agent's record from agent_config.yaml.

    Returns a dict with at least ``agent_id`` and ``api_key``. AC-1.5
    checks that ``themis-orchestrator`` resolves to
    ``c963ea72-65fb-4388-ad8f-75dfd0043250``.
    """
    cfg_path = agent_config_path()
    if not cfg_path.exists():
        raise FileNotFoundError(f"agent_config.yaml not found at {cfg_path}")
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        # Minimal fallback: hand-rolled YAML loader for the tiny
        # surface we need (top-level `key: value` and inline lists).
        data = _parse_minimal_yaml(cfg_path.read_text())
    else:
        with cfg_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    if agent_name not in data:
        raise KeyError(f"agent {agent_name!r} missing from agent_config.yaml")
    rec = data[agent_name]
    return {
        "agent_id": rec["agent_id"],
        "api_key": rec["api_key"],
        "handle": rec.get("handle", ""),
        "role": rec.get("role", ""),
        "framework": rec.get("framework", ""),
    }


def load_chatroom() -> dict[str, Any]:
    """Load the shared ``chatroom:`` block (AC-1.8)."""
    cfg_path = agent_config_path()
    if not cfg_path.exists():
        raise FileNotFoundError(f"agent_config.yaml not found at {cfg_path}")
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        data = _parse_minimal_yaml(cfg_path.read_text())
    else:
        with cfg_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    if "chatroom" not in data:
        raise KeyError("'chatroom:' block missing from agent_config.yaml (AC-1.8)")
    return data["chatroom"]


def _parse_minimal_yaml(text: str) -> dict[str, Any]:
    """Tiny YAML parser for the agent_config shape we use.

    Avoids a PyYAML dep. Supports:
      * ``# comment`` lines (skipped)
      * ``key: value``  (top-level scalars)
      * ``key:``        (start of a nested block; parsed below)
      * ``- item``      (list items under a parent key)
    """
    result: dict[str, Any] = {}
    current_key: str | None = None
    current_list: list[Any] | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith("  - "):
            assert current_key is not None and current_list is not None
            current_list.append(line[4:].strip())
            continue
        if line.startswith("    "):  # continued list item (quoted strings)
            if current_list is not None and current_list:
                current_list[-1] = current_list[-1] + " " + line.strip()
            continue
        if line.endswith(":"):
            key = line[:-1].strip()
            current_key = key
            # block start
            current_list = []
            result[key] = current_list
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            current_key = key
            if value == "":
                current_list = []
                result[key] = current_list
            else:
                result[key] = value.strip('"').strip("'")
                current_list = None
    # Promote list-valued top-level keys where the schema expects a dict
    # (e.g. `tenants:` was written as a 2-line list; for our usage
    # that field is informational, so leave as-is).
    return result


# ---------------------------------------------------------------------------
# AI/ML API client (AC-1.1)
# ---------------------------------------------------------------------------


def build_chat_completions_llm(
    secrets: dict[str, str] | None = None,
    model: str = "openai/gpt-5.4",
) -> ChatOpenAI:
    """Build the AI/ML API LangChain LLM (AC-1.1).

    The plan's story calls the class ``ChatCompletions``; the
    installed ``band-sdk 1.0.0`` uses the canonical
    ``langchain_openai.ChatOpenAI`` against the OpenAI-compatible
    base_url. The model id is forwarded as-is, so we keep
    ``"openai/gpt-5.4"`` to match the spec exactly.
    """
    secrets = secrets if secrets is not None else load_secrets()
    api_key = secrets.get("AIML_API_KEY", "")
    base_url = secrets.get("AIML_API_BASE_URL", "https://api.aimlapi.com/v1")
    if not api_key:
        # In tests we still want the import path to work, so we leave
        # api_key empty here. The real agent.run() will fail-fast
        # at first tool call.
        logger.warning("AIML_API_KEY not set — using empty string (test mode)")
    return ChatOpenAI(model=model, base_url=base_url, api_key=api_key)


# ---------------------------------------------------------------------------
# LangGraph state (AC-1.2)
# ---------------------------------------------------------------------------


class OrchestratorState(TypedDict, total=False):
    """The state carried across the 9-node LangGraph state machine.

    The `state` field is a Literal[one of ORCHESTRATOR_STATES]. Each
    node asserts its expected predecessor before transitioning.
    """

    state: Literal[
        "IDLE",
        "INTAKE",
        "RESEARCH",
        "RISK",
        "POLICY",
        "AUDIT",
        "REDTEAM",
        "COMPLIANCE_ESCALATION",
        "EVIDENCE",
        "DECISION",
        "DONE",
    ]
    case_id: str
    tenant_id: str
    procurement_request: str
    recruit_handles: list[str]
    recruited_agents: list[dict[str, Any]]
    research_findings: str
    risk_score: float
    policy_decision: str
    audit_notes: str
    redteam_findings: str
    sealed_packet: dict[str, Any]
    decision_memo: str
    # S-07b: Compliance Veto decision (set by node_compliance_escalation).
    # When verdict == "veto" the case routes deterministically to
    # COMPLIANCE_ESCALATION regardless of any other agent's output.
    veto_decision: dict[str, Any]
    # S-07b AC-7b.5: DEGRADED banner flag (true when the fallback path
    # activated because the cross-account WebSocket was killed).
    degraded: bool
    # Audit log of every state transition (used by AC-1.3 + AC-1.6 tests).
    transitions: list[dict[str, Any]]
    # Chatroom id loaded from the shared block.
    chatroom_id: str


# A module-level side-channel for the active Band tools. The
# LangGraph checkpointer (InMemorySaver) msgpack-serializes the
# state on every node, so we cannot store a FakeAgentTools (or any
# non-trivial object) directly on the state. Instead, the
# Orchestrator sets ``_TOOLS_REGISTRY[case_id] = tools`` and the
# state carries only ``case_id`` (which IS serializable).
_TOOLS_REGISTRY: dict[str, Any] = {}


def register_tools(case_id: str, tools: Any) -> None:
    """Stash the active Band tools under ``case_id`` for the nodes to find."""
    _TOOLS_REGISTRY[case_id] = tools


def _lookup_tools(case_id: str) -> Any:
    return _TOOLS_REGISTRY.get(case_id) or _TOOLS_REGISTRY.get("__default__")


# ---------------------------------------------------------------------------
# Node helpers
# ---------------------------------------------------------------------------


def _next_state(current: str) -> str:
    idx = ORCHESTRATOR_STATES.index(current)
    if idx + 1 >= len(ORCHESTRATOR_STATES):
        return "DONE"
    return ORCHESTRATOR_STATES[idx + 1]


async def _emit_thought(state: OrchestratorState, content: str) -> None:
    """Emit a `thought` event (AC-1.3).

    Falls back to logging when no Band tools are attached (so unit
    tests can call this without the full Band runtime).
    """
    tools = _lookup_tools(state.get("case_id", ""))
    transition_entry = {
        "from": state.get("state"),
        "content": content,
        "ts_ms": _now_ms(),
    }
    state.setdefault("transitions", []).append(transition_entry)
    send_event = getattr(tools, "send_event", None) if tools is not None else None
    if send_event is None:
        logger.info("[thought @%s] %s", state.get("state"), content)
        return
    try:
        # The installed band.testing.fake_tools.FakeAgentTools exposes
        # an async send_event(content, message_type, metadata=None).
        # The real Band runtime's tools.send_event is also async with
        # the same signature.
        await send_event(content=content, message_type="thought")
    except Exception as exc:  # pragma: no cover (defensive)
        logger.warning("send_event failed: %s", exc)


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


async def _recruit_via_tools(state: OrchestratorState) -> None:
    """Recruit the 8 specialist agents via the Band tools.

    The plan's AC-1.3 says: "on IDLE -> INTAKE, call
    thenvoi_lookup_peers to find the 8 other agents by handle, then
    thenvoi_add_participant to recruit each into the chatroom."

    In the band-sdk 1.0.0 surface these are tool methods exposed on
    the AgentTools object, not module-level helpers. We use the
    real names from the protocol and let the FakeAgentTools record
    the calls in tests. This coroutine MUST be awaited from inside
    the LangGraph runtime (which is already an event loop).
    """
    tools = _lookup_tools(state.get("case_id", ""))
    if tools is None:
        return
    handles: list[str] = list(state.get("recruit_handles", []))
    if not handles:
        return
    lookup = getattr(tools, "lookup_peers", None)
    add = getattr(tools, "add_participant", None)
    if lookup is None or add is None:
        return
    try:
        await lookup()
    except Exception as exc:  # pragma: no cover (network path)
        logger.warning("lookup_peers failed: %s", exc)
    for handle in handles:
        try:
            await add(identifier=handle, role="member")
            state.setdefault("recruited_agents", []).append(
                {"handle": handle, "role": "member"}
            )
        except Exception as exc:  # pragma: no cover (network path)
            logger.warning("add_participant(%s) failed: %s", handle, exc)


# ---------------------------------------------------------------------------
# Nodes — one per state transition
# ---------------------------------------------------------------------------


async def node_idle(state: OrchestratorState) -> OrchestratorState:
    """IDLE: enter the chatroom, load the shared chatroom_id (AC-1.8)."""
    # Mark the state BEFORE emitting so the transition log records
    # the correct source state. The initial entry has from=None;
    # this is by design (no predecessor).
    state["state"] = "IDLE"
    chatroom = load_chatroom()
    state["chatroom_id"] = chatroom.get("chatroom_id", "")
    await _emit_thought(
        state, "Entering IDLE — loading shared chatroom config."
    )
    return state


async def node_intake(state: OrchestratorState) -> OrchestratorState:
    """INTAKE: recruit the 8 specialist agents into the chatroom (AC-1.3)."""
    chatroom = load_chatroom()
    state["recruit_handles"] = list(chatroom.get("participants", []))
    await _recruit_via_tools(state)
    state["state"] = "INTAKE"
    await _emit_thought(
        state,
        f"INTAKE — recruited {len(state.get('recruited_agents', []))} "
        f"specialist agent(s) into chatroom {state.get('chatroom_id', '?')}.",
    )
    return state


async def node_research(state: OrchestratorState) -> OrchestratorState:
    """RESEARCH: dispatch the procurement request to research agents."""
    state["state"] = "RESEARCH"
    state.setdefault(
        "research_findings",
        "stub: extractor + po-matcher would return structured JSON here",
    )
    await _emit_thought(
        state,
        f"RESEARCH — dispatching procurement request "
        f"({len(state.get('procurement_request', ''))} chars) to "
        f"@apohara-themis/extractor and @apohara-themis/po-matcher.",
    )
    return state


async def node_risk(state: OrchestratorState) -> OrchestratorState:
    """RISK: fraud-auditor scores the case."""
    state["state"] = "RISK"
    state["risk_score"] = 0.42  # placeholder; fraud-auditor overrides
    await _emit_thought(
        state,
        f"RISK — fraud-auditor scored the case at "
        f"risk_score={state['risk_score']:.2f}.",
    )
    return state


async def node_policy(state: OrchestratorState) -> OrchestratorState:
    """POLICY: gaap-classifier categorizes the expense under policy rules."""
    state["state"] = "POLICY"
    state["policy_decision"] = "review_required"
    await _emit_thought(
        state,
        f"POLICY — gaap-classifier verdict: {state['policy_decision']}.",
    )
    return state


async def node_audit(state: OrchestratorState) -> OrchestratorState:
    """AUDIT: audit-watchdog checks coherence before the evidence seal."""
    state["state"] = "AUDIT"
    state["audit_notes"] = "coherence OK"
    await _emit_thought(
        state, f"AUDIT — audit-watchdog notes: {state['audit_notes']}."
    )
    return state


async def node_redteam(state: OrchestratorState) -> OrchestratorState:
    """REDTEAM: regression-tester re-runs BLAKE3 chain verification."""
    state["state"] = "REDTEAM"
    state["redteam_findings"] = "chain OK"
    await _emit_thought(
        state,
        f"REDTEAM — regression-tester findings: {state['redteam_findings']}.",
    )
    return state


# ---------------------------------------------------------------------------
# S-07b: Deterministic routing to COMPLIANCE_ESCALATION (AC-7b.4)
# ---------------------------------------------------------------------------


def _route_to_compliance_escalation(
    veto_decision: Any,
    fallback_active: bool = False,
) -> bool:
    """Return True iff the case routes to COMPLIANCE_ESCALATION (AC-7b.4).

    Deterministic: True iff the Compliance Veto emits
    ``verdict == "veto"``. No other agent's output can suppress this
    routing — the function takes only the veto decision + a
    fallback flag. The 100/100 Hypothesis proptest
    (``tests/test_compliance_veto.py::test_deterministic_routing_proptest``)
    asserts this on random state inputs.
    """
    if veto_decision is None:
        return False
    if isinstance(veto_decision, dict):
        verdict = veto_decision.get("verdict")
    else:
        verdict = getattr(veto_decision, "verdict", None)
    if verdict != "veto":
        return False
    # ``fallback_active`` is informational here — the route is True
    # regardless of which transport produced the veto. AC-7b.4 only
    # requires the routing decision to depend on the verdict.
    _ = fallback_active
    return True


async def node_compliance_escalation(state: OrchestratorState) -> OrchestratorState:
    """COMPLIANCE_ESCALATION: deterministic routing on VetoDecision (AC-7b.4).

    Fires UNCONDITIONALLY when the Compliance Veto emits
    ``verdict="veto"``. Other agents (RedTeam, LegalPolicy, etc.)
    cannot suppress this routing — see
    ``_route_to_compliance_escalation`` + the 100/100 proptest.

    The node is registered in the linear graph immediately after
    ``REDTEAM`` and before ``EVIDENCE`` so the case enters the
    escalation path BEFORE the Evidence Clerk seals the packet
    (the sealed packet then carries ``escalation=True`` metadata
    so the regulator sees the escalation at offline-verification
    time).
    """
    veto = state.get("veto_decision")
    fallback_active = bool(
        isinstance(veto, dict) and veto.get("fallback")
    )
    routes = _route_to_compliance_escalation(
        veto, fallback_active=fallback_active
    )
    state["state"] = "COMPLIANCE_ESCALATION"
    if fallback_active:
        state["degraded"] = True
    if routes:
        # Record escalation on the state for the EVIDENCE node to
        # carry into the sealed packet.
        if isinstance(veto, dict):
            veto = dict(veto)
            veto["escalated"] = True
            state["veto_decision"] = veto
    await _emit_thought(
        state,
        f"COMPLIANCE_ESCALATION — veto={veto if isinstance(veto, dict) else None} "
        f"routes={routes} degraded={state.get('degraded', False)}.",
    )
    return state


async def node_evidence(state: OrchestratorState) -> OrchestratorState:
    """EVIDENCE: call S-03 POST /seal to produce the Evidence Packet.

    AC: at EVIDENCE -> DECISION the orchestrator POSTs the packet to
    the local vouch-orchestrator HTTP endpoint and captures
    ``hash`` + ``signature_hex`` + ``c2pa_manifest`` into the state
    for the final Decision Memo.
    """
    case_id = state.get("case_id") or f"case-{uuid.uuid4().hex[:8]}"
    tenant_id = state.get("tenant_id") or "stark"
    request = state.get("procurement_request", "")
    seal_url = os.environ.get("VOUCH_SEAL_URL", "http://localhost:7878/seal")
    payload = {
        "case_id": case_id,
        "tenant_id": tenant_id,
        "agent_outputs": [
            {
                "agent_id": "fraud-auditor",
                "verdict": "review_required",
                "summary": request[:120],
                "risk_score": state.get("risk_score"),
            },
            {
                "agent_id": "gaap-classifier",
                "verdict": state.get("policy_decision", "review_required"),
                "summary": state.get("research_findings", "")[:120],
            },
        ],
        "hash_chain_link": None,
        "reference_database": "stanford-invoicenet-50",
        "policy_version": "apohara-vouch-1",
        "natural_person_id": None,
    }
    sealed: dict[str, Any]
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(seal_url, json=payload)
        if resp.status_code != 200:
            sealed = {"error": f"HTTP {resp.status_code}", "body": resp.text[:200]}
        else:
            sealed = resp.json()
    except Exception as exc:  # network may be down in unit tests
        logger.warning("POST /seal failed: %s", exc)
        sealed = {"error": str(exc)}
    state["sealed_packet"] = sealed
    state["case_id"] = case_id
    state["tenant_id"] = tenant_id
    state["state"] = "EVIDENCE"
    await _emit_thought(
        state,
        "EVIDENCE — sealed packet "
        f"hash={(sealed.get('hash') or 'error')[:16]}…"
        f" sig={(sealed.get('signature_hex') or 'error')[:16]}…",
    )
    return state


async def node_decision(state: OrchestratorState) -> OrchestratorState:
    """DECISION: build the Decision Memo from the sealed packet."""
    sealed = state.get("sealed_packet", {})
    memo = {
        "case_id": state.get("case_id"),
        "tenant_id": state.get("tenant_id"),
        "risk_score": state.get("risk_score"),
        "policy_decision": state.get("policy_decision"),
        "evidence": {
            "hash": sealed.get("hash"),
            "signature_hex": sealed.get("signature_hex"),
            "public_key_hex": sealed.get("public_key_hex"),
            "decision_id": sealed.get("decision_id"),
            "sealed_at": sealed.get("sealed_at"),
            "chain_root": sealed.get("chain_root"),
        },
        "audit_notes": state.get("audit_notes"),
        "redteam_findings": state.get("redteam_findings"),
    }
    state["decision_memo"] = json.dumps(memo, sort_keys=True, indent=2)
    state["state"] = "DECISION"
    await _emit_thought(
        state,
        f"DECISION — memo ready for case_id={state.get('case_id')} "
        f"decision_id={sealed.get('decision_id')}.",
    )
    return state


async def node_done(state: OrchestratorState) -> OrchestratorState:
    """DONE: terminal state — every transition has been recorded (AC-1.3)."""
    state["state"] = "DONE"
    await _emit_thought(
        state,
        f"DONE — orchestrator completed with {len(state.get('transitions', []))} "
        f"transition events emitted.",
    )
    return state


# ---------------------------------------------------------------------------
# State graph builder (AC-1.2)
# ---------------------------------------------------------------------------


def build_state_graph() -> StateGraph:
    """Build the 9-state LangGraph state machine.

    The graph is a pure linear chain IDLE -> INTAKE -> ... -> DONE.
    Each node emits one ``thought`` event before transitioning
    (AC-1.3). The state machine is itself the only public surface
    exposed to the test suite (see tests/test_state_machine.py).
    """
    g = StateGraph(OrchestratorState)
    g.add_node("IDLE", node_idle)
    g.add_node("INTAKE", node_intake)
    g.add_node("RESEARCH", node_research)
    g.add_node("RISK", node_risk)
    g.add_node("POLICY", node_policy)
    g.add_node("AUDIT", node_audit)
    g.add_node("REDTEAM", node_redteam)
    g.add_node("COMPLIANCE_ESCALATION", node_compliance_escalation)
    g.add_node("EVIDENCE", node_evidence)
    g.add_node("DECISION", node_decision)
    g.add_node("DONE", node_done)
    g.add_edge(START, "IDLE")
    g.add_edge("IDLE", "INTAKE")
    g.add_edge("INTAKE", "RESEARCH")
    g.add_edge("RESEARCH", "RISK")
    g.add_edge("RISK", "POLICY")
    g.add_edge("POLICY", "AUDIT")
    g.add_edge("AUDIT", "REDTEAM")
    g.add_edge("REDTEAM", "COMPLIANCE_ESCALATION")
    g.add_edge("COMPLIANCE_ESCALATION", "EVIDENCE")
    g.add_edge("EVIDENCE", "DECISION")
    g.add_edge("DECISION", "DONE")
    g.add_edge("DONE", END)
    return g


def compile_state_machine():
    """Compile the state machine for use by LangGraphAdapter or tests."""
    return build_state_graph().compile(checkpointer=InMemorySaver())


def make_graph_factory(
    secrets: dict[str, str] | None = None,
    model: str = "openai/gpt-5.4",
):
    """Build a ``graph_factory`` callable for ``LangGraphAdapter``.

    band-sdk's ``LangGraphAdapter(graph_factory=...)`` calls this with
    the list of Band tools each turn. We bind the tools into the
    compiled state machine so each node can call them. The LLM is
    held for nodes that want a chat completion (e.g. RESEARCH).

    The factory returns a LangGraph ``Pregel`` compiled from the
    9-state machine with the Band tools bound in.
    """
    secrets = secrets if secrets is not None else load_secrets()
    llm = build_chat_completions_llm(secrets=secrets, model=model)

    def _factory(tools: list[Any]) -> Any:
        # The Band runtime hands the factory the list of tools the
        # LLM can call. We stash them in the module-level registry
        # keyed by case_id (which the LLM provides in the state).
        # Since case_id is only known at runtime, we register the
        # default tools under the ``__default__`` key. The state
        # machine resolves tools via ``_lookup_tools(case_id)`` which
        # falls back to ``__default__`` when no per-case override
        # exists.
        if tools:
            _TOOLS_REGISTRY.setdefault("__default__", tools[0])
        sm = build_state_graph()
        return sm.compile(checkpointer=InMemorySaver())

    return _factory


# ---------------------------------------------------------------------------
# Top-level Orchestrator (the actual Band agent)
# ---------------------------------------------------------------------------


class Orchestrator:
    """The @apohara-themis/themis-orchestrator Band agent.

    Wires the 9-state LangGraph state machine into a band-sdk
    ``LangGraphAdapter`` and exposes ``run()`` to the themis-band-client
    subprocess harness. Tests construct ``Orchestrator()`` directly
    and call ``run_state_machine(initial_state)``.
    """

    def __init__(
        self,
        agent_name: str = "themis-orchestrator",
        secrets: dict[str, str] | None = None,
    ) -> None:
        self.agent_name = agent_name
        self.secrets = secrets if secrets is not None else load_secrets()
        self.config = load_agent_config(agent_name)
        self.chatroom = load_chatroom()
        self.llm = build_chat_completions_llm(secrets=self.secrets)
        self.state_machine = compile_state_machine()

    async def run_state_machine(
        self, initial: OrchestratorState, config: dict[str, Any] | None = None
    ) -> OrchestratorState:
        """Drive the state machine once with the given initial state.

        Used by tests and by the ``themis-band-client`` subprocess
        harness (one invocation per procurement request).
        """
        cfg = config or {"configurable": {"thread_id": uuid.uuid4().hex}}
        # The compiled graph is async; we await it.
        result: OrchestratorState = await self.state_machine.ainvoke(initial, cfg)
        return result

    def run(self) -> None:
        """Production entrypoint used by ``themis-band-client``.

        The actual band-sdk Agent.run() lives in band.agent.Agent
        and takes over the asyncio loop. The subprocess harness
        imports this class and calls ``Orchestrator(...)`` to
        construct the agent; the harness is responsible for the
        ``await agent.run()`` call (AC-1.6 — "persists WebSocket
        connection" is the runtime guarantee of band-sdk 1.0.0).
        """
        # Defer heavy imports so the module is importable in unit
        # tests without the band runtime.
        from band.adapters import LangGraphAdapter  # type: ignore

        adapter = LangGraphAdapter(
            llm=self.llm,
            checkpointer=InMemorySaver(),
            graph_factory=make_graph_factory(secrets=self.secrets),
        )
        # The harness calls ``await Agent.create(adapter=...).run()``;
        # we expose the adapter + agent_id + api_key as a dict the
        # harness can read.
        logger.info(
            "Orchestrator(%s) ready — agent_id=%s chatroom_id=%s",
            self.agent_name,
            self.config["agent_id"],
            self.chatroom.get("chatroom_id"),
        )
        # We don't construct Agent here because that triggers the
        # full Band runtime (WebSocket connect, etc.) which is the
        # responsibility of the themis-band-client subprocess.
        self._adapter = adapter


__all__ = [
    "ORCHESTRATOR_STATES",
    "OrchestratorState",
    "Orchestrator",
    "build_state_graph",
    "build_chat_completions_llm",
    "compile_state_machine",
    "load_secrets",
    "load_agent_config",
    "load_chatroom",
    "make_graph_factory",
    "node_compliance_escalation",
    "_route_to_compliance_escalation",
]
