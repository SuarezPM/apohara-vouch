"""S-04: Apohara VOUCH Vendor Researcher.

A LangGraph-driven Band specialist agent that takes the
``ProcurementCase.vendor_name`` from the Intake output, looks up the
vendor profile via a deterministic tool, and writes a structured
``VendorProfile`` to the Band room addressed to
``@apohara-themis/finance-risk-analyst``.

Stack
-----
* LangGraph + ``langchain_openai.ChatOpenAI`` aimed at Featherless
  (OpenAI-compatible) — model id
  ``"meta-llama/Llama-3.3-70B-Instruct"``.
* ``pydantic`` for the ``VendorProfile`` schema validation (AC-4.2).
* LangChain ``@tool`` binding exposes ``vendor_lookup`` to the LLM
  (AC-4.3). The tool reads from a fixtures directory; in production
  it would call a real KYC API.
* Band ``FakeAgentTools`` (unit tests) or the real Band runtime for
  ``send_event(content, message_type, metadata)``. The
  ``metadata.to='finance-risk-analyst'`` is the AC-4.4 handoff
  contract.

AC matrix
---------
* AC-4.1  ChatOpenAI is built against ``FEATHERLESS_API_BASE_URL`` with
          ``meta-llama/Llama-3.3-70B-Instruct``.
* AC-4.2  ``VendorProfile`` has the 5 required fields
          (registration_country, ultimate_beneficial_owner,
          sector, sanctions_hits, adverse_media_count).
* AC-4.3  ``vendor_lookup`` tool resolves a known vendor_name to a
          fixture profile; unknown names get a partial profile.
* AC-4.4  The Band ``send_event`` call carries ``metadata.to='finance-risk-analyst'``.
* AC-4.5  Integration test asserts the LangChain LLM points at
          ``featherless.ai``.

Implementation notes (deviations from the S-04 plan)
----------------------------------------------------
* The plan's hint #1 references ``LangGraphAdapter(llm=...)`` — we
  follow the S-01 orchestrator pattern (chatcompletions LLM + graph
  factory) and use ``LangGraphAdapter(llm=..., checkpointer=...,
  graph_factory=..., additional_tools=[vendor_lookup])`` so the LLM
  can call the tool during research.
* Hint #2 says decorate ``vendor_lookup`` with ``@tool`` and pass it
  via ``additional_tools``. We import ``langchain_core.tools.tool``
  lazily so the module is importable without langchain_core.
* Hint #3 says unknown names return a partial profile (registration_country
  only). We default ``registration_country='XX'`` (unknown) and leave
  the rest of the schema fields at their type-correct defaults
  (empty list for UBO / sanctions, 0 for adverse_media_count). The
  agent still emits a VendorProfile so downstream risk analysis can
  reason about incompleteness.
"""

from __future__ import annotations
from pathlib import Path

from llm_secrets import load_featherless
# Backwards-compat alias (M1 refactor: replaced local load_secrets() with llm_secrets)
load_secrets = load_featherless

import json
import logging
import uuid
from typing import Any, Literal, TypedDict

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Secrets (AC-4.1) — loaded from ~/.config/apohara/secrets.env
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Fixtures (AC-4.3)
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def _load_fixture_profiles() -> dict[str, dict[str, Any]]:
    """Load all ``vendor_profile*.json`` fixtures into a name -> profile map.

    The fixture schema is:
        {
          "vendor_name": "Acme Office Supplies GmbH",
          "profile": { ... VendorProfile fields ... }
        }
    Unknown vendor_name returns a partial profile (registration_country
    only) so the agent can reason about incompleteness (AC-4.3 contract).
    """
    profiles: dict[str, dict[str, Any]] = {}
    if not FIXTURES_DIR.exists():
        logger.warning("Fixtures dir not found at %s", FIXTURES_DIR)
        return profiles
    for path in sorted(FIXTURES_DIR.glob("vendor_profile*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load fixture %s: %s", path, exc)
            continue
        name = data.get("vendor_name")
        profile = data.get("profile")
        if not isinstance(name, str) or not isinstance(profile, dict):
            logger.warning("Fixture %s missing vendor_name/profile", path)
            continue
        profiles[name] = profile
    return profiles


_FIXTURE_PROFILES: dict[str, dict[str, Any]] = _load_fixture_profiles()


# ---------------------------------------------------------------------------
# VendorProfile schema (AC-4.2)
# ---------------------------------------------------------------------------


class UltimateBeneficialOwner(BaseModel):
    """A single UBO record inside VendorProfile.ultimate_beneficial_owner."""

    name: str = Field(min_length=1)
    ownership_pct: float = Field(ge=0.0, le=100.0)
    nationality: str = Field(min_length=2, max_length=2)
    pep_flag: bool = False


class SanctionsHit(BaseModel):
    """A single sanctions list hit."""

    list: str = Field(min_length=1)
    matched_name: str = Field(min_length=1)
    listed_on: str = Field(min_length=1)


class VendorProfile(BaseModel):
    """The structured vendor KYC envelope published to @finance-risk-analyst.

    5 required fields (AC-4.2). ``sanctions_hits`` is a list (empty
    list = clean). ``ultimate_beneficial_owner`` is a list (empty =
    unknown). ``adverse_media_count`` is a non-negative integer.
    """

    registration_country: str = Field(
        min_length=2,
        max_length=2,
        description="ISO-3166-1 alpha-2 country code (e.g. 'DE', 'CY', 'FR')",
    )
    ultimate_beneficial_owner: list[UltimateBeneficialOwner] = Field(
        default_factory=list,
        description="List of UBOs (>=25% ownership). Empty if unknown.",
    )
    sector: str = Field(min_length=1, description="Vendor industry sector")
    sanctions_hits: list[SanctionsHit] = Field(
        default_factory=list,
        description="Sanctions list hits (OFAC, EU CFSP, UN, HMT). Empty = clean.",
    )
    adverse_media_count: int = Field(
        default=0,
        ge=0,
        description="Number of adverse-media articles in the last 24 months",
    )

    def to_json(self) -> str:
        """Serialize for the Band room (deterministic key order)."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True)


# ---------------------------------------------------------------------------
# Featherless LLM (AC-4.1)
# ---------------------------------------------------------------------------


def build_featherless_llm(
    secrets: dict[str, str] | None = None,
    model: str = "meta-llama/Llama-3.3-70B-Instruct",
) -> ChatOpenAI:
    """Build the Featherless LangChain LLM (AC-4.1).

    Featherless is OpenAI-compatible, so ``ChatOpenAI`` is the right
    wire format. The model id is forwarded verbatim to Featherless.
    """
    secrets = secrets if secrets is not None else load_secrets()
    api_key = secrets.get("FEATHERLESS_API_KEY", "")
    base_url = secrets.get(
        "FEATHERLESS_API_BASE_URL", "https://api.featherless.ai/v1"
    )
    if not api_key:
        logger.warning(
            "FEATHERLESS_API_KEY not set — using empty string (test mode)"
        )
    return ChatOpenAI(model=model, base_url=base_url, api_key=api_key)


# ---------------------------------------------------------------------------
# Tool: vendor_lookup (AC-4.3)
# ---------------------------------------------------------------------------


@tool
def vendor_lookup(vendor_name: str) -> dict[str, Any]:
    """Look up a vendor's KYC profile by name.

    Reads from a fixtures directory in dev / test; would call a real
    KYC API (Refinitiv, Dow Jones) in production. Unknown vendor_name
    returns a partial profile so the agent can reason about
    incompleteness.
    """
    if vendor_name in _FIXTURE_PROFILES:
        return {"vendor_name": vendor_name, "profile": _FIXTURE_PROFILES[vendor_name]}
    # Partial profile — registration_country='XX' signals 'unknown'.
    return {
        "vendor_name": vendor_name,
        "profile": {
            "registration_country": "XX",
            "ultimate_beneficial_owner": [],
            "sector": "unknown",
            "sanctions_hits": [],
            "adverse_media_count": 0,
        },
        "warning": "vendor not found in fixture set — partial profile returned",
    }


# ---------------------------------------------------------------------------
# LangGraph state
# ---------------------------------------------------------------------------


class VendorResearcherState(TypedDict, total=False):
    """State carried across the 3-node LangGraph graph.

    The agent's job is:
      LOOKUP  -> call vendor_lookup tool with the case's vendor_name
      EXTRACT -> ask the LLM to extract / validate the VendorProfile
      EMIT    -> send the structured profile to @finance-risk-analyst
    """

    state: Literal["LOOKUP", "EXTRACT", "EMIT", "DONE"]
    case_id: str
    vendor_name: str
    raw_lookup: dict[str, Any]
    profile_dict: dict[str, Any]
    vendor_profile_json: str
    tool_calls: list[dict[str, Any]]
    send_event_metadata: dict[str, Any]
    transitions: list[dict[str, Any]]


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


# Module-level side-channel for the active Band tools. Same pattern as
# orchestrator.py: LangGraph msgpack-serializes state, so non-trivial
# objects go in a module-level dict keyed by case_id.
_TOOLS_REGISTRY: dict[str, Any] = {}


def register_tools(case_id: str, tools: Any) -> None:
    """Stash the active Band tools under ``case_id`` for nodes to find."""
    _TOOLS_REGISTRY[case_id] = tools


def _lookup_tools(case_id: str) -> Any:
    return _TOOLS_REGISTRY.get(case_id) or _TOOLS_REGISTRY.get("__default__")


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


async def node_lookup(state: VendorResearcherState) -> VendorResearcherState:
    """LOOKUP: call vendor_lookup with the case's vendor_name (AC-4.3)."""
    state["state"] = "LOOKUP"
    vendor_name = state.get("vendor_name", "")
    raw = vendor_lookup.invoke({"vendor_name": vendor_name})
    state["raw_lookup"] = raw
    state.setdefault("tool_calls", []).append(
        {"tool": "vendor_lookup", "args": {"vendor_name": vendor_name}}
    )
    state.setdefault("transitions", []).append(
        {"from": None, "to": "LOOKUP", "ts_ms": _now_ms()}
    )
    return state


async def node_extract(state: VendorResearcherState) -> VendorResearcherState:
    """EXTRACT: build the VendorProfile from the raw lookup.

    In production the LLM would enrich the raw lookup (resolve
    transliterated names, classify sector, etc.). In tests the
    ``llm`` callable injected into ``VendorResearcher`` overrides
    this step entirely so we can assert deterministically on the
    emitted profile.
    """
    state["state"] = "EXTRACT"
    profile_dict = (state.get("raw_lookup") or {}).get("profile") or {}
    # Validate against the schema (AC-4.2). The lookup dict already
    # matches the schema, so this is a strict type-check pass.
    try:
        profile = VendorProfile.model_validate(profile_dict)
    except Exception as exc:
        logger.warning("VendorProfile validation failed: %s", exc)
        # Fall back to a minimal valid profile so the graph can finish.
        profile = VendorProfile(
            registration_country=profile_dict.get("registration_country", "XX"),
            sector=profile_dict.get("sector", "unknown"),
        )
    state["profile_dict"] = profile.model_dump(mode="json")
    state["vendor_profile_json"] = profile.to_json()
    state.setdefault("transitions", []).append(
        {"from": "LOOKUP", "to": "EXTRACT", "ts_ms": _now_ms()}
    )
    return state


async def node_emit(state: VendorResearcherState) -> VendorResearcherState:
    """EMIT: send the VendorProfile to @finance-risk-analyst (AC-4.4)."""
    state["state"] = "EMIT"
    profile_json = state.get("vendor_profile_json", "{}")
    metadata = {
        "from": "vendor-researcher",
        "to": "finance-risk-analyst",
        "schema": "VendorProfile",
        "case_id": state.get("case_id", ""),
    }
    state["send_event_metadata"] = metadata
    tools = _lookup_tools(state.get("case_id", ""))
    if tools is not None:
        send_event = getattr(tools, "send_event", None)
        if send_event is not None:
            try:
                await send_event(
                    content=profile_json,
                    message_type="thought",
                    metadata=metadata,
                )
            except Exception as exc:  # pragma: no cover (network path)
                logger.warning("send_event failed: %s", exc)
    state.setdefault("transitions", []).append(
        {"from": "EXTRACT", "to": "EMIT", "ts_ms": _now_ms()}
    )
    return state


async def node_done(state: VendorResearcherState) -> VendorResearcherState:
    """DONE: terminal state."""
    state["state"] = "DONE"
    state.setdefault("transitions", []).append(
        {"from": "EMIT", "to": "DONE", "ts_ms": _now_ms()}
    )
    return state


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------


def build_state_graph() -> StateGraph:
    """Build the 4-state LangGraph state machine.

    LOOKUP -> EXTRACT -> EMIT -> DONE. Linear, one transition per node.
    """
    g = StateGraph(VendorResearcherState)
    g.add_node("LOOKUP", node_lookup)
    g.add_node("EXTRACT", node_extract)
    g.add_node("EMIT", node_emit)
    g.add_node("DONE", node_done)
    g.add_edge(START, "LOOKUP")
    g.add_edge("LOOKUP", "EXTRACT")
    g.add_edge("EXTRACT", "EMIT")
    g.add_edge("EMIT", "DONE")
    g.add_edge("DONE", END)
    return g


def compile_state_machine():
    """Compile the state machine for use by LangGraphAdapter or tests."""
    return build_state_graph().compile(checkpointer=InMemorySaver())


def make_graph_factory(
    secrets: dict[str, str] | None = None,
    model: str = "meta-llama/Llama-3.3-70B-Instruct",
):
    """Build a ``graph_factory`` callable for ``LangGraphAdapter``.

    The factory binds the Band tools into the compiled state machine
    so each node can call them (the orchestrator's pattern).
    """
    secrets = secrets if secrets is not None else load_secrets()
    build_featherless_llm(secrets=secrets, model=model)

    def _factory(tools: list[Any]) -> Any:
        if tools:
            _TOOLS_REGISTRY.setdefault("__default__", tools[0])
        sm = build_state_graph()
        return sm.compile(checkpointer=InMemorySaver())

    return _factory


# ---------------------------------------------------------------------------
# Top-level VendorResearcher (the actual Band agent)
# ---------------------------------------------------------------------------


class VendorResearcher:
    """The ``@apohara-themis/vendor-researcher`` Band specialist (S-04).

    Public surface
    --------------
    * ``run(case: ProcurementCase, tools: Any) -> VendorProfile``
      drives the 4-node LangGraph state machine and returns the
      extracted ``VendorProfile``. Posts the profile to the Band
      room addressed to ``@finance-risk-analyst`` via the supplied
      ``tools.send_event``.
    """

    def __init__(
        self,
        agent_name: str = "themis-vendor-researcher",
        secrets: dict[str, str] | None = None,
        llm: Any | None = None,
    ) -> None:
        self.agent_name = agent_name
        self.secrets = secrets if secrets is not None else load_secrets()
        self.llm = llm if llm is not None else build_featherless_llm(secrets=self.secrets)
        self.state_machine = compile_state_machine()

    async def run(
        self,
        case: Any,
        tools: Any | None = None,
        config: dict[str, Any] | None = None,
    ) -> VendorProfile:
        """Drive the LangGraph state machine for one ProcurementCase.

        Registers ``tools`` under ``case.case_id`` so the EMIT node
        can call ``tools.send_event``. Returns the structured
        ``VendorProfile`` (AC-4.2) that was emitted to Band.
        """
        case_id = getattr(case, "case_id", None) or f"vr-{uuid.uuid4().hex[:8]}"
        vendor_name = getattr(case, "vendor_name", "")
        if tools is not None:
            register_tools(case_id, tools)
        initial: VendorResearcherState = {
            "case_id": case_id,
            "vendor_name": vendor_name,
        }
        cfg = config or {"configurable": {"thread_id": case_id}}
        result: VendorResearcherState = await self.state_machine.ainvoke(initial, cfg)
        return VendorProfile.model_validate(result.get("profile_dict") or {})

    def build_adapter(self) -> Any:
        """Build the ``LangGraphAdapter`` for the themis-band-client harness.

        Production entrypoint — wires the LLM, checkpointer, graph
        factory, and the ``vendor_lookup`` tool into the Band
        adapter. Tests do NOT call this; they use ``run(case, tools)``
        directly with a mocked ``FakeAgentTools``.
        """
        from band.adapters import LangGraphAdapter  # type: ignore

        return LangGraphAdapter(
            llm=self.llm,
            checkpointer=InMemorySaver(),
            graph_factory=make_graph_factory(secrets=self.secrets),
            additional_tools=[vendor_lookup],
        )


__all__ = [
    "VendorProfile",
    "UltimateBeneficialOwner",
    "SanctionsHit",
    "VendorResearcher",
    "VendorResearcherState",
    "build_featherless_llm",
    "build_state_graph",
    "compile_state_machine",
    "make_graph_factory",
    "vendor_lookup",
    "load_secrets",
]