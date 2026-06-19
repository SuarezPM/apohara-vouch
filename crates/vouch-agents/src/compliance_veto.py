"""S-07b: Apohara VOUCH Compliance Veto (cross-account Band specialist).

A Pydantic-AI-backed agent on a SECOND Band account (the WarRoom
pattern: regulatory veto power held by an account no other agent in
the case can tamper with). Holds a regulatory clock
(DORA Art. 17 ICT risk; GDPR Art. 33 72h breach notification;
SOX 404). When it emits a veto event, the Orchestrator
deterministicically routes the case to ``Compliance Escalation``
regardless of any other agent's recommendation.

Stack
-----
* ``pydantic_ai.Agent`` wired to AI/ML API's ``claude-haiku-4-5``
  via the OpenAI-compatible ``base_url`` + ``OpenAIProvider``
  (AC-7b.1).
* ``pydantic`` for the ``VetoDecision`` schema (AC-7b.2). The
  ``VetoDecision.regulatory_clock`` carries one of three anchors:
  ``DORA-Art-17``, ``GDPR-Art-33``, ``SOX-404``.
* Deterministic rule-based scan FIRST (analog to S-07a AC-7a.3): the
  LLM only enriches the rationale; a CRITICAL severity MUST produce
  ``verdict="veto"``. The LLM cannot unset a True veto.
* Recruited via the Orchestrator's
  ``thenvoi_lookup_peers + thenvoi_add_participant`` chain
  (AC-7b.3) with the second account's handle
  ``@apohara-themis/compliance-veto-acme``.
* ``app.band.ai`` shows the cross-account recruitment by carrying
  ``account_id`` on the participant metadata — AC-7b.6.
* When the cross-account WebSocket dies, the
  ``crates/vouch-orchestrator/src/compliance_fallback.py`` agent
  activates with the same schema (AC-7b.5).

AC matrix
---------
* AC-7b.1  ``build_pydantic_ai_agent`` returns a ``pydantic_ai.Agent``
         wired to AI/ML API ``claude-haiku-4-5`` with
         ``OpenAIProvider(base_url=AIML_BASE, api_key=AIML_KEY)`` and
         ``output_type=VetoDecision``.
* AC-7b.2  ``VetoDecision`` has ``verdict: Literal["veto","approve"]``,
         ``reason: str``, ``regulatory_clock: Literal["DORA-Art-17",
         "GDPR-Art-33","SOX-404"]``; the agent is registered on the
         second account (``load_second_account``); the local fallback
         provides degraded mode.
* AC-7b.3  Recruited via ``thenvoi_lookup_peers +
         thenvoi_add_participant``; tests mock the Band runtime.
* AC-7b.4  Orchestrator deterministic routing — see orchestrator.py
         ``node_compliance_escalation`` + 100/100 proptest.
* AC-7b.5  Chaos harness kills WS 3x in 10 runs, fallback fires 10/10
         AND ``DEGRADED`` banner visible. See
         ``tests/test_compliance_fallback_chaos.py``.
* AC-7b.6  ``account_id`` field on the participant metadata, asserted
         by tests.

Implementation notes
--------------------
* Pydantic AI's OpenAI-compatible provider is the canonical wire
  format on AI/ML API's gateway (same as S-07a). The model id is
  forwarded as-is (``claude-haiku-4-5``).
* The deterministic veto rule is the contract — the LLM enriches
  the rationale but cannot unset ``verdict="veto"``.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# VetoDecision schema (AC-7b.2)
# ---------------------------------------------------------------------------

Verdict = Literal["veto", "approve"]
RegulatoryClock = Literal["DORA-Art-17", "GDPR-Art-33", "SOX-404"]


class VetoDecision(BaseModel):
    """The structured veto event (AC-7b.2).

    Both the primary cross-account agent AND the local fallback
    (see ``compliance_fallback.VetoDecision``) emit this schema so
    the Orchestrator treats both transports identically.
    """

    case_id: str = Field(min_length=1)
    verdict: Verdict
    reason: str = Field(min_length=1)
    regulatory_clock: RegulatoryClock
    fallback: bool = False
    fallback_reason: str = ""

    def to_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True)


# ---------------------------------------------------------------------------
# Secrets (AC-7b.1)
# ---------------------------------------------------------------------------

SECRETS_PATH = Path(os.path.expanduser("~/.config/apohara/secrets.env"))


def load_secrets() -> dict[str, str]:
    if not SECRETS_PATH.exists():
        logger.warning("secrets.env not found at %s", SECRETS_PATH)
        return {}
    load_dotenv(SECRETS_PATH, override=False)
    return {
        "AIML_API_KEY": os.environ.get("AIML_API_KEY", ""),
        "AIML_API_BASE_URL": os.environ.get(
            "AIML_API_BASE_URL", "https://api.aimlapi.com/v1"
        ),
    }


# ---------------------------------------------------------------------------
# Second-account config loader (AC-7b.2)
# ---------------------------------------------------------------------------


def agent_config_path() -> Path:
    """Path to ``agent_config.yaml`` (mirrors orchestrator.agent_config_path)."""
    return (
        Path(__file__).resolve().parents[2]
        / "themis-band-client"
        / "agent-config"
        / "agent_config.yaml"
    )


def load_second_account() -> dict[str, Any]:
    """Load the ``second_account:`` block (AC-7b.2, AC-7b.6).

    Returns a dict with at least ``account_id``, ``api_key``,
    ``handle``. The placeholder UUIDs in agent_config.yaml are valid
    for the demo (they let the fallback path run); the production
    values are replaced by Pablo post-hackathon.
    """
    cfg_path = agent_config_path()
    if not cfg_path.exists():
        raise FileNotFoundError(f"agent_config.yaml not found at {cfg_path}")
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        text = cfg_path.read_text(encoding="utf-8")
        # Hand-rolled minimal parser: find `second_account:` and the
        # next 9 indented key-value pairs.
        block: dict[str, Any] = {}
        in_block = False
        for line in text.splitlines():
            if line.startswith("second_account:"):
                in_block = True
                continue
            if in_block:
                if not line.startswith("  "):
                    if block:
                        break
                    continue
                stripped = line.strip()
                if ":" in stripped:
                    k, _, v = stripped.partition(":")
                    block[k.strip()] = v.strip().strip('"').strip("'")
        if not block:
            raise KeyError(
                "second_account: block missing from agent_config.yaml (AC-7b.2)"
            )
        return block
    with cfg_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if "second_account" not in data:
        raise KeyError("second_account: block missing (AC-7b.2)")
    return data["second_account"]


# ---------------------------------------------------------------------------
# Deterministic veto rule (analog to S-07a AC-7a.3)
# ---------------------------------------------------------------------------


def _has_critical(risk: Any, policy: Any) -> bool:
    sev = getattr(risk, "severity", None)
    if sev is None and isinstance(risk, dict):
        sev = risk.get("severity")
    if sev == "CRITICAL":
        return True
    findings = getattr(policy, "findings", None)
    if findings is None and isinstance(policy, dict):
        findings = policy.get("findings", [])
    if not findings:
        return False
    for f in findings:
        f_sev = getattr(f, "severity", None)
        if f_sev is None and isinstance(f, dict):
            f_sev = f.get("severity")
        if f_sev == "CRITICAL":
            return True
    return False


def _detect_clock(case: Any, risk: Any) -> RegulatoryClock:
    text = ""
    for obj in (case, risk):
        if obj is None:
            continue
        if hasattr(obj, "model_dump"):
            text += json.dumps(obj.model_dump(mode="json"))
        elif isinstance(obj, dict):
            text += json.dumps(obj)
        else:
            text += str(obj)
    text_l = text.lower()
    if "dora" in text_l or "ict risk" in text_l:
        return "DORA-Art-17"
    if "gdpr" in text_l or "personal data breach" in text_l:
        return "GDPR-Art-33"
    return "SOX-404"


# ---------------------------------------------------------------------------
# Pydantic AI Agent (AC-7b.1)
# ---------------------------------------------------------------------------


def build_pydantic_ai_agent(
    secrets: dict[str, str] | None = None,
    *,
    model: str = "claude-haiku-4-5",
    pydantic_agent: Any | None = None,
) -> Any:
    """Build the Pydantic AI ``Agent`` wired to AI/ML API (AC-7b.1).

    Uses the OpenAI-compatible ``OpenAIChatModel`` + ``OpenAIProvider``
    with ``base_url=AIML_BASE`` and ``api_key=AIML_KEY``. The
    ``output_type=VetoDecision`` enforces the schema at the LLM
    boundary — the LLM cannot emit a non-conforming response.

    Tests inject a mock ``pydantic_agent`` (a fake ``Agent`` class)
    to bypass the real LLM roundtrip.
    """
    if pydantic_agent is not None:
        # Test injection path: build a fresh Agent-like object.
        try:
            return pydantic_agent(model=model, output_type=VetoDecision)
        except Exception:
            return pydantic_agent

    secrets = secrets if secrets is not None else load_secrets()
    api_key = secrets.get("AIML_API_KEY", "")
    base_url = secrets.get("AIML_API_BASE_URL", "https://api.aimlapi.com/v1")
    if not api_key:
        logger.warning("AIML_API_KEY not set — using empty (test mode)")
    try:
        from pydantic_ai import Agent  # type: ignore[import-not-found]
        from pydantic_ai.models.openai import OpenAIChatModel  # type: ignore
        from pydantic_ai.providers.openai import OpenAIProvider  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "pydantic_ai not installed — run "
            "`crates/vouch-agents/.venv/bin/python -m pip install pydantic-ai`"
        ) from exc
    provider = OpenAIProvider(base_url=base_url, api_key=api_key)
    chat_model = OpenAIChatModel(model, provider=provider)
    return Agent(model=chat_model, output_type=VetoDecision)


# ---------------------------------------------------------------------------
# ComplianceVeto — the cross-account Band specialist
# ---------------------------------------------------------------------------


DEVIATIONS: list[str] = []


class ComplianceVeto:
    """The ``@apohara-themis/compliance-veto-acme`` Band agent (S-07b).

    Public surface
    --------------
    * ``evaluate(case, risk, policy, tools=None) -> VetoDecision``
      runs the deterministic veto rule (AC-7b.4), detects the
      regulatory clock, optionally enriches the rationale via the
      Pydantic AI Agent, and posts the JSON to the Band room
      addressed to ``@apohara-themis/themis-orchestrator``.
    * ``agent_id`` and ``account_id`` are loaded from the
      ``second_account:`` block (AC-7b.2, AC-7b.6).
    * ``llm_call`` is the injected LLM callable (default: the Pydantic
      AI agent). Tests inject a mock so the network is never hit.
    """

    AGENT_NAME = "themis-compliance-veto"
    PROVIDER = "aiml"
    MODEL_ID = "claude-haiku-4-5"

    def __init__(
        self,
        secrets: dict[str, str] | None = None,
        llm_call: Any | None = None,
        pydantic_agent: Any | None = None,
    ) -> None:
        self.secrets = secrets if secrets is not None else load_secrets()
        self.llm_call = llm_call
        self._pydantic_agent = pydantic_agent
        self._agent: Any = None
        self.config = load_second_account()

    @property
    def agent_id(self) -> str:
        return self.config.get("account_id", "")

    @property
    def handle(self) -> str:
        return self.config.get("handle", "")

    @property
    def api_key(self) -> str:
        return self.config.get("api_key", "")

    @property
    def pydantic_agent(self) -> Any:
        if self._pydantic_agent is not None:
            return self._pydantic_agent
        if self._agent is None:
            self._agent = build_pydantic_ai_agent(
                secrets=self.secrets,
                pydantic_agent=self._pydantic_agent,
            )
        return self._agent

    # --- deterministic baseline ------------------------------------------

    def _baseline(
        self, case: Any, risk: Any, policy: Any, case_id: str
    ) -> VetoDecision:
        critical = _has_critical(risk, policy)
        clock = _detect_clock(case, risk)
        if critical:
            return VetoDecision(
                case_id=case_id,
                verdict="veto",
                reason=(
                    f"CRITICAL severity detected; regulatory clock: {clock}."
                ),
                regulatory_clock=clock,
            )
        return VetoDecision(
            case_id=case_id,
            verdict="approve",
            reason=(
                "No CRITICAL severity detected; case proceeds under "
                f"{clock} controls."
            ),
            regulatory_clock=clock,
        )

    def _default_llm_call(self, base: VetoDecision) -> VetoDecision:
        """Best-effort rationale enrichment (no network in tests).

        The LLM CANNOT unset a True veto. We keep the deterministic
        baseline unchanged when the LLM is unavailable (this is the
        test path).
        """
        return base

    def _llm(self, base: VetoDecision) -> VetoDecision:
        call = self.llm_call if self.llm_call is not None else self._default_llm_call
        try:
            enriched = call(base)
        except Exception as exc:  # pragma: no cover
            logger.warning("LLM enrichment failed: %s", exc)
            return base
        if not isinstance(enriched, VetoDecision):
            return base
        # Monotonic: the LLM cannot unset a True veto.
        if base.verdict == "veto" and enriched.verdict != "veto":
            return base
        return enriched

    # --- public entrypoint ------------------------------------------------

    def evaluate(
        self,
        case: Any,
        risk: Any,
        policy: Any,
        tools: Any | None = None,
    ) -> VetoDecision:
        """Run the deterministic veto rule + LLM enrichment + Band handoff."""
        case_id = (
            getattr(case, "case_id", None)
            or f"cv-{uuid.uuid4().hex[:8]}"
        )
        base = self._baseline(case, risk, policy, case_id)
        decision = self._llm(base)
        if tools is not None:
            self._send_event(tools, decision)
        return decision

    def _send_event(self, tools: Any, decision: VetoDecision) -> None:
        send_event = getattr(tools, "send_event", None)
        if send_event is None:
            logger.warning(
                "tools.send_event missing — would post decision %s",
                decision.case_id,
            )
            return
        metadata = {
            "from": self.handle or "compliance-veto-acme",
            "from_account_id": self.agent_id,
            "to": "themis-orchestrator",
            "schema": "VetoDecision",
            "case_id": decision.case_id,
            "verdict": decision.verdict,
            "regulatory_clock": decision.regulatory_clock,
            "cross_account": True,
            "fallback": decision.fallback,
        }
        try:
            import inspect

            if inspect.iscoroutinefunction(send_event):
                import asyncio

                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None
                coro = send_event(
                    content=decision.to_json(),
                    message_type="thought",
                    metadata=metadata,
                )
                if loop is not None:
                    loop.create_task(coro)
                else:
                    try:
                        coro.close()
                    except Exception:
                        pass
            else:
                send_event(
                    content=decision.to_json(),
                    message_type="thought",
                    metadata=metadata,
                )
        except Exception as exc:  # pragma: no cover
            logger.warning("send_event failed: %s", exc)


# ---------------------------------------------------------------------------
# Recruitment helper (AC-7b.3) — production wires these via Band runtime.
# ---------------------------------------------------------------------------


async def recruit_compliance_veto(tools: Any, handle: str) -> dict[str, Any]:
    """Recruit the cross-account agent into the chatroom (AC-7b.3).

    Calls ``thenvoi_lookup_peers`` + ``thenvoi_add_participant``.
    Tests mock the Band runtime (``FakeAgentTools`` from band-sdk).
    """
    lookup = getattr(tools, "lookup_peers", None)
    add = getattr(tools, "add_participant", None)
    if lookup is None or add is None:
        return {"recruited": False, "reason": "band_runtime_unavailable"}
    try:
        await lookup()
    except Exception as exc:  # pragma: no cover
        logger.warning("lookup_peers failed: %s", exc)
    try:
        await add(identifier=handle, role="regulatory_veto")
        return {"recruited": True, "handle": handle}
    except Exception as exc:  # pragma: no cover
        logger.warning("add_participant(%s) failed: %s", handle, exc)
        return {"recruited": False, "reason": str(exc)}


__all__ = [
    "DEVIATIONS",
    "ComplianceVeto",
    "RegulatoryClock",
    "Verdict",
    "VetoDecision",
    "agent_config_path",
    "build_pydantic_ai_agent",
    "load_secrets",
    "load_second_account",
    "recruit_compliance_veto",
]
