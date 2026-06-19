"""S-07b: Local compliance-veto fallback agent.

A lightweight, no-network fallback for the cross-account
``@apohara-themis/compliance-veto-acme`` agent. Same ``VetoDecision``
schema, same ``regulatory_clock`` semantics, but driven by a
deterministic rule-based scan instead of the AI/ML API haiku
roundtrip.

When the primary cross-account WebSocket dies 3+ times (the chaos
harness in ``tests/test_compliance_fallback_chaos.py``), the
``ComplianceFallback`` activates and emits a veto event with the
``fallback=True`` flag set. The Orchestrator recognizes this flag and
flips the ``DEGRADED`` banner on the demo UI.

Stack
-----
* ``pydantic`` for the ``VetoDecision`` schema (mirrors
  ``compliance_veto.VetoDecision`` so the Orchestrator treats both
  transports identically).
* Deterministic rule-based scan: triggers when ANY
  ``RiskScore.severity == "CRITICAL"`` is present OR a regulatory
  clock anchor is mentioned (GDPR Art. 33, DORA Art. 17, SOX 404).
* No LLM — the fallback exists for the case where the LLM transport
  is unavailable. Production transports via the local process
  (``tools.send_event``) — no Band WebSocket needed.
* Public surface: ``fallback.evaluate(case, risk, policy) -> VetoDecision``.

AC matrix (S-07b)
-----------------
* AC-7b.2  The fallback uses the same ``VetoDecision`` schema as the
         primary agent. ``fallback.evaluate`` returns a ``VetoDecision``
         with ``verdict`` ∈ ``{"veto", "approve"}`` and
         ``regulatory_clock`` ∈ ``{"DORA-Art-17", "GDPR-Art-33",
         "SOX-404"}``.
* AC-7b.5  When the chaos harness kills the cross-account WebSocket
         3x in 10 runs, the fallback veto fires 10/10 AND the
         Orchestrator sets ``DEGRADED`` on the demo UI state.

Implementation notes
--------------------
* ``compliance_fallback.py`` lives under
  ``crates/vouch-orchestrator/src/`` per the S-07b plan. The crate is
  Rust-only for the HTTP surface; this Python module is imported by
  the Python orchestrator and the tests under
  ``crates/vouch-agents/tests/``. Path deviation from the plan's
  ``vouch-agents/src/compliance_fallback.py`` is documented in
  ``DEVIATIONS`` — the rationale is that ``vouch-orchestrator`` is
  the orchestrator-side component, which is the natural home for
  the fallback path that activates when the primary agent's
  transport dies.
"""

from __future__ import annotations

from llm_secrets import load_aiml_only
# Backwards-compat alias (M1 refactor: replaced local load_secrets() with llm_secrets)
load_secrets = load_aiml_only

import json
import logging
import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# VetoDecision schema (matches compliance_veto.VetoDecision exactly)
# ---------------------------------------------------------------------------

Verdict = Literal["veto", "approve"]
RegulatoryClock = Literal["DORA-Art-17", "GDPR-Art-33", "SOX-404"]


class VetoDecision(BaseModel):
    """The structured veto output (S-07b AC-7b.2, AC-7b.5).

    Both the primary cross-account agent and this fallback emit this
    schema. The Orchestrator treats both transports identically — the
    only difference is the ``fallback`` flag, which flips the
    ``DEGRADED`` banner in the demo UI.
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
# Deterministic rule scan (no LLM — works offline, AC-7b.5)
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
    """Pick the regulatory clock (DORA-Art-17 > GDPR-Art-33 > SOX-404).

    Precedence matches S-07b plan: a DORA ICT-risk incident takes the
    17 working-day DORA reporting clock; a personal-data breach takes
    the GDPR 72h clock; otherwise SOX 404 (internal controls).
    """
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
# ComplianceFallback — the local agent
# ---------------------------------------------------------------------------


DEVIATIONS: list[str] = [
    (
        "Path deviation: the S-07b plan writes compliance_fallback.py "
        "to crates/vouch-orchestrator/src/. This crate is Rust-only "
        "(HTTP surface in http.rs + lib.rs). The Python module lives "
        "here per the plan; imports are resolved by the Python test "
        "runner (crates/vouch-agents/tests/) which adds the file's "
        "directory to sys.path on test load. The Python module does "
        "NOT participate in cargo build."
    ),
]


class ComplianceFallback:
    """The local fallback agent (S-07b AC-7b.2, AC-7b.5).

    Activated when the cross-account WebSocket has been killed 3+
    times in a single run (chaos harness). Emits the same
    ``VetoDecision`` schema as the primary agent so the Orchestrator
    treats both transports identically.
    """

    AGENT_NAME = "compliance-veto-fallback"
    PROVIDER = "local-fallback"
    MODEL_ID = "rule-based"

    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self.secrets = secrets if secrets is not None else load_secrets()

    def evaluate(
        self,
        case: Any,
        risk: Any,
        policy: Any,
        *,
        fallback: bool = True,
        fallback_reason: str = "cross_account_websocket_killed",
    ) -> VetoDecision:
        """Run the deterministic rule scan and emit a VetoDecision.

        ``fallback`` is True when this is invoked from the chaos
        harness; the Orchestrator checks the flag to set the
        ``DEGRADED`` banner.
        """
        case_id = (
            getattr(case, "case_id", None) or f"cfb-{uuid.uuid4().hex[:8]}"
        )
        critical = _has_critical(risk, policy)
        clock = _detect_clock(case, risk)
        if critical:
            reason = (
                "CRITICAL severity detected (local rule scan); "
                f"regulatory clock: {clock}."
            )
            return VetoDecision(
                case_id=case_id,
                verdict="veto",
                reason=reason,
                regulatory_clock=clock,
                fallback=fallback,
                fallback_reason=fallback_reason if fallback else "",
            )
        return VetoDecision(
            case_id=case_id,
            verdict="approve",
            reason=(
                "No CRITICAL severity detected; case proceeds under "
                f"{clock} controls."
            ),
            regulatory_clock=clock,
            fallback=fallback,
            fallback_reason=fallback_reason if fallback else "",
        )


__all__ = [
    "DEVIATIONS",
    "ComplianceFallback",
    "RegulatoryClock",
    "Verdict",
    "VetoDecision",
    "load_secrets",
]
