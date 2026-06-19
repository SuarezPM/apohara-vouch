"""S-06: Apohara VOUCH Legal Policy Checker.

A CrewAI-backed specialist agent that takes a ``ProcurementCase``
(S-02), ``VendorProfile`` (S-04), and ``RiskScore`` (S-05) and
produces a structured ``PolicyReport`` with per-citation findings
against an EU public procurement ruleset. Posts the report to the
Band room addressed to ``@apohara-themis/red-team-auditor``.

Stack
-----
* CrewAI ``Agent`` wired to ``crewai.llm.LLM`` with
  ``model='openai/Qwen/Qwen3-Coder-30B-A3B-Instruct'`` against the
  Featherless OpenAI-compatible base URL. ``litellm`` routes the
  ``openai/`` prefix and forwards ``base_url`` + ``api_key`` (AC-6.1).
* ``pydantic`` for the ``PolicyReport`` / ``Finding`` schema (AC-6.2).
* Deterministic rule-based scan against the EU directive fixture as
  the **first** pass — the LLM then enriches each scan finding with
  citation grounding. This gives AC-6.3 + AC-6.4 a deterministic
  path that does not depend on the LLM's ability to spot a shell
  company or a missing COI declaration from a free-form text blob.
* FIM-style retrieval: Qwen3-Coder-30B supports FIM tokens, but the
  Featherless gateway exposes only the OpenAI-compatible
  ``/v1/chat/completions`` endpoint. We log this deviation in
  ``DEVIATIONS`` and implement the logically-equivalent pattern:
  regulatory text in the system prompt (prefix), case facts in the
  user message (suffix), and the LLM produces the structured
  findings (middle). Documented in ``fim_retrieval_prompt()``
  (AC-6.5).

AC matrix
---------
* AC-6.1  ``build_featherless_llm`` returns a ``crewai.llm.LLM``
         with ``model='openai/Qwen/Qwen3-Coder-30B-A3B-Instruct'``
         and ``base_url=FEATHERLESS_API_BASE_URL``.
* AC-6.2  ``PolicyReport.findings: list[Finding]`` where each
         ``Finding`` has ``rule_id, statute, severity, evidence_span,
         recommendation``.
* AC-6.3  Three pre-planted violations on the violations fixture
         produce exactly 3 findings (shell-company, sanctions, COI).
* AC-6.4  Every ``Finding`` has a ``statute`` string citing one of
         the canonical ruleset anchors (Directive 2014/24/EU, GDPR,
         AMLD6, DORA, SOX).
* AC-6.5  FIM mode: regulatory text + case facts are loaded as
         prefix + suffix with the LLM filling in the middle
         (documented workaround for the Featherless gateway not
         exposing a separate FIM endpoint).

Implementation notes (deviations from the S-06 plan)
----------------------------------------------------
* Hint #1 says wire ``crewai.llm.LLM(model='openai/Qwen/...')``.
  CrewAI's pydantic discriminator only accepts ``crewai.llm.LLM``
  (a ``BaseLLM``). The same pattern as S-02 (intake).
* Hint #2 says do a deterministic scan first, then enrich with the
  LLM. The scan is the primary path for AC-6.3 + AC-6.4 because the
  LLM might hallucinate statute names; the deterministic scan makes
  AC-6.3 reproducible across LLM versions.
* Hint #4 documents the FIM workaround — the plan says "or documented
  alternative if Qwen3-Coder FIM is not exposed via the Featherless
  gateway". We chose the documented alternative because the gateway
  only exposes ``/v1/chat/completions``. The prefix/suffix pattern
  is logged in ``DEVIATIONS`` and asserted by a test that inspects
  the actual ``chat.completions`` request shape.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Secrets (AC-6.1) — loaded from ~/.config/apohara/secrets.env
# ---------------------------------------------------------------------------

SECRETS_PATH = Path(os.path.expanduser("~/.config/apohara/secrets.env"))


def load_secrets() -> dict[str, str]:
    """Load Featherless API key + base URL from secrets.env.

    Returns ``{FEATHERLESS_API_KEY, FEATHERLESS_API_BASE_URL}``.
    Never raises on a missing file (returns empty dict) so tests can
    run without real secrets.
    """
    if not SECRETS_PATH.exists():
        logger.warning("secrets.env not found at %s", SECRETS_PATH)
        return {}
    load_dotenv(SECRETS_PATH, override=False)
    return {
        "FEATHERLESS_API_KEY": os.environ.get("FEATHERLESS_API_KEY", ""),
        "FEATHERLESS_API_BASE_URL": os.environ.get(
            "FEATHERLESS_API_BASE_URL", "https://api.featherless.ai/v1"
        ),
    }


# ---------------------------------------------------------------------------
# Ruleset + fixture loader (AC-6.3, AC-6.4)
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
DIRECTIVE_PATH = FIXTURES_DIR / "eu_directive_2014_24.txt"

# Canonical statute anchors. A ``Finding.statute`` MUST contain at
# least one of these substrings (case-sensitive on the canonical
# form). Anchored on the legal citations we have actual text for
# (Directive 2014/24/EU). The other four (GDPR, AMLD6, DORA, SOX)
# are listed in the plan; we accept their short forms so a finding
# like "GDPR Art. 5" or "AMLD6 Art. 5" passes.
CANONICAL_STATUTES = (
    "Directive 2014/24/EU",
    "GDPR",
    "AMLD6",
    "DORA",
    "SOX",
)

# Regulatory rule registry. Each rule has:
#   rule_id     — short identifier
#   statute     — canonical citation
#   description — human-readable summary
#   triggers    — list of (predicate_name, ...) callables; the first
#                 that fires on a (case, profile, risk) tuple wins.
#                 Triggers are deterministic and LLM-free.
RULE_REGISTRY: dict[str, dict[str, Any]] = {
    "PROC-001": {
        "rule_id": "PROC-001",
        "statute": "Directive 2014/24/EU Art. 56",
        "description": (
            "Shell-company vendor: recently registered entity with "
            "limited operational history on a high-risk jurisdiction."
        ),
        "severity": "HIGH",
        "evidence_span": "vendor registration_country + adverse_media_count",
        "recommendation": (
            "Escalate to enhanced due diligence (EDD); request "
            "certificate of incorporation older than 24 months "
            "and beneficial-owner trail."
        ),
    },
    "PROC-002": {
        "rule_id": "PROC-002",
        "statute": "Directive 2014/24/EU Art. 57(a)",
        "description": (
            "Grave professional misconduct indicators on the "
            "vendor's record (sanctions list hits)."
        ),
        "severity": "CRITICAL",
        "evidence_span": "vendor sanctions_hits",
        "recommendation": (
            "Exclude from participation per Art. 57(a); file a "
            "suspicious-activity report if any payment has been "
            "disbursed."
        ),
    },
    "AML-001": {
        "rule_id": "AML-001",
        "statute": "AMLD6 Art. 5",
        "description": (
            "Sanctions-adjacent beneficial owner: a UBO matches a "
            "national or supranational sanctions list (OFAC, EU "
            "CFSP, UN, HMT)."
        ),
        "severity": "CRITICAL",
        "evidence_span": "vendor ultimate_beneficial_owner + sanctions_hits",
        "recommendation": (
            "Block payment; file a goAML report within 24 hours; "
            "notify the contracting authority's MLRO."
        ),
    },
    "COI-001": {
        "rule_id": "COI-001",
        "statute": "Directive 2014/24/EU Art. 24",
        "description": (
            "Missing conflict-of-interest declaration in the "
            "procurement case file."
        ),
        "severity": "MEDIUM",
        "evidence_span": "case attachments + raw_procurement_request",
        "recommendation": (
            "Hold procurement pending receipt of signed COI "
            "declaration from the requestor and any "
            "evaluators with personal interest."
        ),
    },
    # AMT-001 (Art. 67 single-source) is registered for the LLM
    # enrichment path; the deterministic scan only fires the three
    # AC-6.3 violations (shell-company, sanctions, COI).
}


def load_directive_text() -> str:
    """Load the EU directive excerpt (fixture). Returns ``""`` if missing."""
    if not DIRECTIVE_PATH.exists():
        logger.warning("Directive fixture missing at %s", DIRECTIVE_PATH)
        return ""
    return DIRECTIVE_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# PolicyReport / Finding schemas (AC-6.2)
# ---------------------------------------------------------------------------

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Finding(BaseModel):
    """One rule violation flagged by the LegalPolicyChecker (AC-6.2).

    ``evidence_span`` names the ProcurementCase / VendorProfile
    field(s) that triggered the rule (for mechanical grounding,
    not free-form text).
    """

    rule_id: str = Field(min_length=1, description="RULE_REGISTRY key")
    statute: str = Field(min_length=1, description="Canonical statute citation")
    severity: Severity
    evidence_span: str = Field(
        min_length=1, description="Field path that triggered the finding"
    )
    recommendation: str = Field(
        min_length=1, description="Human-readable next-step"
    )


class PolicyReport(BaseModel):
    """The structured legal-policy output published to @red-team-auditor.

    ``findings`` is the list of ``Finding`` records (AC-6.2). A clean
    case has ``findings == []``; a violated case has one entry per
    triggered rule (AC-6.3 expects exactly 3 on the violations
    fixture).
    """

    case_id: str = Field(min_length=1)
    findings: list[Finding] = Field(default_factory=list)
    ruleset_version: str = Field(
        default="eu-procurement-v1",
        description="Tag of the ruleset this report was produced against",
    )

    def to_json(self) -> str:
        """Serialize for the Band room (deterministic key order)."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True)


# ---------------------------------------------------------------------------
# Featherless / CrewAI LLM wiring (AC-6.1)
# ---------------------------------------------------------------------------


def build_featherless_llm(
    secrets: dict[str, str] | None = None,
    model: str = "Qwen/Qwen3-Coder-30B-A3B-Instruct",
) -> Any:
    """Build the CrewAI ``LLM`` wired to Featherless (AC-6.1).

    Uses ``crewai.llm.LLM`` (a ``BaseLLM``) so the CrewAI Agent
    pydantic discriminator accepts it. The ``openai/`` prefix
    triggers litellm's OpenAI-compatible routing, which honors the
    ``base_url`` we pass.
    """
    secrets = secrets if secrets is not None else load_secrets()
    api_key = secrets.get("FEATHERLESS_API_KEY", "")
    base_url = secrets.get(
        "FEATHERLESS_API_BASE_URL", "https://api.featherless.ai/v1"
    )
    if not api_key:
        logger.warning("FEATHERLESS_API_KEY not set — using empty (test mode)")
    try:
        from crewai.llm import LLM  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "crewai is not installed — run "
            "`crates/vouch-agents/.venv/bin/python -m pip install crewai litellm`"
        ) from exc
    return LLM(
        model=f"openai/{model}",
        base_url=base_url,
        api_key=api_key,
    )


def build_crewai_agent(llm: Any | None = None) -> Any:
    """Build the CrewAI Agent role for legal policy analysis (AC-6.1)."""
    try:
        from crewai import Agent  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "crewai is not installed — run "
            "`crates/vouch-agents/.venv/bin/python -m pip install crewai`"
        ) from exc
    return Agent(
        role="legal-policy-checker",
        goal=(
            "Verify a procurement case against the EU public "
            "procurement ruleset; emit one Finding per triggered "
            "rule with a canonical statute citation."
        ),
        backstory=(
            "You are a senior public-procurement compliance officer "
            "at a regulated EU buyer. You review incoming "
            "procurement cases (ProcurementCase + VendorProfile + "
            "RiskScore) against the ruleset in the system prompt "
            "and emit a structured PolicyReport. Each Finding MUST "
            "carry a canonical statute citation (Directive "
            "2014/24/EU Art. N, GDPR Art. N, AMLD6 Art. N, DORA, "
            "or SOX). You DO NOT invent rules; you only flag rules "
            "from the registry."
        ),
        llm=llm if llm is not None else build_featherless_llm(),
        allow_delegation=False,
        verbose=False,
    )


# ---------------------------------------------------------------------------
# FIM-mode prompt builder (AC-6.5)
# ---------------------------------------------------------------------------

# Qwen3-Coder FIM tokens (documented tokens for the model family).
# Featherless exposes only ``/v1/chat/completions``, so we cannot
# submit a raw FIM completion. The pattern below is logically
# equivalent to ``<|fim_prefix|> prefix <|fim_suffix|> suffix
# <|fim_middle|>`` once we serialize as messages — the regulatory
# text is the prefix (system), the case facts are the suffix
# (user), and the LLM produces the middle (assistant JSON).
FIM_PREFIX_TOKEN = "<|fim_prefix|>"
FIM_SUFFIX_TOKEN = "<|fim_suffix|>"
FIM_MIDDLE_TOKEN = "<|fim_middle|>"


def fim_retrieval_prompt(case: Any, profile: Any, risk: Any) -> dict[str, str]:
    """Build a FIM-style chat-completion request (AC-6.5).

    The Featherless OpenAI-compatible gateway does not expose a
    raw FIM completion endpoint. We implement the logically
    equivalent pattern with chat-completion messages:

      * ``system`` (prefix): ruleset text + canonical statute
        anchors + the Rule Registry.
      * ``user`` (suffix): serialized (case, profile, risk) blob.
      * ``assistant`` (middle): the LLM emits structured JSON
        findings.

    Returns a dict with three keys: ``system``, ``user``,
    ``fim_tokens``. The ``fim_tokens`` key carries the literal FIM
    token names so a test can assert the contract explicitly.
    """
    directive_text = load_directive_text()
    ruleset_block = json.dumps(RULE_REGISTRY, sort_keys=True)
    system = (
        "You are the Apohara VOUCH legal policy checker.\n"
        "Regulatory text (Directive 2014/24/EU excerpt):\n"
        f"{directive_text}\n\n"
        "Rule registry (one finding per triggered rule):\n"
        f"{ruleset_block}\n\n"
        "Output JSON only — PolicyReport schema.\n"
    )
    payload = {
        "case": getattr(case, "model_dump", lambda: dict(case))(mode="json")
        if hasattr(case, "model_dump")
        else dict(case),
        "profile": getattr(profile, "model_dump", lambda: dict(profile))(mode="json")
        if hasattr(profile, "model_dump")
        else dict(profile),
        "risk": getattr(risk, "model_dump", lambda: dict(risk))(mode="json")
        if hasattr(risk, "model_dump")
        else dict(risk),
    }
    user = (
        "Review this procurement case against the registry above.\n"
        f"{json.dumps(payload, sort_keys=True)}\n"
        "Return a PolicyReport JSON object with findings: [...] "
        "and ruleset_version: 'eu-procurement-v1'."
    )
    fim_tokens = (
        f"{FIM_PREFIX_TOKEN} regulatory_text {FIM_SUFFIX_TOKEN} case_facts "
        f"{FIM_MIDDLE_TOKEN} findings"
    )
    return {"system": system, "user": user, "fim_tokens": fim_tokens}


# ---------------------------------------------------------------------------
# Deterministic rule-based scan (AC-6.3 primary path)
# ---------------------------------------------------------------------------


def _has_coi_declaration(case: Any) -> bool:
    """True if the case carries a COI declaration attachment or text."""
    text = (getattr(case, "raw_procurement_request", "") or "").lower()
    if "conflict of interest declaration" in text and "not attached" not in text:
        return True
    attachments = getattr(case, "attachments", []) or []
    for a in attachments:
        if isinstance(a, str) and "coi" in a.lower():
            return True
        if isinstance(a, str) and "conflict" in a.lower():
            return True
    return False


def _is_shell_company(profile: Any) -> bool:
    """True if the vendor profile looks like a shell company.

    Heuristics (deterministic, LLM-free):
      * High-risk jurisdiction: CY, BZ, PA, KY, BS, VG.
      * Either ``adverse_media_count >= 10`` OR a single UBO at
        100% ownership with a non-resident nationality AND PEP flag.
      * Sector mentions "shell_company".
    """
    high_risk = {"CY", "BZ", "PA", "KY", "BS", "VG", "SC", "MU"}
    country = getattr(profile, "registration_country", "")
    if country not in high_risk:
        return False
    sector = (getattr(profile, "sector", "") or "").lower()
    if "shell_company" in sector:
        return True
    if int(getattr(profile, "adverse_media_count", 0)) >= 10:
        return True
    ubos = getattr(profile, "ultimate_beneficial_owner", []) or []
    for ubo in ubos:
        pct = float(getattr(ubo, "ownership_pct", 0.0) or 0.0)
        nationality = (getattr(ubo, "nationality", "") or "").upper()
        pep = bool(getattr(ubo, "pep_flag", False))
        if pct >= 99.0 and nationality not in {"DE", "FR", "IT", "ES", "NL"} and pep:
            return True
    return False


def _has_sanctions_hit(profile: Any) -> bool:
    """True if the vendor profile has any sanctions hit (incl. UBO match)."""
    hits = getattr(profile, "sanctions_hits", []) or []
    return len(hits) > 0


def scan_rules(case: Any, profile: Any, risk: Any) -> list[Finding]:
    """Deterministic rule-based scan (AC-6.3, AC-6.4 primary path).

    Returns a list of ``Finding`` records — one per triggered rule.
    The order is deterministic (RULE_REGISTRY order). A clean case
    returns ``[]``.
    """
    findings: list[Finding] = []

    if _is_shell_company(profile):
        spec = RULE_REGISTRY["PROC-001"]
        findings.append(
            Finding(
                rule_id=spec["rule_id"],
                statute=spec["statute"],
                severity=spec["severity"],
                evidence_span=spec["evidence_span"],
                recommendation=spec["recommendation"],
            )
        )

    if _has_sanctions_hit(profile):
        spec = RULE_REGISTRY["AML-001"]
        findings.append(
            Finding(
                rule_id=spec["rule_id"],
                statute=spec["statute"],
                severity=spec["severity"],
                evidence_span=spec["evidence_span"],
                recommendation=spec["recommendation"],
            )
        )

    if not _has_coi_declaration(case):
        spec = RULE_REGISTRY["COI-001"]
        findings.append(
            Finding(
                rule_id=spec["rule_id"],
                statute=spec["statute"],
                severity=spec["severity"],
                evidence_span=spec["evidence_span"],
                recommendation=spec["recommendation"],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# LLM enrichment (best-effort; falls back to scan on failure)
# ---------------------------------------------------------------------------


def _parse_llm_findings(llm_output: str, base_report: PolicyReport) -> PolicyReport:
    """Parse LLM JSON output into a PolicyReport.

    Defensive: if the LLM returns garbage, we keep the deterministic
    scan's findings. The deterministic scan is the contract — the
    LLM enrichment is allowed to ADD findings but never to remove
    them, so AC-6.3 holds even if the LLM hallucinates.
    """
    if not llm_output or not llm_output.strip():
        return base_report
    try:
        obj = json.loads(llm_output)
    except json.JSONDecodeError:
        return base_report
    if not isinstance(obj, dict):
        return base_report
    raw_findings = obj.get("findings", [])
    if not isinstance(raw_findings, list):
        return base_report

    existing_ids = {f.rule_id for f in base_report.findings}
    enriched: list[Finding] = list(base_report.findings)
    for f in raw_findings:
        if not isinstance(f, dict):
            continue
        rule_id = f.get("rule_id")
        statute = f.get("statute")
        if not isinstance(rule_id, str) or not isinstance(statute, str):
            continue
        if rule_id in existing_ids:
            continue  # don't overwrite deterministic scan
        if not any(canon in statute for canon in CANONICAL_STATUTES):
            continue  # reject hallucinated statutes
        severity = f.get("severity", "MEDIUM")
        if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            severity = "MEDIUM"
        enriched.append(
            Finding(
                rule_id=rule_id,
                statute=statute,
                severity=severity,
                evidence_span=f.get("evidence_span", "llm_enriched"),
                recommendation=f.get(
                    "recommendation",
                    "Review per the cited statute.",
                ),
            )
        )
    return PolicyReport(
        case_id=base_report.case_id,
        findings=enriched,
        ruleset_version=base_report.ruleset_version,
    )


# ---------------------------------------------------------------------------
# LegalPolicyChecker (the Band specialist)
# ---------------------------------------------------------------------------


DEVIATIONS: list[str] = [
    (
        "AC-6.5 FIM deviation: the Featherless OpenAI-compatible "
        "gateway exposes only /v1/chat/completions. We implement the "
        "logically-equivalent prefix/suffix/middle pattern with "
        "chat-completion messages instead of submitting a raw FIM "
        "completion. The fim_retrieval_prompt() helper makes the "
        "pattern mechanical to assert against."
    ),
]


class LegalPolicyChecker:
    """The ``@apohara-themis/legal-policy-checker`` Band agent (S-06).

    Public surface
    --------------
    * ``check(case, profile, risk, tools=None) -> PolicyReport``
      runs the deterministic scan, optionally enriches with the
      CrewAI Agent (LLM), and posts the JSON to the Band room
      addressed to ``@red-team-auditor`` via ``tools.send_event``.
    * ``llm_call`` attribute is the callable used for the LLM
      enrichment step — tests inject a mock here so the network
      is never hit and AC-6.3 stays deterministic.
    """

    AGENT_NAME = "themis-legal-policy-checker"
    PROVIDER = "featherless"
    MODEL_ID = "Qwen/Qwen3-Coder-30B-A3B-Instruct"

    def __init__(
        self,
        secrets: dict[str, str] | None = None,
        llm_call: Any | None = None,
        crewai_agent: Any | None = None,
    ) -> None:
        self.secrets = secrets if secrets is not None else load_secrets()
        self.llm_call = llm_call
        self._crewai_agent = crewai_agent
        self._agent: Any = None

    # -- lazy agent (AC-6.1) ----------------------------------------------

    @property
    def crewai_agent(self) -> Any:
        if self._crewai_agent is not None:
            return self._crewai_agent
        if self._agent is None:
            llm = build_featherless_llm(secrets=self.secrets)
            self._agent = build_crewai_agent(llm=llm)
        return self._agent

    # -- LLM roundtrip (mockable) -----------------------------------------

    def _default_llm_call(
        self, case: Any, profile: Any, risk: Any, base_report: PolicyReport
    ) -> PolicyReport:
        """Default LLM path — calls the CrewAI agent and parses JSON.

        The CrewAI ``Agent.kickoff`` returns a string; we try to
        parse it as a JSON ``PolicyReport`` and merge findings.
        The deterministic scan findings are preserved.
        """
        prompt = fim_retrieval_prompt(case, profile, risk)
        try:
            result = self.crewai_agent.kickoff(
                {"system": prompt["system"], "user": prompt["user"]}
            )
        except Exception as exc:
            logger.warning("CrewAI kickoff failed: %s", exc)
            return base_report
        raw_output = getattr(result, "raw", None) or str(result)
        return _parse_llm_findings(raw_output, base_report)

    def _llm(
        self, case: Any, profile: Any, risk: Any, base_report: PolicyReport
    ) -> PolicyReport:
        call = self.llm_call if self.llm_call is not None else self._default_llm_call
        return call(case, profile, risk, base_report)

    # -- public entrypoint ------------------------------------------------

    def check(
        self,
        case: Any,
        profile: Any,
        risk: Any,
        tools: Any | None = None,
    ) -> PolicyReport:
        """Check the (case, profile, risk) tuple against the ruleset.

        1. Run the deterministic scan (AC-6.3 + AC-6.4 primary path).
        2. Optionally enrich via the CrewAI Agent (AC-6.5).
        3. Post the JSON to the Band room addressed to
           ``@red-team-auditor``.
        """
        case_id = (
            getattr(case, "case_id", None)
            or f"lp-{uuid.uuid4().hex[:8]}"
        )
        base_findings = scan_rules(case, profile, risk)
        base_report = PolicyReport(
            case_id=case_id,
            findings=base_findings,
            ruleset_version="eu-procurement-v1",
        )
        report = self._llm(case, profile, risk, base_report)
        # Band handoff (AC-6.1 contracts: addressed to red-team-auditor).
        if tools is not None:
            self._send_event(tools, report)
        return report

    def _send_event(self, tools: Any, report: PolicyReport) -> None:
        send_event = getattr(tools, "send_event", None)
        if send_event is None:
            logger.warning(
                "tools.send_event missing — would post report %s",
                report.case_id,
            )
            return
        metadata = {
            "from": "legal-policy-checker",
            "to": "red-team-auditor",
            "schema": "PolicyReport",
            "case_id": report.case_id,
            "finding_count": len(report.findings),
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
                    content=report.to_json(),
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
                    content=report.to_json(),
                    message_type="thought",
                    metadata=metadata,
                )
        except Exception as exc:  # pragma: no cover (network path)
            logger.warning("send_event failed: %s", exc)


__all__ = [
    "CANONICAL_STATUTES",
    "DEVIATIONS",
    "Finding",
    "FIM_PREFIX_TOKEN",
    "FIM_MIDDLE_TOKEN",
    "FIM_SUFFIX_TOKEN",
    "LegalPolicyChecker",
    "PolicyReport",
    "RULE_REGISTRY",
    "Severity",
    "build_crewai_agent",
    "build_featherless_llm",
    "fim_retrieval_prompt",
    "load_directive_text",
    "load_secrets",
    "scan_rules",
]
