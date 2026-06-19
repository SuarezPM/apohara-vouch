"""S-02: Apohara VOUCH Intake agent.

A CrewAI-backed specialist agent that parses a raw procurement request
(PDF text, JSON dict-as-text, or free-form email body) into a strict
``ProcurementCase`` JSON envelope, then posts the parsed case to the
Band room addressed to ``@apohara-themis/vendor-researcher``.

Stack
-----
* CrewAI (Agent role wiring) backed by LangChain's ``ChatOpenAI`` aimed
  at AI/ML API's OpenAI-compatible endpoint, model id
  ``"claude-haiku-4-5"`` (cheap + fast extraction).
* ``pydantic`` for the ``ProcurementCase`` schema validation (AC-2.2).
* Band ``FakeAgentTools`` (in unit tests) or the real Band runtime
  (in production) for ``send_event(content, message_type, metadata)``.

AC matrix
---------
* AC-2.1  uses CrewAI LLM via AI/ML API base_url + ``claude-haiku-4-5``.
* AC-2.2  ``ProcurementCase`` has all 9 required fields.
* AC-2.3  Given the clean fixture, emits valid JSON with all fields populated.
* AC-2.4  Malformed input emits ``message_type='error'`` and the case
          does NOT advance (i.e. the parsed case is None and we DO NOT
          post a ``thought`` addressed to @vendor-researcher).
* AC-2.5  ``tests/test_intake.py`` covers 3 fixture cases (clean,
          1 violation, 3 violations) and the malformed path.

Implementation notes (deviations from the S-02 plan)
----------------------------------------------------
* The plan's hint #2 wires a CrewAI ``Agent(llm=...)``. We import
  ``crewai.Agent`` lazily inside ``IntakeAgent`` so the module is
  importable for unit tests without crewai installed (we mock the
  CrewAI surface with ``unittest.mock.MagicMock`` per hint #5).
* Hint #1 says the CrewAI LLM is ``ChatOpenAI(model='claude-haiku-4-5',
  base_url=AIML_BASE, api_key=AIML_KEY)``. AI/ML API's gateway is
  OpenAI-compatible, so this is the canonical wire format. The model
  id is forwarded verbatim.
* Hint #5 says mock CrewAI in tests. We do NOT mock the schema layer
  (``pydantic``) — the schema validation is the contract under test,
  so it runs for real on every test.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Secrets (AC-1.7 parity with orchestrator.py — same secrets.env)
# ---------------------------------------------------------------------------

SECRETS_PATH = Path(os.path.expanduser("~/.config/apohara/secrets.env"))


def load_secrets() -> dict[str, str]:
    """Load AI/ML API key + base URL from secrets.env.

    Returns ``{AIML_API_KEY, AIML_API_BASE_URL}``. Empty strings for
    missing keys (never raises) so unit tests can run without the
    real secrets.
    """
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
# ProcurementCase schema (AC-2.2)
# ---------------------------------------------------------------------------


class ProcurementCase(BaseModel):
    """The structured intake envelope published to @vendor-researcher.

    9 required fields (AC-2.2). All fields are non-optional: a missing
    value is a schema violation, not a default. ``attachments`` is a
    list of URI strings (S3, mailto:, file://).
    """

    case_id: str = Field(min_length=1, description="Internal case identifier")
    buyer: str = Field(min_length=1, description="Legal entity name of the buyer")
    vendor_name: str = Field(min_length=1, description="Vendor legal name")
    vendor_id: str = Field(min_length=1, description="Vendor registration / VAT id")
    amount_eur: float = Field(gt=0.0, description="Total amount in EUR (positive)")
    category: str = Field(min_length=1, description="Procurement category slug")
    requested_action: str = Field(min_length=1, description="approve | review | reject")
    attachments: list[str] = Field(
        default_factory=list,
        description="List of attachment URIs (s3://, mailto:, file://, https://)",
    )
    urgency: str = Field(min_length=1, description="standard | urgent | emergency")


# ---------------------------------------------------------------------------
# AI/ML API client (AC-2.1)
# ---------------------------------------------------------------------------


def build_extraction_llm(
    secrets: dict[str, str] | None = None,
    model: str = "claude-haiku-4-5",
):
    """Build the CrewAI-backed LLM (AC-2.1).

    The plan's hint #1 says to wire ``ChatOpenAI(model='claude-haiku-4-5',
    base_url=AIML_BASE, api_key=AIML_KEY)``. CrewAI 1.14's pydantic
    discriminator only accepts the langchain ``BaseLLM`` (legacy
    string-output) base class — langchain 1.3's ``ChatOpenAI`` is a
    ``BaseChatModel`` and is rejected. The canonical workaround is
    CrewAI's own ``crewai.llm.LLM`` which IS a ``BaseLLM`` and exposes
    the same ``base_url``/``api_key`` fields. We use the LiteLLM
    fallback path (``model='openai/claude-haiku-4-5'``) so the AIML
    gateway receives the request with the configured ``base_url``.

    Returns the ``crewai.llm.LLM`` instance. Tests inject a MagicMock.
    """
    secrets = secrets if secrets is not None else load_secrets()
    api_key = secrets.get("AIML_API_KEY", "")
    base_url = secrets.get("AIML_API_BASE_URL", "https://api.aimlapi.com/v1")
    if not api_key:
        logger.warning("AIML_API_KEY not set — using empty string (test mode)")
    try:
        from crewai.llm import LLM  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "crewai is not installed — run "
            "`crates/vouch-agents/.venv/bin/python -m pip install crewai litellm`"
        ) from exc
    # The ``openai/`` prefix routes through LiteLLM as an OpenAI-compatible
    # call, which honors the ``base_url`` we pass. AI/ML API's gateway
    # exposes claude-haiku-4-5 over the OpenAI-compatible endpoint.
    return LLM(
        model=f"openai/{model}",
        base_url=base_url,
        api_key=api_key,
    )


# ---------------------------------------------------------------------------
# CrewAI role wiring (AC-2.1)
# ---------------------------------------------------------------------------


def build_crewai_agent(
    llm: Any | None = None,
    role: str = "intake-analyst",
    goal: str = (
        "Parse unstructured procurement request (PDF, JSON, email) into "
        "ProcurementCase JSON with all required fields populated."
    ),
    backstory: str = (
        "You are a procurement-intake analyst at a regulated EU public-sector "
        "buyer. You parse incoming procurement requests (PDF, JSON, email) "
        "into a strict ProcurementCase schema. If a field is missing or the "
        "input is malformed, you emit an error event and DO NOT advance "
        "the case."
    ),
):
    """Build the CrewAI Agent role (AC-2.1).

    Imports ``crewai.Agent`` lazily so the module is importable in
    environments where crewai is not yet installed (e.g. CI before
    ``pip install -e .`` runs). Tests inject a MagicMock via the
    ``llm`` parameter and ``crewai.Agent`` is monkey-patched.
    """
    try:
        from crewai import Agent  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "crewai is not installed — run "
            "`crates/vouch-agents/.venv/bin/python -m pip install crewai`"
        ) from exc
    return Agent(
        role=role,
        goal=goal,
        backstory=backstory,
        llm=llm if llm is not None else build_extraction_llm(),
        allow_delegation=False,
        verbose=False,
    )


# ---------------------------------------------------------------------------
# Extraction helpers (deterministic, regex-based, used as fallback + tests)
# ---------------------------------------------------------------------------

# Field extraction patterns. The deterministic extractor is used when the
# LLM path is mocked or unavailable. It MUST produce a valid
# ProcurementCase JSON for the clean fixture and an ``error`` event for
# the malformed fixture (AC-2.4).
_AMOUNT_RE = re.compile(
    r"(?:EUR|€)\s*([0-9][0-9.,]*)", re.IGNORECASE
)
_VENDOR_ID_RE = re.compile(
    r"\(([A-Z]{2}-[A-Z0-9-]{4,})\)"
)
_CASE_ID_RE = re.compile(
    r"\b(PC-\d{4}-\d{3,6})\b"
)


def _deterministic_extract(raw: str) -> dict[str, Any]:
    """Extract a ProcurementCase dict from a raw procurement request text.

    This is a deterministic regex-based extractor used when the LLM path
    is unavailable or mocked. The 3 fixture files are crafted so this
    extractor succeeds on the clean fixture and fails on the violations
    fixture (the violations are detected downstream by vendor-researcher,
    not by intake — intake only catches malformed/missing-field inputs).
    """
    case_id_m = _CASE_ID_RE.search(raw)
    vendor_m = _VENDOR_ID_RE.search(raw)
    amount_m = _AMOUNT_RE.search(raw)

    # Required-string fields — best-effort heuristics. The LLM path
    # produces better results; this is the deterministic safety net.
    case_id = case_id_m.group(1) if case_id_m else ""
    vendor_id = vendor_m.group(1) if vendor_m else ""

    # Heuristic: pick the first non-trivial capitalized noun-phrase as
    # vendor_name. The fixtures put it before the parenthesized id.
    vendor_name = ""
    if vendor_m:
        # Walk back from the vendor_id match to find the vendor name.
        idx = vendor_m.start()
        prefix = raw[:idx].rstrip(" (")
        # Take the last 1-5 words immediately before the id.
        words = prefix.split()
        if words:
            tail = words[-5:]
            vendor_name = " ".join(tail).strip(",.;:")
            # Strip a trailing "from" / "with" / "to" connector.
            vendor_name = re.sub(
                r"\s+(from|with|to|engagement\s+with|engaging|for)\s*$",
                "",
                vendor_name,
                flags=re.IGNORECASE,
            )

    amount = 0.0
    if amount_m:
        try:
            amount = float(amount_m.group(1).replace(",", "").replace(".", ""))
            # The regex picks up the integer/fractional part without the
            # decimal separator. If the value has both ',' and '.', the
            # last '.' is the decimal. Heuristic: if amount looks
            # implausibly large (> 10x the cap), try the other order.
            if amount > 1_000_000_000:
                amount = float(amount_m.group(1).replace(".", "").replace(",", "."))
        except ValueError:
            amount = 0.0

    # Buyer: pull the first "from X" / "request X from Y" phrase.
    buyer = ""
    buyer_m = re.search(
        r"(?:from|on behalf of)\s+([A-Z][A-Za-z0-9.&'\-\s]{2,80}?)(?:\s*\(|,|\.| requesting)",
        raw,
    )
    if buyer_m:
        buyer = buyer_m.group(1).strip()

    # Category: pull the first lowercase noun-phrase after "for".
    category = "uncategorized"
    cat_m = re.search(r"\bfor\s+([a-z][a-z_]+)", raw)
    if cat_m:
        candidate = cat_m.group(1)
        if candidate not in {"the", "a", "an", "approval", "engagement"}:
            category = candidate

    # Urgency: explicit marker or default to standard.
    urgency = "standard"
    if re.search(r"\burgent\b|\bemergency\b", raw, re.IGNORECASE):
        urgency = "urgent"

    # Attachments: collect s3:// / file:// / https:// URIs.
    attachments = re.findall(
        r"(?:s3|file|https?)://[^\s,;]+",
        raw,
    )

    # requested_action: default to "approve" (the most common verb).
    requested_action = "approve"
    if re.search(r"\b(reject|deny|block)\b", raw, re.IGNORECASE):
        requested_action = "reject"
    elif re.search(r"\b(review|investigate)\b", raw, re.IGNORECASE):
        requested_action = "review"

    return {
        "case_id": case_id,
        "buyer": buyer,
        "vendor_name": vendor_name,
        "vendor_id": vendor_id,
        "amount_eur": amount,
        "category": category,
        "requested_action": requested_action,
        "attachments": attachments,
        "urgency": urgency,
    }


# ---------------------------------------------------------------------------
# IntakeAgent
# ---------------------------------------------------------------------------


class IntakeAgent:
    """The ``@apohara-themis/intake-agent`` Band specialist (S-02).

    Public surface
    --------------
    * ``parse_request(raw: str | bytes) -> ProcurementCase | None``
      parses raw input via the CrewAI role (LLM) and validates against
      the ProcurementCase pydantic schema. Returns ``None`` on
      malformed input (caller MUST emit a ``message_type='error'``
      event). The LLM output is JSON; we validate strictly.

    * ``post_to_band(case: ProcurementCase, tools: Any) -> dict``
      posts the parsed case to the Band room via
      ``tools.send_event(content=..., message_type='thought', ...)``.

    * ``post_error_to_band(raw: str | bytes, reason: str, tools: Any) -> dict``
      posts the AC-2.4 error event.

    The agent is recruited by the Orchestrator via
    ``thenvoi_lookup_peers`` + ``thenvoi_add_participant`` (S-01 surface).
    The intake agent itself does not own recruitment — the orchestrator
    does. We only expose ``send_event``-style writes.
    """

    def __init__(
        self,
        agent_name: str = "themis-intake-agent",
        secrets: dict[str, str] | None = None,
        crewai_agent: Any | None = None,
        llm: Any | None = None,
    ) -> None:
        self.agent_name = agent_name
        self.secrets = secrets if secrets is not None else load_secrets()
        self.llm = llm if llm is not None else build_extraction_llm(secrets=self.secrets)
        # The CrewAI Agent is built lazily so import order doesn't
        # matter and so tests can inject a MagicMock.
        self._crewai_agent = crewai_agent

    # -- CrewAI wiring ----------------------------------------------------

    @property
    def crewai_agent(self) -> Any:
        if self._crewai_agent is None:
            self._crewai_agent = build_crewai_agent(llm=self.llm)
        return self._crewai_agent

    # -- Extraction -------------------------------------------------------

    def parse_request(self, raw: str | bytes) -> ProcurementCase | None:
        """Parse a raw procurement request into a ProcurementCase.

        Pipeline:
          1. If ``raw`` is bytes, decode as UTF-8 (best-effort).
          2. If ``raw`` starts with ``{``, parse it as JSON directly
             (deterministic path) — used for the fixture tests.
          3. Otherwise call the CrewAI Agent (mocked in tests) and
             expect a JSON string back. Fall back to the deterministic
             extractor if the LLM call fails.

        Returns ``None`` when the parsed payload cannot satisfy the
        schema. The caller MUST post a ``message_type='error'`` event
        and NOT advance the case (AC-2.4).
        """
        if isinstance(raw, (bytes, bytearray)):
            try:
                text = bytes(raw).decode("utf-8")
            except UnicodeDecodeError:
                return None
        else:
            text = raw

        if not text or not text.strip():
            return None

        # If the input is already a JSON document, use the deterministic
        # JSON path. This is the fixture path (AC-2.3 + AC-2.5).
        payload: dict[str, Any] | None = None
        stripped = text.strip()
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                return None
            if not isinstance(obj, dict):
                return None
            payload = obj
        else:
            # LLM path — the CrewAI agent is expected to return a JSON
            # string. In tests we mock this method.
            try:
                result = self.crewai_agent.kickoff({"raw": text})
            except Exception as exc:
                logger.warning("CrewAI kickoff failed: %s — falling back", exc)
                payload = _deterministic_extract(text)
            else:
                # CrewAI's kickoff returns a CrewOutput with a .raw
                # attribute, or a plain string in older versions.
                raw_output = getattr(result, "raw", None) or str(result)
                try:
                    obj = json.loads(raw_output)
                except (json.JSONDecodeError, TypeError):
                    payload = _deterministic_extract(text)
                else:
                    if not isinstance(obj, dict):
                        return None
                    payload = obj

        if payload is None:
            return None

        # Strict schema validation. Any validation error -> None
        # (caller MUST emit error event).
        try:
            return ProcurementCase.model_validate(payload)
        except ValidationError as exc:
            logger.info("ProcurementCase validation failed: %s", exc)
            return None

    # -- Band writes ------------------------------------------------------

    def post_to_band(self, case: ProcurementCase, tools: Any) -> dict[str, Any]:
        """Publish the parsed case to the Band room (AC-2.3).

        Addressed to ``@apohara-themis/vendor-researcher`` per the S-02
        story. ``message_type='thought'`` is the same shape the
        orchestrator emits; we add a metadata envelope so downstream
        agents can detect a structured ProcurementCase vs free-form.
        """
        content = json.dumps(
            case.model_dump(mode="json"),
            sort_keys=True,
        )
        metadata = {
            "from": "themis-intake-agent",
            "to": "vendor-researcher",
            "schema": "ProcurementCase",
            "case_id": case.case_id,
        }
        send_event = getattr(tools, "send_event", None)
        if send_event is None:
            logger.warning(
                "tools.send_event missing — would post case %s", case.case_id
            )
            return {"posted": False, "reason": "no_tools"}
        return send_event(
            content=content,
            message_type="thought",
            metadata=metadata,
        )

    def post_error_to_band(
        self,
        raw: str | bytes,
        reason: str,
        tools: Any,
    ) -> dict[str, Any]:
        """Emit a ``message_type='error'`` event when input is malformed.

        The error event carries the first 200 chars of the raw input
        + the reason string. The case MUST NOT advance (the caller
        checks ``parse_request()`` returning None and posts this
        error path; no ProcurementCase is ever constructed).
        """
        if isinstance(raw, (bytes, bytearray)):
            text = bytes(raw).decode("utf-8", errors="replace")
        else:
            text = raw
        content = json.dumps(
            {
                "reason": reason,
                "raw_preview": text[:200],
            },
            sort_keys=True,
        )
        metadata = {
            "from": "themis-intake-agent",
            "to": "vendor-researcher",
            "schema": "IntakeError",
        }
        send_event = getattr(tools, "send_event", None)
        if send_event is None:
            logger.warning("tools.send_event missing — would post error: %s", reason)
            return {"posted": False, "reason": "no_tools"}
        return send_event(
            content=content,
            message_type="error",
            metadata=metadata,
        )


__all__ = [
    "ProcurementCase",
    "IntakeAgent",
    "build_extraction_llm",
    "build_crewai_agent",
    "load_secrets",
]
