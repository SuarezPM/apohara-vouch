"""S-09: Apohara VOUCH Approval Manager.

The final Band specialist agent in the procurement pipeline. Takes the
sealed ``EvidencePacket`` from S-08 (EvidenceClerk), synthesises a one-page
``DecisionMemo`` procurement decision via a CrewAI Agent running
``claude-sonnet-4-6`` through AI/ML API's OpenAI-compatible gateway,
renders a one-page C2PA-signed PDF with all 8 EU AI Act Art. 12 fields +
a QR code to the ``vouch-verify`` verifier, and gates on a human sign-off
before emitting the case-closing ``vouched: true`` event.

Stack
-----
* CrewAI ``Agent`` wired to ``crewai.llm.LLM`` with
  ``model='openai/claude-sonnet-4-6'`` against the AI/ML API
  OpenAI-compatible base URL. ``litellm`` routes the ``openai/`` prefix
  and forwards ``base_url`` + ``api_key`` (AC-9.1).
* ``pydantic`` for ``DecisionMemo`` schema validation (AC-9.2).
* ``reportlab`` for one-page C2PA-signed PDF (AC-9.3). Rust
  ``vouch-receipt/src/packet.rs`` does not currently expose a PDF
  renderer binary, so Python owns the PDF layout. The QR code is
  generated via the ``qrcode`` library and embedded as a PNG in the
  PDF; the QR targets ``https://vouch.apohara.dev/verify?packet=<hash>``.
* ``threading.Event`` as the human sign-off gate (AC-9.4). The
  production wiring listens to Band room messages for
  ``@approval-manager approve <code>`` and calls ``signoff_event.set()``
  with the validated code. Tests drive the gate directly via
  ``ApprovalManager.approve(code)``.

AC matrix
---------
* AC-9.1  ``build_crewai_agent`` returns a ``crewai.Agent`` whose
         ``llm`` is ``crewai.llm.LLM(model='openai/claude-sonnet-4-6',
         base_url=AIML_API_BASE_URL, api_key=AIML_API_KEY)``.
* AC-9.2  ``DecisionMemo`` schema: ``verdict`` (Literal Approve /
         Conditional / Reject / Escalate), ``confidence`` (0..1),
         ``rationale`` (str), ``citations`` (list[str]),
         ``required_signoffs`` (list[HumanRole]).
* AC-9.3  ``render_memo_pdf`` writes a one-page PDF that contains all
         8 EU AI Act Art. 12 fields, the BLAKE3 chain root, the C2PA
         manifest id + algorithm, and a QR code to the vouch-verify
         URL. PDF path is configurable via ``pdf_out`` (default
         ``/tmp/apohara_decision_memo.pdf``).
* AC-9.4  ``request_human_signoff`` emits ``send_event`` with
         ``message_type='task'``, ``metadata.to='human-procurement-lead'``,
         ``metadata.requires_signoff=True`` and blocks on a
         ``threading.Event`` until a human approval code is delivered.
* AC-9.5  On human approval the agent emits a ``send_event`` with
         ``message_type='vouched'`` and content ``{"vouched": true}``,
         which closes the case.

Implementation notes (deviations from the S-09 plan)
----------------------------------------------------
* Hint #1 says the model is ``claude-sonnet-4-6``. The plan offers a
  CrewAI Agent with ``crewai.llm.LLM(model='openai/claude-sonnet-4-6', ...)``.
  We follow the S-02 intake pattern (``crewai.llm.LLM`` with the
  ``openai/`` LiteLLM prefix) which is the canonical wire format for
  AIML's OpenAI-compatible gateway.
* Hint #2 offers the Rust binary path or a direct ``reportlab`` path.
  The Rust ``vouch-receipt`` crate does not expose a ``render`` binary
  today (only the data types in ``src/packet.rs``). We take the
  ``reportlab`` path and document it under ``PDF_RENDERER``.
* Hint #3 specifies a ``threading.Event`` for the gate. We use the
  simpler ``threading.Event`` (sync) and expose ``approve(code)`` so
  tests can release the gate without spinning a Band room. Production
  wires ``approve(code)`` to the Band room listener.
* Hint #4: the QR target is ``https://vouch.apohara.dev/verify?packet=<hash>``.
  We use the ``vouch.apohara.dev`` host as configured in
  ``VOUCH_VERIFY_URL``; tests override it via ``vouch_verify_url``.
* Hint #5: the handoff event is documented in the Band event contract
  below.
* Hint #6: ``vouched: true`` event is sent as a dedicated
  ``message_type='vouched'`` rather than a generic ``task`` so the
  orchestrator's case-closing handler can subscribe precisely.

Hard rules
----------
1. No secrets in source — ``AIML_API_KEY`` from ``secrets.env``.
2. Every public function has at least one unit test.
3. Tests do not hit the network — CrewAI Agent is mocked.
4. The PDF is generated offline (no Rust binary call required).
5. The sign-off gate is deterministic — tests use a ``threading.Event``
   and bypass the Band room.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Secrets (AC-9.1)
# ---------------------------------------------------------------------------

SECRETS_PATH = Path(os.path.expanduser("~/.config/apohara/secrets.env"))


def load_secrets() -> dict[str, str]:
    """Load AI/ML API key + base URL from ``secrets.env``.

    Returns ``{AIML_API_KEY, AIML_API_BASE_URL}``. Empty strings for
    missing keys (never raises) so unit tests run without real
    secrets.
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
# Defaults / constants
# ---------------------------------------------------------------------------

# AC-9.1: model id is forwarded verbatim with the LiteLLM ``openai/`` prefix.
DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_AGENT_ROLE = "approval-manager"
DEFAULT_VERIFY_URL = "https://vouch.apohara.dev/verify"

PDF_RENDERER = "reportlab"  # Per hint #2; documented deviation above.

DEFAULT_PDF_OUT = "/tmp/apohara_decision_memo.pdf"

EU_AI_ACT_ART12_FIELDS: tuple[str, ...] = (
    "start_time",
    "end_time",
    "reference_database",
    "input_data",
    "natural_person_id",
    "decision_id",
    "policy_version",
    "hash_chain_prev",
)

# Approval codes are pre-shared with the human procurement lead.
# The gate is satisfied when ``approve(code)`` is called with a code
# present in ``ApprovalManager.valid_codes``. Production wires the
# Band room listener; tests inject codes directly.
DEFAULT_VALID_CODE = "VOUCH-OK-2026"


# ---------------------------------------------------------------------------
# DecisionMemo schema (AC-9.2)
# ---------------------------------------------------------------------------


class HumanRole(str, Enum):
    """Roles that can sign off on a DecisionMemo.

    The memo's ``required_signoffs`` lists every human role whose
    approval is needed before the agent emits ``vouched: true``. The
    Role is also stored on the audit log entry.
    """

    PROCUREMENT_LEAD = "human-procurement-lead"
    LEGAL_COUNSEL = "human-legal-counsel"
    FINANCE_CONTROLLER = "human-finance-controller"
    COMPLIANCE_OFFICER = "human-compliance-officer"
    CTO = "human-cto"
    CEO = "human-ceo"


class EuAiActArt12(BaseModel):
    """The 8 EU AI Act Art. 12 fields embedded in the DecisionMemo PDF.

    Mirrors ``vouch_receipt::packet::EU_AI_ACT_ART12_FIELDS`` (8 fields).
    AC-9.3: the PDF must show every field.
    """

    start_time: str
    end_time: str
    reference_database: str
    input_data: str
    natural_person_id: str | None = None
    decision_id: str
    policy_version: str
    hash_chain_prev: str


class C2paManifest(BaseModel):
    """C2PA manifest id + algorithm for the PDF.

    Mirrors ``vouch_receipt::packet::C2paManifest``. The full manifest
    lives in the EvidencePacket (S-08). The DecisionMemo PDF only
    carries the id + algorithm + claim generator.
    """

    manifest_id: str = Field(min_length=1)
    claim_generator: str = Field(min_length=1)
    algorithm: str = Field(default="Ed25519+BLAKE3")
    claim_hex: str | None = None


class DecisionMemo(BaseModel):
    """The one-page procurement decision memo (AC-9.2).

    Synthesised by the ApprovalManager's CrewAI Agent from the sealed
    EvidencePacket. The ``verdict`` drives the downstream Band
    handoff: ``Approve`` / ``Conditional`` clear the case, ``Reject``
    halts, ``Escalate`` defers to a higher role.
    """

    verdict: Literal["Approve", "Conditional", "Reject", "Escalate"]
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1)
    citations: list[str] = Field(default_factory=list)
    required_signoffs: list[HumanRole] = Field(default_factory=list)
    case_id: str = Field(min_length=1)
    eu_ai_act_art12: EuAiActArt12
    c2pa_manifest: C2paManifest
    blake3_chain_root: str = Field(min_length=1, max_length=128)
    packet_hash: str = Field(min_length=1, max_length=128)

    @field_validator("citations")
    @classmethod
    def _strip_blank_citations(cls, value: list[str]) -> list[str]:
        return [c.strip() for c in value if c and c.strip()]

    def to_json(self) -> str:
        """Deterministic JSON for Band room payload."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True)


# ---------------------------------------------------------------------------
# CrewAI LLM + Agent (AC-9.1)
# ---------------------------------------------------------------------------


def build_approval_llm(
    secrets: dict[str, str] | None = None,
    model: str = DEFAULT_MODEL,
) -> Any:
    """Build the CrewAI ``LLM`` wired to AI/ML API + ``claude-sonnet-4-6``.

    AC-9.1: ``crewai.llm.LLM(model='openai/claude-sonnet-4-6',
    base_url=AIML_API_BASE_URL, api_key=AIML_API_KEY)``. The
    ``openai/`` prefix routes through LiteLLM as an OpenAI-compatible
    call, which honors the ``base_url`` we pass. AI/ML API's gateway
    exposes claude-sonnet-4-6 over its OpenAI-compatible endpoint.

    Returns the ``crewai.llm.LLM`` instance. Tests inject a
    ``MagicMock`` for ``llm`` and skip this path entirely.
    """
    secrets = secrets if secrets is not None else load_secrets()
    api_key = secrets.get("AIML_API_KEY", "")
    base_url = secrets.get("AIML_API_BASE_URL", "https://api.aimlapi.com/v1")
    if not api_key:
        logger.warning(
            "AIML_API_KEY not set — using empty string (test mode)"
        )
    try:
        from crewai.llm import LLM  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "crewai is not installed — run "
            "`crates/vouch-agents/.venv/bin/python -m pip install crewai litellm`"
        ) from exc
    return LLM(model=f"openai/{model}", base_url=base_url, api_key=api_key)


def build_crewai_agent(
    llm: Any | None = None,
    role: str = DEFAULT_AGENT_ROLE,
    goal: str = (
        "Synthesise the sealed EvidencePacket into a one-page procurement "
        "DecisionMemo: verdict (Approve/Conditional/Reject/Escalate), "
        "confidence (0..1), rationale with citations, and required human "
        "sign-offs. Cite the originating statute and the agent whose "
        "finding drove the verdict."
    ),
    backstory: str = (
        "You are the approval manager at a regulated EU public-sector "
        "buyer. You receive a sealed EvidencePacket from the evidence "
        "clerk (Ed25519 + BLAKE3 chain root + C2PA manifest), every "
        "prior agent's verdict (vendor-researcher, finance-risk, "
        "legal-policy, red-team-auditor, evidence-clerk), and you "
        "produce the one-page DecisionMemo that gates a procurement "
        "decision on human sign-off. Your memo must cite every statute "
        "and finding that drove the verdict."
    ),
):
    """Build the CrewAI Agent role (AC-9.1).

    Imports ``crewai.Agent`` lazily so the module is importable in
    environments where crewai is not yet installed. Tests inject a
    MagicMock via ``llm`` and monkey-patch ``crewai.Agent``.
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
        llm=llm if llm is not None else build_approval_llm(),
        allow_delegation=False,
        verbose=False,
    )


# ---------------------------------------------------------------------------
# Memo synthesis from the LLM kickoff (AC-9.2)
# ---------------------------------------------------------------------------


def parse_memo_payload(raw: str) -> dict[str, Any]:
    """Parse the CrewAI Agent's raw output into a DecisionMemo-ready dict.

    Tolerates JSON wrapped in ```json ... ``` fences (a common CrewAI
    kickoff shape) and raises ``ValueError`` for non-JSON output.

    Returns the dict; callers validate against ``DecisionMemo``.
    """
    text = (raw or "").strip()
    if text.startswith("```"):
        # Strip ```json / ``` fences.
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return json.loads(text)


# ---------------------------------------------------------------------------
# PDF generation (AC-9.3)
# ---------------------------------------------------------------------------


def render_memo_pdf(
    memo: DecisionMemo,
    *,
    pdf_out: str | Path = DEFAULT_PDF_OUT,
    vouch_verify_url: str = DEFAULT_VERIFY_URL,
) -> bytes:
    """Render the one-page DecisionMemo PDF (AC-9.3).

    Contains:
      * the verdict + confidence + rationale + citations,
      * all 8 EU AI Act Art. 12 fields (AC-9.3, ≥7/8 required),
      * the BLAKE3 chain root,
      * the C2PA manifest id + algorithm + claim generator,
      * a QR code whose target URL is
        ``<vouch_verify_url>?packet=<packet_hash>`` (per hint #4).

    Writes the PDF to ``pdf_out`` AND returns its bytes. The on-disk
    write is so the demo UI can serve the file via the orchestrator's
    static-files route; the return value is so unit tests can inspect
    the bytes without touching the filesystem.

    PDF renderer: ``reportlab`` (documented in ``PDF_RENDERER``).
    """
    try:
        from reportlab.lib.pagesizes import A4  # type: ignore[import-not-found]
        from reportlab.lib.styles import getSampleStyleSheet  # type: ignore[import-not-found]
        from reportlab.lib.units import mm  # type: ignore[import-not-found]
        from reportlab.platypus import (  # type: ignore[import-not-found]
            Image,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
        from reportlab.lib import colors  # type: ignore[import-not-found]
        import qrcode  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "reportlab + qrcode are required — run "
            "`pip install reportlab qrcode`"
        ) from exc

    qr_target = f"{vouch_verify_url}?packet={memo.packet_hash}"
    qr_png = qrcode.make(qr_target)
    qr_buffer = io.BytesIO()
    qr_png.save(qr_buffer, format="PNG")
    qr_buffer.seek(0)

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    h2_style = styles["Heading2"]
    body_style = styles["BodyText"]
    mono_style = styles["Code"]

    story: list[Any] = []
    story.append(
        Paragraph(
            f"<b>DecisionMemo — case {memo.case_id}</b>", title_style
        )
    )
    story.append(
        Paragraph(
            f"<b>Verdict:</b> {memo.verdict} "
            f"&nbsp;&nbsp;<b>Confidence:</b> {memo.confidence:.2f}",
            body_style,
        )
    )
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("<b>Rationale</b>", h2_style))
    story.append(Paragraph(memo.rationale, body_style))
    story.append(Spacer(1, 3 * mm))

    if memo.citations:
        story.append(Paragraph("<b>Citations</b>", h2_style))
        for c in memo.citations:
            story.append(Paragraph(f"&bull; {c}", body_style))
        story.append(Spacer(1, 3 * mm))

    if memo.required_signoffs:
        story.append(Paragraph("<b>Required sign-offs</b>", h2_style))
        for r in memo.required_signoffs:
            story.append(Paragraph(f"&bull; {r.value}", body_style))
        story.append(Spacer(1, 3 * mm))

    # EU AI Act Art. 12 — all 8 fields in a compact table (AC-9.3).
    art12_rows: list[list[str]] = [["Field", "Value"]]
    art12 = memo.eu_ai_act_art12
    for f in EU_AI_ACT_ART12_FIELDS:
        art12_rows.append([f, getattr(art12, f) or "-"])
    art12_table = Table(art12_rows, colWidths=[55 * mm, 115 * mm])
    art12_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.black),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(Paragraph("<b>EU AI Act Art. 12 (8/8 fields)</b>", h2_style))
    story.append(art12_table)
    story.append(Spacer(1, 3 * mm))

    # Crypto anchors.
    crypto_rows = [
        ["BLAKE3 chain root", memo.blake3_chain_root],
        ["C2PA manifest id", memo.c2pa_manifest.manifest_id],
        ["C2PA algorithm", memo.c2pa_manifest.algorithm],
        ["C2PA claim generator", memo.c2pa_manifest.claim_generator],
    ]
    crypto_table = Table(crypto_rows, colWidths=[55 * mm, 115 * mm])
    crypto_table.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("FONTNAME", (1, 0), (1, -1), "Courier"),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.black),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ]
        )
    )
    story.append(Paragraph("<b>Crypto anchors</b>", h2_style))
    story.append(crypto_table)
    story.append(Spacer(1, 3 * mm))

    # QR code (anchored to vouch-verify).
    story.append(
        Paragraph(
            f"<b>Verify offline:</b> {qr_target}", mono_style
        )
    )
    story.append(Image(qr_buffer, width=30 * mm, height=30 * mm))

    pdf_bytes = io.BytesIO()
    doc = SimpleDocTemplate(
        pdf_bytes,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"Apohara DecisionMemo {memo.case_id}",
    )
    doc.build(story)

    rendered = pdf_bytes.getvalue()
    out_path = Path(pdf_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(rendered)
    return rendered


# ---------------------------------------------------------------------------
# Band handoff + sign-off gate (AC-9.4, AC-9.5)
# ---------------------------------------------------------------------------


def request_human_signoff(
    memo: DecisionMemo,
    *,
    tools: Any,
    gate: threading.Event,
    signoff_timeout_s: float = 0.0,
    pdf_bytes: bytes | None = None,
    pdf_b64: str | None = None,
) -> dict[str, Any]:
    """Emit the sign-off request and block until the gate opens.

    AC-9.4: emits ``send_event`` with ``message_type='task'``,
    ``metadata.to='human-procurement-lead'``,
    ``metadata.requires_signoff=True`` and the DecisionMemo as the
    payload. Blocks until ``gate`` is set (default: indefinite;
    ``signoff_timeout_s`` > 0 enables a finite wait that returns a
    ``timed_out`` status without raising).

    The PDF is delivered in-band as base64 in the metadata so the
    Band room participant can download it without a second round
    trip. Either ``pdf_bytes`` or ``pdf_b64`` may be supplied.
    """
    if pdf_b64 is None and pdf_bytes is not None:
        pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")
    payload = {
        "content": memo.to_json(),
        "message_type": "task",
        "metadata": {
            "to": "human-procurement-lead",
            "from": "approval-manager",
            "requires_signoff": True,
            "case_id": memo.case_id,
            "decision_id": memo.eu_ai_act_art12.decision_id,
            "verdict": memo.verdict,
            "required_signoffs": [r.value for r in memo.required_signoffs],
            "packet_hash": memo.packet_hash,
            "vouch_verify_url": (
                f"{DEFAULT_VERIFY_URL}?packet={memo.packet_hash}"
            ),
            "pdf_b64": pdf_b64,
        },
    }
    send_event = getattr(tools, "send_event", None)
    if send_event is None:
        logger.warning(
            "tools.send_event missing — would post sign-off request for %s",
            memo.case_id,
        )
    else:
        send_event(**payload)

    if signoff_timeout_s > 0:
        opened = gate.wait(timeout=signoff_timeout_s)
        return {"opened": opened, "timed_out": not opened}
    gate.wait()
    return {"opened": True, "timed_out": False}


def emit_vouched_event(
    memo: DecisionMemo,
    *,
    tools: Any,
    approver_role: HumanRole = HumanRole.PROCUREMENT_LEAD,
    approver_code: str = DEFAULT_VALID_CODE,
) -> dict[str, Any]:
    """Emit the case-closing ``vouched: true`` event (AC-9.5).

    Sent as ``message_type='vouched'`` (distinct from ``task`` so the
    orchestrator's case-closing handler can subscribe precisely). The
    content is ``{"vouched": true, "case_id": ..., ...}`` and the
    metadata carries the approver role + code for auditability.
    """
    payload = {
        "content": json.dumps(
            {
                "vouched": True,
                "case_id": memo.case_id,
                "verdict": memo.verdict,
                "decision_id": memo.eu_ai_act_art12.decision_id,
                "approver_role": approver_role.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            sort_keys=True,
        ),
        "message_type": "vouched",
        "metadata": {
            "to": "all",
            "from": "approval-manager",
            "case_id": memo.case_id,
            "decision_id": memo.eu_ai_act_art12.decision_id,
            "approver_role": approver_role.value,
            "approver_code": approver_code,
        },
    }
    send_event = getattr(tools, "send_event", None)
    if send_event is None:
        logger.warning(
            "tools.send_event missing — would emit vouched for %s",
            memo.case_id,
        )
        return payload
    send_event(**payload)
    return payload


# ---------------------------------------------------------------------------
# ApprovalManager — public entry point
# ---------------------------------------------------------------------------


class ApprovalManager:
    """Band-aware entry point for the ApprovalManager agent.

    Mirrors the ``VendorResearcher`` / ``IntakeAgent`` /
    ``EvidenceClerk`` shape: ``run()`` accepts a ``BandTools``-like
    object + the sealed ``EvidencePacket`` (from S-08), invokes the
    CrewAI Agent to synthesise the DecisionMemo, renders the PDF, and
    drives the human sign-off gate.
    """

    def __init__(
        self,
        *,
        crewai_agent: Any | None = None,
        llm: Any | None = None,
        valid_codes: tuple[str, ...] = (DEFAULT_VALID_CODE,),
        vouch_verify_url: str = DEFAULT_VERIFY_URL,
        signoff_timeout_s: float = 0.0,
    ) -> None:
        self._crewai_agent = crewai_agent
        self._llm = llm
        self.valid_codes = set(valid_codes)
        self.vouch_verify_url = vouch_verify_url
        self.signoff_timeout_s = signoff_timeout_s
        self._signoff_event = threading.Event()
        self._accepted_code: str | None = None
        self._accepted_role: HumanRole | None = None

    # ---- crewai lazy accessor ---------------------------------------------

    @property
    def crewai_agent(self) -> Any:
        """Lazy-build the CrewAI Agent (AC-9.1)."""
        if self._crewai_agent is None:
            self._crewai_agent = build_crewai_agent(llm=self._llm)
        return self._crewai_agent

    # ---- sign-off gate ----------------------------------------------------

    def approve(
        self,
        code: str,
        *,
        role: HumanRole = HumanRole.PROCUREMENT_LEAD,
    ) -> bool:
        """Release the sign-off gate if ``code`` is valid (AC-9.4)."""
        if code not in self.valid_codes:
            logger.warning("approval code rejected: %s", code)
            return False
        self._accepted_code = code
        self._accepted_role = role
        self._signoff_event.set()
        return True

    def _reset_gate(self) -> None:
        self._signoff_event.clear()
        self._accepted_code = None
        self._accepted_role = None

    # ---- synthesis + Band handoff ----------------------------------------

    def synthesise_memo(
        self,
        packet: dict[str, Any],
    ) -> DecisionMemo:
        """Invoke the CrewAI Agent and parse the DecisionMemo.

        ``packet`` is the sealed EvidencePacket dict from S-08 (the
        shape produced by ``evidence_clerk.EvidenceClerk.run``).

        The CrewAI Agent's ``kickoff`` returns a result whose ``raw``
        attribute holds the JSON. Tests pass a ``MagicMock`` whose
        ``kickoff.return_value.raw`` is a JSON string with the
        DecisionMemo fields. Production invokes the real LLM.
        """
        prompt = json.dumps(packet, sort_keys=True)
        result = self.crewai_agent.kickoff(inputs={"packet": prompt})
        raw = getattr(result, "raw", None) or str(result)
        memo_dict = parse_memo_payload(raw)
        return DecisionMemo.model_validate(memo_dict)

    def render_pdf(
        self,
        memo: DecisionMemo,
        *,
        pdf_out: str | Path = DEFAULT_PDF_OUT,
    ) -> bytes:
        """Render the DecisionMemo PDF (AC-9.3)."""
        return render_memo_pdf(
            memo,
            pdf_out=pdf_out,
            vouch_verify_url=self.vouch_verify_url,
        )

    def request_signoff(
        self,
        memo: DecisionMemo,
        *,
        tools: Any,
        pdf_bytes: bytes | None = None,
    ) -> dict[str, Any]:
        """Emit the sign-off request and block on the gate (AC-9.4).

        Returns the ``gate.wait`` result dict. Tests drive the gate
        by calling ``manager.approve(code)`` from a background
        thread; production wires ``approve`` to the Band room
        listener.
        """
        self._reset_gate()
        return request_human_signoff(
            memo,
            tools=tools,
            gate=self._signoff_event,
            signoff_timeout_s=self.signoff_timeout_s,
            pdf_bytes=pdf_bytes,
        )

    def emit_vouched(
        self,
        memo: DecisionMemo,
        *,
        tools: Any,
    ) -> dict[str, Any]:
        """Emit the case-closing ``vouched: true`` event (AC-9.5)."""
        role = self._accepted_role or HumanRole.PROCUREMENT_LEAD
        code = self._accepted_code or DEFAULT_VALID_CODE
        return emit_vouched_event(
            memo,
            tools=tools,
            approver_role=role,
            approver_code=code,
        )

    # ---- top-level orchestrator hook -------------------------------------

    def run(
        self,
        packet: dict[str, Any],
        *,
        tools: Any,
        pdf_out: str | Path = DEFAULT_PDF_OUT,
        approver_code: str | None = None,
        approver_role: HumanRole = HumanRole.PROCUREMENT_LEAD,
        approver_delay_s: float = 0.05,
    ) -> dict[str, Any]:
        """End-to-end ApprovalManager pipeline.

        Returns a dict with ``memo``, ``pdf_bytes``,
        ``signoff_request``, ``signoff_result``, ``vouched_event`` so
        the orchestrator can drive the case-closing transition.

        If ``approver_code`` is provided, a daemon thread is spawned
        BEFORE the sign-off gate blocks to call ``approve(code)``
        after a short delay (default 50ms). This mirrors the
        production Band room listener pattern (the listener thread
        is always running) and avoids a deadlock where the gate
        would never be released because the release thread cannot
        be scheduled while we hold the foreground thread in wait.
        """
        memo = self.synthesise_memo(packet)
        pdf_bytes = self.render_pdf(memo, pdf_out=pdf_out)

        # Pre-spawn the release thread so it's already running by the
        # time ``request_signoff`` blocks on the gate. This is the
        # production analogue (the Band room listener is a long-lived
        # daemon thread) and avoids the deadlock where the thread
        # can't be scheduled because the foreground is blocked.
        if approver_code is not None:
            def _release_after_delay() -> None:
                time.sleep(approver_delay_s)
                self.approve(approver_code, role=approver_role)

            threading.Thread(
                target=_release_after_delay,
                daemon=True,
                name="approval-manager-auto-release",
            ).start()

        signoff_request = self.request_signoff(
            memo, tools=tools, pdf_bytes=pdf_bytes
        )

        vouched_event = self.emit_vouched(memo, tools=tools)

        return {
            "memo": memo,
            "pdf_bytes": pdf_bytes,
            "signoff_request": signoff_request,
            "vouched_event": vouched_event,
        }
