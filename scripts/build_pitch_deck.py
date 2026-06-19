"""S-11: Generate docs/pitch-deck.pdf (15 slides, VOUCH brand).

Brand colors (per docs/visual-verdict palette):
  Background:  #0a0e1a (deep navy)
  Accent:      #d4a017 (gold)
  HALT:        #dc2626 (red)
  APPROVED:    #10b981 (green)
  REVIEW:      #f59e0b (amber)
  Text:        #f9fafb (high-contrast white)
  Muted text:  #9ca3af (gray)
"""
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    Frame,
    KeepInFrame,
    PageBreak,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import Flowable

# ---------------------------------------------------------------------------
# Brand
# ---------------------------------------------------------------------------
NAVY = colors.HexColor("#0a0e1a")
GOLD = colors.HexColor("#d4a017")
RED = colors.HexColor("#dc2626")
GREEN = colors.HexColor("#10b981")
AMBER = colors.HexColor("#f59e0b")
WHITE = colors.HexColor("#f9fafb")
MUTED = colors.HexColor("#9ca3af")

# 16:9 at 1280x720 logical points (Letter landscape scaled)
PAGE_W, PAGE_H = landscape((13.333 * inch, 7.5 * inch))

OUTPUT = Path("docs/pitch-deck.pdf")
OUTPUT.parent.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
styles = getSampleStyleSheet()

H1 = ParagraphStyle(
    "H1",
    parent=styles["Heading1"],
    fontName="Helvetica-Bold",
    fontSize=44,
    leading=52,
    textColor=WHITE,
    spaceAfter=12,
)
H2 = ParagraphStyle(
    "H2",
    parent=styles["Heading2"],
    fontName="Helvetica-Bold",
    fontSize=28,
    leading=34,
    textColor=GOLD,
    spaceAfter=12,
)
H3 = ParagraphStyle(
    "H3",
    parent=styles["Heading3"],
    fontName="Helvetica-Bold",
    fontSize=20,
    leading=26,
    textColor=WHITE,
    spaceAfter=8,
)
BODY = ParagraphStyle(
    "BODY",
    parent=styles["BodyText"],
    fontName="Helvetica",
    fontSize=14,
    leading=20,
    textColor=WHITE,
    spaceAfter=8,
)
MONO = ParagraphStyle(
    "MONO",
    parent=styles["Code"],
    fontName="Courier",
    fontSize=12,
    leading=18,
    textColor=GOLD,
)
SMALL = ParagraphStyle(
    "SMALL",
    parent=BODY,
    fontSize=11,
    leading=15,
    textColor=MUTED,
)


# ---------------------------------------------------------------------------
# Slide primitive
# ---------------------------------------------------------------------------
class Slide(Flowable):
    """A full-page slide: navy background + gold accents + content."""

    def __init__(self, title, body_flowables, badge=None):
        super().__init__()
        self.title = title
        self.body = body_flowables
        self.badge = badge

    def wrap(self, availWidth, availHeight):
        return PAGE_W, PAGE_H

    def draw(self):
        c = self.canv
        # Background
        c.setFillColor(NAVY)
        c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        # Top + bottom gold strip
        c.setFillColor(GOLD)
        c.rect(0, PAGE_H - 6, PAGE_W, 6, fill=1, stroke=0)
        c.rect(0, 0, PAGE_W, 6, fill=1, stroke=0)

        # Title
        if self.title:
            c.setFillColor(WHITE)
            c.setFont("Helvetica-Bold", 32)
            c.drawString(0.6 * inch, PAGE_H - 0.9 * inch, self.title)

            # Gold underline
            c.setStrokeColor(GOLD)
            c.setLineWidth(2)
            c.line(
                0.6 * inch,
                PAGE_H - 1.0 * inch,
                0.6 * inch + 2.5 * inch,
                PAGE_H - 1.0 * inch,
            )

        # Optional badge top-right
        if self.badge:
            c.setFillColor(GOLD)
            c.setFont("Helvetica-Bold", 11)
            c.drawRightString(
                PAGE_W - 0.6 * inch,
                PAGE_H - 0.6 * inch,
                self.badge,
            )

        # Footer
        c.setFillColor(MUTED)
        c.setFont("Helvetica", 9)
        c.drawString(
            0.6 * inch,
            0.3 * inch,
            "Apohara VOUCH · Band of Agents Hackathon · Track 3",
        )
        c.drawRightString(
            PAGE_W - 0.6 * inch,
            0.3 * inch,
            "vouch.apohara.dev · github.com/SuarezPM/apohara-themis",
        )

        # Body content inside frame
        frame = Frame(
            0.6 * inch,
            0.6 * inch,
            PAGE_W - 1.2 * inch,
            PAGE_H - 2.0 * inch,
            showBoundary=0,
        )
        # Re-flow on the slide's own canvas
        frame.addFromList(
            [
                KeepInFrame(
                    PAGE_W - 1.2 * inch,
                    PAGE_H - 2.0 * inch,
                    self.body,
                    mode="shrink",
                )
            ],
            c,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def divider():
    return Spacer(1, 12)


def h1(text):
    return Paragraph(text, H1)


def h2(text):
    return Paragraph(text, H2)


def h3(text):
    return Paragraph(text, H3)


def body(text):
    return Paragraph(text, BODY)


def mono(text):
    return Paragraph(text, MONO)


def small(text):
    return Paragraph(text, SMALL)


def kv_table(rows, col_widths=None):
    if col_widths is None:
        col_widths = [2.6 * inch, 9.6 * inch]
    t = Table(rows, colWidths=col_widths)
    t.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, -1), "Helvetica", 12),
                ("TEXTCOLOR", (0, 0), (-1, -1), WHITE),
                ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 12),
                ("TEXTCOLOR", (0, 0), (0, -1), GOLD),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 0), (-1, -1), 0.25, MUTED),
            ]
        )
    )
    return t


def agent_table():
    rows = [
        ["#", "Agent", "Framework", "Model", "Sponsor"],
        [
            "1",
            "@Orchestrator",
            "LangGraph",
            "openai/gpt-5.4",
            "AI/ML API",
        ],
        [
            "2",
            "@IntakeAgent",
            "CrewAI",
            "claude-haiku-4-5",
            "AI/ML API",
        ],
        [
            "3",
            "@VendorResearcher",
            "LangGraph",
            "Llama-3.3-70B",
            "Featherless",
        ],
        [
            "4",
            "@FinanceRiskAnalyst",
            "Pydantic AI",
            "claude-sonnet-4-6",
            "AI/ML API",
        ],
        [
            "5",
            "@LegalPolicyChecker",
            "CrewAI",
            "Qwen3-Coder-30B",
            "Featherless",
        ],
        [
            "6",
            "@RedTeamAuditor",
            "Anthropic SDK",
            "claude-opus-4-5",
            "AI/ML API",
        ],
        [
            "7",
            "@ComplianceVeto",
            "Pydantic AI",
            "claude-haiku-4-5",
            "AI/ML API (2nd account)",
        ],
        [
            "8",
            "@EvidenceClerk",
            "LangGraph",
            "DeepSeek-V3-0324",
            "Featherless",
        ],
        [
            "9",
            "@ApprovalManager",
            "CrewAI",
            "claude-sonnet-4-6",
            "AI/ML API",
        ],
    ]
    t = Table(
        rows,
        colWidths=[0.4 * inch, 2.0 * inch, 1.5 * inch, 2.7 * inch, 3.6 * inch],
    )
    t.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 11),
                ("TEXTCOLOR", (0, 0), (-1, 0), GOLD),
                ("FONT", (0, 1), (-1, -1), "Helvetica", 11),
                ("TEXTCOLOR", (0, 1), (-1, -1), WHITE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [NAVY, colors.HexColor("#101729")]),
                ("LINEBELOW", (0, 0), (-1, 0), 0.75, GOLD),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return t


def art12_table():
    rows = [
        ["EU AI Act Art. 12 field", "Source", "Status"],
        ["start_time", "RFC 3161 timestamp", "✓"],
        ["end_time", "RFC 3161 timestamp", "✓"],
        ["reference_database", "Band room id + chatroom_id", "✓"],
        ["input_data", "ProcurementCase JSON envelope", "✓"],
        ["natural_person_id", "Buyer + approver identifiers", "✓"],
        ["decision_id", "case_id + sequence", "✓"],
        ["policy_version", "vouch-compliance version", "✓"],
        ["hash_chain_prev", "BLAKE3 prev_hash link", "✓"],
    ]
    t = Table(
        rows,
        colWidths=[3.4 * inch, 5.6 * inch, 1.2 * inch],
    )
    t.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 12),
                ("TEXTCOLOR", (0, 0), (-1, 0), GOLD),
                ("FONT", (0, 1), (-1, -1), "Helvetica", 12),
                ("TEXTCOLOR", (0, 1), (-2, -1), WHITE),
                ("TEXTCOLOR", (-1, 1), (-1, -1), GREEN),
                ("ALIGN", (-1, 1), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [NAVY, colors.HexColor("#101729")]),
                ("LINEBELOW", (0, 0), (-1, 0), 0.75, GOLD),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return t


def evidence_layer_table():
    rows = [
        ["Layer", "Primitive", "What it does"],
        ["vouch-chain", "BLAKE3", "Hash chain over every agent decision, sequence-monotonic"],
        ["vouch-evidence", "Ed25519", "Per-tenant signing; per-entry signature"],
        ["vouch-evidence", "RFC 3161", "Trusted timestamp (FreeTSA), cert chain validated"],
        ["vouch-evidence", "Rekor v2", "Transparency log inclusion proof"],
        ["vouch-receipt", "C2PA", "Signed PDF manifest, vendor-neutral provenance"],
        ["vouch-aibom", "CycloneDX 1.6", "AIBOM: every agent + every model lineage"],
        ["vouch-compliance", "DORA / EU AI Act / NIST AI RMF / OWASP Agentic", "4 framework mappers"],
        ["vouch-gate", "BAAAR (5 conditions)", "Deterministic post-LLM halt gate"],
    ]
    t = Table(
        rows,
        colWidths=[2.2 * inch, 2.4 * inch, 7.4 * inch],
    )
    t.setStyle(
        TableStyle(
            [
                ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 11),
                ("TEXTCOLOR", (0, 0), (-1, 0), GOLD),
                ("FONT", (0, 1), (-1, -1), "Helvetica", 11),
                ("TEXTCOLOR", (0, 1), (-1, -1), WHITE),
                ("FONT", (0, 1), (0, -1), "Courier-Bold", 11),
                ("TEXTCOLOR", (0, 1), (0, -1), GOLD),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [NAVY, colors.HexColor("#101729")]),
                ("LINEBELOW", (0, 0), (-1, 0), 0.75, GOLD),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return t


def cover_slide():
    """Slide 1: VOUCH brand lead slide."""
    return Slide(
        title="",
        badge="Slide 1 / 15",
        body_flowables=[
            Spacer(1, 0.6 * inch),
            Paragraph(
                "<font color='#d4a017'><b>VOUCH</b></font>",
                ParagraphStyle(
                    "lead",
                    fontName="Helvetica-Bold",
                    fontSize=120,
                    leading=130,
                    alignment=1,
                    textColor=GOLD,
                ),
            ),
            Paragraph(
                "<i>Vouch for every agent decision.</i>",
                ParagraphStyle(
                    "tagline",
                    fontName="Helvetica-Oblique",
                    fontSize=24,
                    leading=30,
                    alignment=1,
                    textColor=WHITE,
                ),
            ),
            Spacer(1, 0.4 * inch),
            Paragraph(
                "9 agents · 4 frameworks · 2 LLM providers · 1 chat room · 1 signed receipt",
                ParagraphStyle(
                    "subtagline",
                    fontName="Helvetica",
                    fontSize=14,
                    leading=20,
                    alignment=1,
                    textColor=MUTED,
                ),
            ),
            Spacer(1, 0.3 * inch),
            Paragraph(
                "<b>Band of Agents Hackathon</b> · Track 3 — Regulated & High-Stakes Workflows",
                ParagraphStyle(
                    "track",
                    fontName="Helvetica-Bold",
                    fontSize=16,
                    leading=22,
                    alignment=1,
                    textColor=GOLD,
                ),
            ),
            Spacer(1, 0.2 * inch),
            Paragraph(
                "Live demo · vouch.apohara.dev<br/>"
                "Source · github.com/SuarezPM/apohara-themis",
                ParagraphStyle(
                    "urls",
                    fontName="Courier",
                    fontSize=12,
                    leading=18,
                    alignment=1,
                    textColor=MUTED,
                ),
            ),
        ],
    )


def problem_slide():
    return Slide(
        title="The problem",
        badge="Slide 2 / 15",
        body_flowables=[
            h2("Regulated procurement needs receipts, not summaries"),
            body(
                "Buyer-side procurement — vendor onboarding, financial risk "
                "scoring, statutory compliance, audit sign-off — is a "
                "multi-agent workflow by construction. Today the agents are "
                "human. Tomorrow they will be AI. The gap is the receipt: "
                "an auditor must be able to verify, offline, that a decision "
                "was made, by whom, on what data, and why."
            ),
            divider(),
            kv_table(
                [
                    ["DORA Art. 17", "72-hour incident reporting clock"],
                    [
                        "EU AI Act Art. 12",
                        "Record-keeping for high-risk AI systems",
                    ],
                    [
                        "NIST AI RMF",
                        "Govern / Map / Measure / Manage trace",
                    ],
                    [
                        "OWASP Agentic 2026",
                        "ASI01–ASI10 threat model",
                    ],
                ]
            ),
            Spacer(1, 0.1 * inch),
            small(
                "Multi-framework compliance is the moat — one Evidence "
                "Packet, four regulators satisfied by construction."
            ),
        ],
    )


def sponsor_stack_slide():
    return Slide(
        title="Sponsor stack",
        badge="Slide 3 / 15",
        body_flowables=[
            h2("Band · AI/ML API · Featherless — three load-bearing integrations"),
            kv_table(
                [
                    [
                        "Band",
                        "Multi-agent coordination substrate; chat-room IS the audit trail (9 agents, 2 accounts)",
                    ],
                    [
                        "AI/ML API",
                        "Multimodal reasoning for 5 of 9 agents × 4 models (GPT-5.4, Haiku 4.5, Sonnet 4.6, Opus 4.7)",
                    ],
                    [
                        "Featherless",
                        "Open-weight specialist reasoning for 3 of 9 agents × 3 models (Llama-3.3-70B, Qwen3-Coder-30B, DeepSeek-V3)",
                    ],
                ]
            ),
            divider(),
            body(
                "Per-agent cost is visible in the live demo UI's cost "
                "panel. Graceful degradation between providers; no "
                "single-vendor lock-in; no consensus trap (3 distinct "
                "Featherless lineages)."
            ),
        ],
    )


def architecture_slide():
    return Slide(
        title="9-agent court architecture",
        badge="Slide 4 / 15",
        body_flowables=[
            small(
                "Single Band chat room (<font color='#d4a017'>vouch-procurement-court</font>) · 4 frameworks · 2 LLM providers"
            ),
            divider(),
            agent_table(),
        ],
    )


def orchestrator_slide():
    return Slide(
        title="Orchestrator + state machine",
        badge="Slide 5 / 15",
        body_flowables=[
            h2("9-state machine, LangGraph, every transition signed"),
            kv_table(
                [
                    ["IDLE", "Await first procurement case"],
                    ["INTAKE", "@IntakeAgent extracts ProcurementCase (Claude Haiku 4.5)"],
                    ["RESEARCH", "@VendorResearcher resolves vendor profile (Llama-3.3-70B)"],
                    ["RISK", "@FinanceRiskAnalyst scores RiskScore (Claude Sonnet 4.6)"],
                    ["POLICY", "@LegalPolicyChecker cites statutes (Qwen3-Coder-30B)"],
                    ["AUDIT", "@RedTeamAuditor adversarially audits (Claude Opus 4.7)"],
                    ["REDTEAM", "@ComplianceVeto binding veto (Claude Haiku 4.5, 2nd account)"],
                    ["EVIDENCE", "@EvidenceClerk seals EvidencePacket (DeepSeek-V3)"],
                    ["DECISION / DONE", "@ApprovalManager renders DecisionMemo + C2PA PDF + human sign-off"],
                ]
            ),
            Spacer(1, 0.1 * inch),
            small(
                "Every state transition emits <font color='#d4a017'>thenvoi_send_event</font> "
                "with message_type='thought'. The transcript IS the audit "
                "trail — signed and embedded in the Evidence Packet."
            ),
        ],
    )


def flow_slide():
    return Slide(
        title="Court flow",
        badge="Slide 6 / 15",
        body_flowables=[
            h2("Intake → Research → Risk → Policy → Audit → Veto → Evidence → Approval"),
            Paragraph(
                "<font face='Courier' color='#d4a017'>"
                "case-WAYNE-2026-0173<br/>"
                "@Orchestrator → @IntakeAgent → @VendorResearcher<br/>"
                "       → @FinanceRiskAnalyst → @LegalPolicyChecker<br/>"
                "       → @RedTeamAuditor → @ComplianceVeto<br/>"
                "       → @EvidenceClerk → @ApprovalManager<br/>"
                "<br/>"
                "@ApprovalManager → human sign-off → vouched: true"
                "</font>",
                ParagraphStyle(
                    "flow",
                    fontName="Courier",
                    fontSize=14,
                    leading=22,
                    textColor=GOLD,
                ),
            ),
            divider(),
            small(
                "Every arrow is a real @mention in a live Band chat room. "
                "Every node is a real signed event in the BLAKE3 chain."
            ),
        ],
    )


def evidence_layer_slide():
    return Slide(
        title="Evidence Layer (the VOUCH moat)",
        badge="Slide 7 / 15",
        body_flowables=[
            small(
                "Rust workspace: <font color='#d4a017'>vouch-chain · vouch-evidence · vouch-gate · "
                "vouch-receipt · vouch-aibom · vouch-compliance</font>"
            ),
            divider(),
            evidence_layer_table(),
        ],
    )


def verify_slide():
    return Slide(
        title="vouch-verify CLI (offline)",
        badge="Slide 8 / 15",
        body_flowables=[
            h2("Offline verification, no network, <30 s"),
            Paragraph(
                "<font face='Courier' color='#d4a017'>"
                "$ vouch-verify fixtures/sample_packet.json<br/>"
                "<br/>"
                "Reading SealedPacket: case-WAYNE-2026-0173<br/>"
                "DSSE envelope: 9 signatures, 9/9 verified<br/>"
                "BLAKE3 chain:  10 entries, chain root 7a3b4c2e...<br/>"
                "Ed25519 sigs:  9/9 verified against per-agent pubkeys<br/>"
                "RFC 3161:      freetsa.org genTime=1718662400<br/>"
                "Rekor v2:      log_index=1287, included<br/>"
                "EU AI Act:     8/8 Art. 12 fields populated<br/>"
                "DORA:          3/3 Art. 9/10/17 fields populated<br/>"
                "NIST AI RMF:   4/4 functions traced<br/>"
                "OWASP Agentic: 10/10 threats assessed<br/>"
                "<br/>"
                "&#10003; VERIFIED — packet is tamper-evident and timestamped"
                "</font>",
                ParagraphStyle(
                    "verify",
                    fontName="Courier",
                    fontSize=11,
                    leading=16,
                    textColor=GOLD,
                ),
            ),
        ],
    )


def demo_slide():
    return Slide(
        title="Live demo",
        badge="Slide 9 / 15",
        body_flowables=[
            h2("vouch.apohara.dev — 3 panels, cold fetch <800 ms"),
            kv_table(
                [
                    [
                        "Left panel",
                        "Live Band room transcript (SSE stream, auto-scroll, latest at bottom)",
                    ],
                    [
                        "Top-right",
                        "Per-agent cost panel: AI/ML API $ + Featherless $ per call",
                    ],
                    [
                        "Bottom-right",
                        "EU AI Act Art. 12 dashboard (8/8 ✓ on every approved packet)",
                    ],
                    [
                        "Form",
                        "Submit procurement → agents deliberate → Evidence Packet → human sign-off → vouched=true",
                    ],
                ]
            ),
            divider(),
            small(
                "Demo arc (5 min): submit → 9-agent deliberation → "
                "Evidence Packet download → offline verify → human "
                "sign-off → vouched=true."
            ),
        ],
    )


def art12_slide():
    return Slide(
        title="EU AI Act Art. 12 coverage",
        badge="Slide 10 / 15",
        body_flowables=[
            h2("8/8 fields populated on every approved packet"),
            art12_table(),
            Spacer(1, 0.2 * inch),
            small(
                "The same Evidence Packet also populates DORA Art. 9/10/17 "
                "(3/3), NIST AI RMF (4/4 functions), OWASP Agentic 2026 "
                "(10/10), and the CycloneDX 1.6 AIBOM."
            ),
        ],
    )


def cross_prize_overview_slide():
    return Slide(
        title="Cross-prize narrative",
        badge="Slide 11 / 18",
        body_flowables=[
            h2("One submission, three prizes"),
            kv_table(
                [
                    [
                        "Main Track 3",
                        "9-agent procurement court + cryptographic Evidence Layer + offline verifier (vouch-verify)",
                    ],
                    [
                        "Best Use of AI/ML API",
                        "5/9 agents × 4 distinct models on the critical decision path",
                    ],
                    [
                        "Best Use of Featherless",
                        "3/9 agents × 3 distinct open-weight models chosen by role",
                    ],
                ]
            ),
            divider(),
            small(
                "Two LLM providers, four frameworks, two Band accounts. "
                "No single-vendor lock-in. No consensus trap. The verb is "
                "<i>VOUCH</i>."
            ),
        ],
    )


def main_track3_slide():
    return Slide(
        title="Main Track 3 — Regulated & High-Stakes",
        badge="Slide 12 / 18",
        body_flowables=[
            h2("Prize: 1st / 2nd / 3rd"),
            kv_table(
                [
                    [
                        "Artifact",
                        "9-agent procurement court on Band (LangGraph + CrewAI + Pydantic AI + Anthropic SDK)",
                    ],
                    [
                        "Workflow",
                        "Regulated enterprise procurement: intake → research → risk → policy → audit → veto → evidence → approval",
                    ],
                    [
                        "Compliance veto",
                        "Independent second Band account cannot be overridden by the Orchestrator",
                    ],
                    [
                        "Evidence Layer",
                        "Ed25519 + BLAKE3 + RFC 3161 + Rekor v2 + C2PA — 9/9 signed per packet",
                    ],
                    [
                        "Verifier",
                        "<b>vouch-verify</b> CLI · offline · &lt;30s · no network · reproducible from the receipt",
                    ],
                    [
                        "Coverage",
                        "EU AI Act Art. 12 8/8 · DORA Art. 9/10/17 3/3 · NIST AI RMF 4/4 · OWASP Agentic 10/10",
                    ],
                ]
            ),
            divider(),
            small(
                "One receipt per procurement case. Tamper-evident, timestamped, "
                "auditable without trusting VOUCH."
            ),
        ],
    )


def aimlapi_prize_slide():
    return Slide(
        title="Best Use of AI/ML API",
        badge="Slide 13 / 18",
        body_flowables=[
            h2("Prize: $1,000 cash + $1,000 credits"),
            kv_table(
                [
                    [
                        "Coverage",
                        "5 of 9 agents on the critical decision path × 4 distinct models",
                    ],
                    [
                        "@Orchestrator",
                        "openai/gpt-5.4 — 9-state machine routing, emits thenvoi_send_event on every transition",
                    ],
                    [
                        "@IntakeAgent",
                        "claude-haiku-4-5 — structured extraction into typed ProcurementCase (9 fields)",
                    ],
                    [
                        "@FinanceRiskAnalyst",
                        "claude-sonnet-4-6 — RiskScore with citation grounding; monotonic in amount_eur",
                    ],
                    [
                        "@RedTeamAuditor",
                        "claude-opus-4-5 — adversarial audit, deterministic CRITICAL finding via Hypothesis",
                    ],
                    [
                        "@ApprovalManager",
                        "claude-sonnet-4-6 — DecisionMemo + C2PA PDF + human sign-off gate",
                    ],
                    [
                        "@ComplianceVeto (2nd Band account)",
                        "claude-haiku-4-5 — binding veto over Critical findings, escalation routing",
                    ],
                ]
            ),
            divider(),
            small(
                "Prompt-cache hit ≈95% across runs on Sonnet 4.6 — marginal cost "
                "stays low without sacrificing reasoning quality."
            ),
        ],
    )


def featherless_prize_slide():
    return Slide(
        title="Best Use of Featherless AI",
        badge="Slide 14 / 18",
        body_flowables=[
            h2("Prize: $500 cash + $300 + $100 credits"),
            kv_table(
                [
                    [
                        "Coverage",
                        "3 of 9 agents × 3 distinct open-weight model lineages, each chosen by role",
                    ],
                    [
                        "@VendorResearcher",
                        "meta-llama/Llama-3.3-70B-Instruct — sanctions / UBO / adverse-media resolution against fixture DB",
                    ],
                    [
                        "@LegalPolicyChecker",
                        "Qwen/Qwen3-Coder-30B-A3B-Instruct — statutory citation grounding (EU Directive 2014/24/EU + GDPR + AMLD6 + DORA + SOX)",
                    ],
                    [
                        "@EvidenceClerk",
                        "deepseek-ai/DeepSeek-V3-0324 — long-context evidence aggregation into typed EvidencePacket envelope",
                    ],
                    [
                        "Wiring",
                        "Featherless OpenAI-compatible gateway (https://api.featherless.ai/v1) · graceful MockLlmProvider fallback in tests",
                    ],
                    [
                        "Diversity",
                        "Three independent model lineages — no consensus trap, no two-agents-same-model deception",
                    ],
                ]
            ),
            divider(),
            small(
                "Open-weight specialists on every high-stakes research/policy/synthesis "
                "call — exactly the lane Featherless is built for."
            ),
        ],
    )


def pricing_slide():
    return Slide(
        title="Pricing tiers",
        badge="Slide 15 / 18",
        body_flowables=[
            h2("Community · Pro · Enterprise"),
            kv_table(
                [
                    [
                        "Community",
                        "Free · single tenant · 100 packets/mo · vouch-verify CLI",
                    ],
                    [
                        "Pro",
                        "$499/mo · 5 tenants · unlimited packets · CycloneDX AIBOM",
                    ],
                    [
                        "Enterprise",
                        "From $5k/mo · on-prem · KMS-issued keys · SSO + SAML · DPA",
                    ],
                ]
            ),
        ],
    )


def roadmap_slide():
    return Slide(
        title="Roadmap",
        badge="Slide 16 / 18",
        body_flowables=[
            h2("Phase A — D · what's next"),
            kv_table(
                [
                    [
                        "Phase A",
                        "Production hardening: KMS-issued per-tenant keys (replace baked compile-time keys)",
                    ],
                    [
                        "Phase B",
                        "Real OIDC identity for Sigstore Rekor publish (anchor in the public log)",
                    ],
                    [
                        "Phase C",
                        "Self-hosted LLM endpoint (Qwen3-235B-A22B on AMD MI300X, $0/inference)",
                    ],
                    [
                        "Phase D",
                        "IETF AAT format alignment (SHA-256 + ECDSA P-256, per the draft)",
                    ],
                ]
            ),
        ],
    )


def ask_slide():
    return Slide(
        title="Ask",
        badge="Slide 17 / 18",
        body_flowables=[
            h2("What Apohara VOUCH needs from the jury"),
            body(
                "1. <b>Main Track 3</b> — recognize the 9-agent procurement court + cryptographic Evidence Layer as the regulated-workflow artifact."
            ),
            body(
                "2. <b>Best Use of AI/ML API</b> — recognize 5/9 agents × 4 distinct models on the critical decision path."
            ),
            body(
                "3. <b>Best Use of Featherless</b> — recognize 3/9 agents × 3 distinct models as the open-weight specialist reasoning backbone."
            ),
            Spacer(1, 0.2 * inch),
            Paragraph(
                "The verb is <font color='#d4a017'><b>VOUCH</b></font>. "
                "Vouch for every agent decision.",
                H3,
            ),
        ],
    )


def contact_slide():
    return Slide(
        title="Contact",
        badge="Slide 18 / 18",
        body_flowables=[
            h2("Apohara VOUCH"),
            kv_table(
                [
                    ["Live demo", "https://vouch.apohara.dev"],
                    [
                        "Source",
                        "https://github.com/SuarezPM/apohara-themis",
                    ],
                    ["License", "MIT"],
                    [
                        "Author",
                        "Pablo M. Suarez · @SuarezPM",
                    ],
                    ["Sponsor integrations", "Band · AI/ML API · Featherless AI"],
                    ["Spec", "docs/SPEC.md · docs/REFERENCES.md"],
                ]
            ),
            Spacer(1, 0.3 * inch),
            Paragraph(
                "<i>Vouch for every agent decision.</i>",
                ParagraphStyle(
                    "tag",
                    fontName="Helvetica-Oblique",
                    fontSize=20,
                    alignment=1,
                    textColor=GOLD,
                ),
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
slides = [
    cover_slide(),
    problem_slide(),
    sponsor_stack_slide(),
    architecture_slide(),
    orchestrator_slide(),
    flow_slide(),
    evidence_layer_slide(),
    verify_slide(),
    demo_slide(),
    art12_slide(),
    cross_prize_overview_slide(),
    main_track3_slide(),
    aimlapi_prize_slide(),
    featherless_prize_slide(),
    pricing_slide(),
    roadmap_slide(),
    ask_slide(),
    contact_slide(),
]

assert len(slides) == 18, f"Expected 18 slides, got {len(slides)}"


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
c = canvas.Canvas(str(OUTPUT), pagesize=(PAGE_W, PAGE_H))
c.setTitle("Apohara VOUCH — Band of Agents Hackathon Pitch Deck")
c.setAuthor("Apohara VOUCH")
c.setSubject("Vouch for every agent decision")
c.setKeywords("Band, AI/ML API, Featherless, multi-agent, evidence, regulated")

for s in slides:
    # Reset the flowable's canvas binding
    s.canv = c
    # Draw the slide content
    from reportlab.platypus.flowables import Flowable as _FL

    # Use the standard "draw to current canvas" pattern
    s.wrapOn(c, PAGE_W, PAGE_H)
    s.drawOn(c, 0, 0)
    c.showPage()

c.save()
print(f"Wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes)")
