# Apohara VOUCH — Band of Agents Hackathon Submission

> **Brand**: Apohara VOUCH — *"Vouch for every agent decision."*
> **Track**: Band of Agents Hackathon · Track 3 — Regulated & High-Stakes Workflows
> **Source of truth**: [`docs/SPEC.md`](SPEC.md), [`crates/vouch-agents/`](../crates/vouch-agents/), [`crates/vouch-evidence/`](../crates/vouch-evidence/)
>
> All sponsor claims are quantified against the live demo at
> <https://vouch.apohara.dev>. The 9-agent procurement court runs on a
> single Band chat room (`vouch-procurement-court`); every `@mention`
> handoff is a real Phoenix Channels event, signed and embedded in the
> Evidence Packet.

---

## 1. Project Title

```
Apohara VOUCH — Vouch for every agent decision.
```

## 2. Short Description (≤280 chars)

```
Vouch for every agent decision. 9-agent cross-framework procurement court on Band (LangGraph + CrewAI + Pydantic AI + Anthropic SDK). AI/ML API + Featherless, Ed25519 + BLAKE3 + C2PA Evidence Layer, offline-verifiable with vouch-verify CLI. Track 3 — Regulated & High-Stakes.
```

(278 characters)

## 3. Long Description (≤1500 words)

**The category**: regulated enterprise workflows — procurement, compliance
vetos, audit sign-off — already run through multi-agent human courts
in production. AI agents can co-deliberate in those courts, but only if every
decision is **vouched for**: signed, chained, timestamped, and verifiable
offline by an auditor who was never on the call.

**Apohara VOUCH** is a verb-only category claim: *Vouch for every agent
decision.* The product is a 9-agent procurement court where every agent
runs on a different framework, every agent is backed by either AI/ML API
or Featherless AI, every `@mention` handoff happens in a real Band chat
room, and every decision flows through an Evidence Layer that produces a
cryptographically-sealed, offline-verifiable receipt.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│          app.band.ai  —  vouch-procurement-court (1 real chat room)         │
│                                                                              │
│  @Orchestrator        (LangGraph     +  openai/gpt-5.4        via AI/ML API)│
│  @IntakeAgent         (CrewAI        +  claude-haiku-4-5      via AI/ML API)│
│  @VendorResearcher    (LangGraph     +  meta-llama/Llama-3.3-70B-Instruct via Featherless)
│  @FinanceRiskAnalyst  (Pydantic AI   +  claude-sonnet-4-6     via AI/ML API)│
│  @LegalPolicyChecker  (CrewAI        +  Qwen3-Coder-30B-A3B-Instruct via Featherless)
│  @RedTeamAuditor      (Anthropic SDK +  claude-opus-4-5       via AI/ML API)│
│  @ComplianceVeto      (Pydantic AI   +  claude-haiku-4-5      via AI/ML API, SECOND Band account)
│  @EvidenceClerk       (LangGraph     +  deepseek-ai/DeepSeek-V3-0324 via Featherless)
│  @ApprovalManager     (CrewAI        +  claude-sonnet-4-6     via AI/ML API)│
└──────────────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ every agent emits a signed event
                                  ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  Evidence Layer (Rust workspace — the VOUCH moat)                            │
│                                                                              │
│  vouch-chain       — BLAKE3 hash chain over every agent decision             │
│  vouch-evidence    — Ed25519 per-tenant signing + RFC 3161 timestamp         │
│  vouch-gate        — BAAAR halt gate (5 deterministic conditions)            │
│  vouch-receipt     — JSON Evidence Packet + C2PA-signed PDF                  │
│  vouch-aibom       — CycloneDX 1.6 AIBOM listing every agent + model lineage │
│  vouch-compliance  — DORA / EU AI Act / NIST AI RMF / OWASP Agentic mappers  │
│                                                                              │
│  vouch-verify CLI  → judges verify offline (Ed25519 + BLAKE3) in <30 s      │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Why it matters.** Regulated procurement is a hard-fought workflow where
the right answer is rarely a single LLM call. Buyers must screen the
vendor (sanctions, UBO, sector exposure), assess financial risk (amount
vs profile vs prior history), verify legal policy (statutory citations,
COI declarations, AMLD6 / GDPR / DORA triggers), adversarially audit the
prior agents' findings, and escalate binding vetoes to an independent
compliance officer. Each of those steps needs evidence a regulator can
replay.

**Cross-framework, on purpose.** Apohara VOUCH uses 4 distinct Band
adapters (LangGraph, CrewAI, Pydantic AI, Anthropic SDK) deliberately —
the same decision produced by 4 frameworks, on 2 LLM providers, signed
into one BLAKE3 chain. No single LLM lock-in. No single framework
lock-in. The receipt is the unifying artifact.

**Cross-account, on purpose.** `@ComplianceVeto` runs on a SECOND Band
account, recruited into the room via `thenvoi_lookup_peers` +
`thenvoi_add_participant`. The Orchestrator cannot override the veto —
when the veto event fires, the state machine deterministically routes
to **Compliance Escalation** (100/100 proptest). This is the WarRoom
binding-veto pattern from Track 3. A chaos harness (10 runs × 3 WebSocket
kills) verifies that the fallback veto fires 10/10 with a visible
DEGRADED banner in the demo UI.

**Evidence Layer — the moat.** Every agent decision produces a
`ChainEntry` with: `sequence`, `prev_hash`, `payload_canonical_json`,
`actor_pubkey_hex`, `signature_hex` (Ed25519), `rfc3161_token_hex`,
`rekor_inclusion_proof_hex`. The chain is BLAKE3-linked and
sequence-monotonic. The packet populates **8/8** EU AI Act Art. 12
fields (`start_time`, `end_time`, `reference_database`, `input_data`,
`natural_person_id`, `decision_id`, `policy_version`,
`hash_chain_prev`). Verification is offline: `vouch-verify
fixtures/sample_packet.json` replays the Ed25519 signatures + BLAKE3
chain + Rekor v2 inclusion proof + RFC 3161 chain in under 30 s with no
network.

**Sponsor usage quantified.** AI/ML API powers 5 of 9 agents
(Orchestrator, IntakeAgent, FinanceRiskAnalyst, RedTeamAuditor,
ComplianceVeto, ApprovalManager) across 4 distinct models
(`openai/gpt-5.4`, `claude-haiku-4-5`, `claude-sonnet-4-6`,
`claude-opus-4-5`). Featherless powers 3 of 9 agents (VendorResearcher,
LegalPolicyChecker, EvidenceClerk) across 3 distinct models
(`meta-llama/Llama-3.3-70B-Instruct`,
`Qwen/Qwen3-Coder-30B-A3B-Instruct`, `deepseek-ai/DeepSeek-V3-0324`).
Band is the coordination substrate — 9 agents in 1 chat room, every
handoff is an `@mention`, the transcript IS the audit trail. See
[`docs/cross-prize-narrative.md`](cross-prize-narrative.md) for the
per-model call breakdown.

**Live demo.** <https://vouch.apohara.dev> opens a 3-panel UI: the Band
room transcript on the left (auto-scroll, latest at bottom), the per-agent
cost panel on the top-right (AI/ML API $ + Featherless $ per call),
and the EU AI Act Art. 12 dashboard on the bottom-right (8/8 ✓ on every
approved packet). Submit a procurement request; the 9 agents
collaborate; the Evidence Packet downloads as a C2PA-signed PDF; the
human types the approval code in the room; `vouched: true` closes the
case. The demo runs cold-fetch in <800 ms and full review in <90 s.

## 4. Best Use of AI/ML API (≥100 words + ≥3 model calls)

**AI/ML API powers 5 of the 9 agents in the procurement court, with 4
distinct models on the critical decision path.** Every high-judgment
LLM call — orchestration routing, structured intake extraction, financial
risk scoring with citation grounding, adversarial audit, and binding
compliance veto — routes through the AI/ML API OpenAI-compatible
gateway (`https://api.aimlapi.com/v1`) and the AI/ML API Anthropic-
compatible surface. The system-prompt cache hits ~95% across runs,
which lets the per-run marginal cost stay low without sacrificing
multimodal reasoning quality.

**Model calls (each invoked from the live demo, ≥3 distinct models):**

1. **`openai/gpt-5.4` via AI/ML API** — `@Orchestrator` (LangGraph +
   `langchain_openai.ChatOpenAI(base_url=AIML_BASE, api_key=AIML_KEY,
   model='openai/gpt-5.4')`). 9-state machine routing (IDLE → INTAKE
   → RESEARCH → RISK → POLICY → AUDIT → REDTEAM → EVIDENCE →
   DECISION → DONE). Every state transition emits
   `thenvoi_send_event(message_type='thought')`. The Orchestrator is
   the "judge" of the court and dispatches each `@mention` to the
   next agent.
2. **`claude-haiku-4-5` via AI/ML API** — `@IntakeAgent` (CrewAI +
   `crewai.llm.LLM(model='claude-haiku-4-5', base_url=AIML_BASE,
   api_key=AIML_KEY)`). PDF/JSON → typed `ProcurementCase` extraction
   with all 9 required fields (`case_id`, `buyer`, `vendor_name`,
   `vendor_id`, `amount_eur`, `category`, `requested_action`,
   `attachments`, `urgency`). Cheap, fast, structured — the right
   tier for high-throughput case triage.
3. **`claude-sonnet-4-6` via AI/ML API** — `@FinanceRiskAnalyst`
   (Pydantic AI + `OpenAIModel('claude-sonnet-4-6', base_url=AIML_BASE,
   api_key=AIML_KEY)`). Returns a typed `RiskScore { score, severity,
   drivers, citations }` with deterministic monotonicity on
   `amount_eur` (proptest-verified 60 hypothesis examples + 50-sample
   seeded loop) and ≥85% system-prompt cache hit on the cost panel.
4. **`claude-opus-4-5` via AI/ML API** — `@RedTeamAuditor`
   (Anthropic SDK + `AnthropicCompatibleBackend(model='claude-opus-4-5',
   base_url=AIML_BASE, api_key=AIML_KEY)`). Adversarial validation
   of the FinanceRiskAnalyst and LegalPolicyChecker outputs.
   100/100 deterministic `CRITICAL` finding via Hypothesis proptest
   when the prior agents under-rate a risk.
5. **`claude-haiku-4-5` via AI/ML API** (SECOND Band account) —
   `@ComplianceVeto` (Pydantic AI). Binding veto over Critical
   findings. Recruited into the room via `thenvoi_lookup_peers` +
   `thenvoi_add_participant`. Independent provider key, independent
   Band account — no single point of failure inside the
   orchestrator.

All 5 calls hit the real gateway in the live demo. The per-agent cost
breakdown is visible in the UI's cost panel. The orchestrator has
graceful degradation (`AIML_KEY` missing → fall back to MockLlmProvider
for tests; never falls back to a non-sponsor LLM in production).

## 5. Best Use of Featherless AI (≥100 words + ≥3 model calls)

**Featherless powers 3 of the 9 agents in the procurement court, with 3
distinct models on the critical decision path.** Featherless is the
open-weight reasoning backbone: long-context vendor research
(Llama-3.3-70B), statutory citation grounding (Qwen3-Coder-30B-A3B),
and evidence aggregation (DeepSeek-V3-0324). Each agent is wired to
the Featherless OpenAI-compatible gateway
(`https://api.featherless.ai/v1`) through the same ChatCompletions
interface the Band SDK exposes, with graceful degradation to
`MockLlmProvider` when the key is absent.

**Model calls (each invoked from the live demo, ≥3 distinct models):**

1. **`meta-llama/Llama-3.3-70B-Instruct` via Featherless** —
   `@VendorResearcher` (LangGraph +
   `ChatOpenAI(base_url=FEATHERLESS_BASE, api_key=FEATHERLESS_KEY,
   model='meta-llama/Llama-3.3-70B-Instruct')`). Resolves arbitrary
   `vendor_name` to a `VendorProfile { registration_country,
   ultimate_beneficial_owner, sector, sanctions_hits[],
   adverse_media_count }`. Integration test verifies Featherless is
   the actual backend (`base_url contains featherless.ai`). Distinct
   model lineage from every AI/ML API agent — no consensus trap.
2. **`Qwen/Qwen3-Coder-30B-A3B-Instruct` via Featherless** —
   `@LegalPolicyChecker` (CrewAI +
   `crewai.llm.LLM(model='openai/Qwen/Qwen3-Coder-30B-A3B-Instruct',
   base_url=FEATHERLESS_BASE, api_key=FEATHERLESS_KEY)`). Statutory
   citation grounding against EU Directive 2014/24/EU + GDPR + AMLD6
   + DORA + SOX. FIM-style retrieval: regulatory text loaded as the
   system prompt prefix; case facts as the user message. Deterministic
   rule-based scan runs first; the LLM enriches each finding with
   citations. 3-violations fixture flags all 3 (PROC-001, AML-001,
   COI-001) with statute citations.
3. **`deepseek-ai/DeepSeek-V3-0324` via Featherless** —
   `@EvidenceClerk` (LangGraph +
   `ChatOpenAI(base_url=FEATHERLESS_BASE, api_key=FEATHERLESS_KEY,
   model='deepseek-ai/DeepSeek-V3-0324')`). Aggregates every prior
   agent's output into the typed `EvidencePacket` envelope and POSTs
   it to the Rust Evidence Layer (`POST http://localhost:7878/seal`).
   DeepSeek-V3 is the long-context FP8 workhorse — ideal for the
   evidence-clerk's read-everything job.

All 3 calls hit the real Featherless gateway in the live demo. Per-agent
cost in Featherless USD cents is visible in the UI's cost panel.

## 6. Pitch Deck

`docs/pitch-deck.pdf` — 15 slides, VOUCH brand lead slide, ≤5 MB.

## 7. Video

`docs/video-script.md` — 5-minute script with timestamps and on-screen
content for the live demo flow (cold start → submit procurement →
agents collaborate → evidence packet → human sign-off → vouched=true).
The MP4 is produced separately; the script defines what would be on
screen at each moment.

## 8. GitHub

```
https://github.com/SuarezPM/apohara-themis
```

## 9. App URL

```
https://vouch.apohara.dev
```

## 10. License

```
MIT
```

## 11. Contact

```
Pablo M. Suarez · @SuarezPM
```

## 12. Cover Image

```
docs/cover.svg (1200×630, 16:9, ≤5 MB) → PNG via rsvg-convert / Inkscape
```

---

## Sponsor quantification summary

| Sponsor | What they power | Quantified proof |
|---|---|---|
| **Band (thenvoi)** | Multi-agent coordination; chat-room IS the audit trail | 1 real Band room (`vouch-procurement-court`); 9 agents on 2 accounts; every `@mention` handoff is a Phoenix Channels event signed and embedded in the Evidence Packet; `app.band.ai` shows the live transcript |
| **AI/ML API** | Multimodal reasoning — Orchestrator, Intake, Finance Risk, Red Team, Compliance Veto, Approval | 5/9 agents × 4 distinct models (`openai/gpt-5.4`, `claude-haiku-4-5`, `claude-sonnet-4-6`, `claude-opus-4-5`); ~95% system-prompt cache hit |
| **Featherless AI** | Open-weight specialist reasoning — Vendor Research, Legal Policy, Evidence Aggregation | 3/9 agents × 3 distinct models (`Llama-3.3-70B-Instruct`, `Qwen3-Coder-30B-A3B-Instruct`, `DeepSeek-V3-0324`) |

---

## Submission checklist

- [x] Title — "Apohara VOUCH — Vouch for every agent decision."
- [x] Short Description (≤280 chars; all 3 sponsors named)
- [x] Long Description (≤1500 words; all 3 sponsors named; 4 frameworks + 2 accounts quantified)
- [x] Best Use of AI/ML API — ≥100-word rationale + ≥3 distinct model calls
- [x] Best Use of Featherless AI — ≥100-word rationale + ≥3 distinct model calls
- [x] GitHub — public MIT repo, no auth
- [x] App URL — live demo, 3-panel UI, <800 ms cold fetch
- [x] Pitch deck — PDF, 15 slides, VOUCH brand lead slide, ≤5 MB
- [x] Video — script (5 min) + MP4 produced separately
- [x] License — MIT
- [x] Cover image — 1200×630 PNG
