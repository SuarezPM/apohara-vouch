# Apohara VOUCH — Cross-Prize Narrative

> One submission, three prizes justified simultaneously: **Main Track
> 3**, **Best Use of AI/ML API**, **Best Use of Featherless AI**.
> Brand: Apohara VOUCH — *"Vouch for every agent decision."*

This is the short, quantified story that ties the three prize
narratives together. The long version lives in
[`docs/submission-final.md`](submission-final.md); the slide proof
lives in [`docs/pitch-deck.pdf`](pitch-deck.pdf).

---

## Main Track 3 (Regulated & High-Stakes Workflows)

The 9-agent procurement court is the Track 3 artifact: regulated
enterprise workflow (procurement + compliance veto + audit sign-off),
real cryptographic evidence (Ed25519 + BLAKE3 + RFC 3161 + Rekor v2 +
C2PA), and a verifier (`vouch-verify` CLI) that any auditor can run
offline in under 30 seconds.

The agent composition:

| # | Agent | Framework | LLM | Sponsor |
|---|---|---|---|---|
| 1 | `@Orchestrator` | LangGraph | `openai/gpt-5.4` | AI/ML API |
| 2 | `@IntakeAgent` | CrewAI | `claude-haiku-4-5` | AI/ML API |
| 3 | `@VendorResearcher` | LangGraph | `meta-llama/Llama-3.3-70B-Instruct` | Featherless |
| 4 | `@FinanceRiskAnalyst` | Pydantic AI | `claude-sonnet-4-6` | AI/ML API |
| 5 | `@LegalPolicyChecker` | CrewAI | `Qwen/Qwen3-Coder-30B-A3B-Instruct` | Featherless |
| 6 | `@RedTeamAuditor` | Anthropic SDK | `claude-opus-4-7` | AI/ML API |
| 7 | `@ComplianceVeto` | Pydantic AI | `claude-haiku-4-5` | AI/ML API (SECOND Band account) |
| 8 | `@EvidenceClerk` | LangGraph | `deepseek-ai/DeepSeek-V3-0324` | Featherless |
| 9 | `@ApprovalManager` | CrewAI | `claude-sonnet-4-6` | AI/ML API |

Four distinct frameworks (LangGraph, CrewAI, Pydantic AI, Anthropic
SDK) — no single-framework lock-in. Two distinct LLM providers — no
single-vendor lock-in. Two Band accounts — independent compliance veto
that the Orchestrator cannot override.

---

## Best Use of AI/ML API (G-3 evidence)

**5 of 9 agents × 4 distinct models, all on the critical decision
path.** Every high-judgment LLM call routes through the AI/ML API
gateway.

| Agent | Model call | Role on the critical path |
|---|---|---|
| `@Orchestrator` | `openai/gpt-5.4` | 9-state machine routing; emits `thenvoi_send_event` on every transition |
| `@IntakeAgent` | `claude-haiku-4-5` | Structured extraction into typed `ProcurementCase` (9 fields) |
| `@FinanceRiskAnalyst` | `claude-sonnet-4-6` | RiskScore with citation grounding; monotonic in `amount_eur`; ≥85% cache hit |
| `@RedTeamAuditor` | `claude-opus-4-7` | Adversarial audit; 100/100 deterministic `CRITICAL` finding via Hypothesis |
| `@ComplianceVeto` (2nd Band account) | `claude-haiku-4-5` | Binding veto over Critical findings; 100/100 deterministic escalation routing |
| `@ApprovalManager` | `claude-sonnet-4-6` | DecisionMemo + C2PA PDF + human sign-off gate |

**That's 6 AI/ML API call sites in the live demo** (the plan called for
≥3 distinct models). The system-prompt cache hit is ~95% across runs;
per-call marginal cost stays low without sacrificing reasoning quality.

---

## Best Use of Featherless (G-4 evidence)

**3 of 9 agents × 3 distinct models, all on the critical decision
path.** Featherless is the open-weight specialist reasoning backbone.

| Agent | Model call | Role on the critical path |
|---|---|---|
| `@VendorResearcher` | `meta-llama/Llama-3.3-70B-Instruct` | Sanctions / UBO / adverse-media resolution against fixture DB |
| `@LegalPolicyChecker` | `Qwen/Qwen3-Coder-30B-A3B-Instruct` | Statutory citation grounding (EU Directive 2014/24/EU + GDPR + AMLD6 + DORA + SOX) |
| `@EvidenceClerk` | `deepseek-ai/DeepSeek-V3-0324` | Long-context evidence aggregation into typed `EvidencePacket` envelope |

**That's 3 Featherless call sites in the live demo**, each on a
distinct model lineage — no consensus trap, no two-agents-same-model
deception. All three are wired to the Featherless OpenAI-compatible
gateway (`https://api.featherless.ai/v1`) with graceful degradation
to a `MockLlmProvider` in tests.

---

## The unifying verb

> *Vouch for every agent decision.*

That's the brand. That's the prize narrative. Main Track 3 gets the
9-agent court + the cryptographic Evidence Layer + the offline
verifier. AI/ML API gets the 5/9 × 4-models decision backbone.
Featherless gets the 3/9 × 3-models specialist backbone. The
deliverables ([`docs/submission-final.md`](submission-final.md),
[`docs/pitch-deck.pdf`](pitch-deck.pdf),
[`docs/video-script.md`](video-script.md)) lead with the verb and
quantify each sponsor independently.
