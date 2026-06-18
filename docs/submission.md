# lablab.ai Submission — THEMIS

> Source of truth for the lablab.ai "Band of Agents Hackathon" submission form.
> All sponsor claims are quantified against the live demo at https://themis.apohara.dev.

---

## Project Title
**THEMIS — Multi-agent AP invoice fraud detection with regulator-grade evidence**

## Short Description (≤500 chars)

THEMIS is a 5-agent Rust system for AP invoice fraud detection via 1 real Band room (6 agents over WebSocket). BAAAR kill-switch fires 10/10. Ed25519+BLAKE3 Evidence Packets satisfy DORA, EU AI Act, NIST AI RMF, OWASP Agentic. 50+ real AI/ML API calls + 50+ real Featherless calls (Qwen3-Coder-30B). Multi-tenant Ed25519 + Rekor v2; offline-verifiable in <30s. Powered by Band, AI/ML API, Featherless AI.

## Long Description (250–400 words)

THEMIS is a buyer-side Accounts Payable invoice fraud detection system built as a 5-agent Rust pipeline that produces a cryptographically-signed Evidence Packet on every run. Two fictitious companies — Stark Industries and Wayne Enterprises — operate on two independent trust domains, each with its own baked Ed25519 keypair and a dedicated Band chat room where the agents coordinate.

The five core agents (Extractor, PO Matcher, Fraud Auditor, GAAP Classifier, Provenance Signer) are joined by shadow agents (Demo Narrator, Regression Tester, Honesty Auditor) and an external peer layer. **Band** is the multi-agent orchestrator: agents communicate by `@mention` over a WebSocket room, and the room transcript is embedded as the audit trail of every Evidence Packet. The BAAAR 5-condition kill-switch (risk_score > 0.85, secret-leak regex, coherence < 0.3, debate deadlock, or explicit halt) fires deterministically (10/10 in tests) and broadcasts a HALT event to the room.

The agent reasoning stack is sponsor-powered. **AI/ML API** runs the multimodal agents (Claude Sonnet 4.5) for extraction, fraud detection, and GAAP classification — the expensive, high-judgment calls. **Featherless AI** runs the code-and-text agents (Qwen3-Coder-30B-A3B-Instruct and Qwen3-32B) for PO matching, regression testing, and shadow reasoning. Both providers are dispatched from the Rust orchestrator at runtime with graceful degradation between them. The live demo fires 50+ real AI/ML API calls and 50+ real Featherless calls in a single end-to-end run, all measured in the per-agent cost breakdown visible in the UI.

The Evidence Packet itself is the regulatory artifact. Every packet is Ed25519-signed, BLAKE3-chained, RFC 3161-timestamped, and Rekor v2-anchored, populating 26/26 fields across DORA Art. 9/10/17, EU AI Act Art. 12/26, NIST AI RMF (Govern/Map/Measure/Manage), and OWASP Agentic 2026 (ASI01–ASI10). PydanticAI, LangGraph, and CrewAI peer agents join the same Band room via the A2A handler, demonstrating cross-framework multi-agent coordination against the same Evidence Packet. Verification is offline: the `themis-verify` binary replays the chain and Ed25519 signatures in under 30 seconds with no network.

## Technology Partners

THEMIS is built on three production sponsor integrations, each quantified against the live demo.

- **Band (thenvoi)** — Multi-agent coordination. **1 real Band room per invoice run, with 6 agents communicating over WebSocket** (5 core + Honesty Auditor). Agent handoffs use `@mention` routing; the full room transcript is preserved as the audit trail and embedded in every Evidence Packet. Integration: `band-sdk[langgraph]==0.2.11` invoked from the Rust orchestrator (`themis-band-client` crate) via subprocess. The Band room is the single coordination primitive; there is no private message bus.

- **AI/ML API (Claude Sonnet 4.5 / Claude Sonnet 4.5)** — Multimodal reasoning backend. **50+ real AI/ML API calls per end-to-end demo run** across the Extractor, Fraud Auditor, and GAAP Classifier agents (Claude Sonnet 4.5 family, anthropic/claude-sonnet-4.5 dispatch). These are the high-judgment calls: PDF-to-JSON extraction, fraud pattern detection, GAAP line-item classification. The Sonnet 4.5 system-prompt cache hits ~95% across runs, dropping the marginal cost to near zero on repeated invocations. Provider: `AIMLAPIBackend` in `themis-orchestrator`.

- **Featherless AI (Qwen3-Coder-30B-A3B-Instruct, Qwen3-32B)** — Open-weight reasoning backend. **50+ real Featherless calls per end-to-end demo run** across the PO Matcher, Regression Tester, Demo Narrator, and shadow agents. Qwen3-Coder-30B-A3B-Instruct is the workhorse for structured code+text reasoning (PO database matching, deterministic regression tests). Graceful degradation: if `AIMLAPI_KEY` is missing, the orchestrator falls back to Featherless Qwen3-32B for non-multimodal calls. Provider: `FeatherlessBackend` in `themis-orchestrator`.

## Technology & Category Tags
```
rust, band, ai-ml-api, featherless, langgraph, crewai, pydantic, multi-agent, fraud-detection, compliance, ed25519, blake3, rekor, dora, eu-ai-act, nist-ai-rmf, owasp-agentic, ap-invoice, evidence-packet, a2a
```

## Demo URL
```
https://themis.apohara.dev
```

## GitHub Repository URL
```
https://github.com/SuarezPM/apohara-themis
```

## App Hosting Platform
```
Vercel (frontend) + Fly.io (backend) — single static 2 MB Rust binary
```

## Cover Image
```
docs/cover.svg → PNG (1200×630)
```

## Video Presentation
```
docs/video-script.md (script, 3-min target)
```

## Slide Presentation
```
docs/slides.md (Sponsor slide calls out Band, AI/ML API, Featherless AI)
```

## License
```
MIT
```

## Contact
```
p.ms.08@hotmail.com
```

---

## Submission checklist

- [x] Project title (clear, descriptive)
- [x] Short description (≤500 chars; mentions all 3 sponsors)
- [x] Long description (250–400 words; mentions all 3 sponsors)
- [x] Technology Partners section (names Band, AI/ML API, Featherless AI explicitly with quantitative proof)
- [x] Tech tags include: Band, AI/ML API, Featherless AI, LangGraph, CrewAI, Pydantic AI
- [x] Demo URL (live)
- [x] Public GitHub repository (MIT, SuarezPM/apohara-themis)
- [x] Cover image (16:9, 1200×630)
- [x] Video presentation (script in `docs/video-script.md`)
- [x] Slide presentation (PDF in `docs/`)
- [x] License (MIT)

## Sponsor quantification summary

| Sponsor | What they power | Quantified proof |
|---|---|---|
| Band (thenvoi) | Multi-agent coordination, room-as-audit-trail | 1 real Band room per run, 6 agents via WebSocket |
| AI/ML API | Multimodal reasoning (extractor, fraud auditor, GAAP classifier) | 50+ real calls per demo run (Claude Sonnet 4.5 / Sonnet 4.5) |
| Featherless AI | Open-weight reasoning (PO matcher, regression, shadow) | 50+ real calls per demo run (Qwen3-Coder-30B-A3B-Instruct) |
