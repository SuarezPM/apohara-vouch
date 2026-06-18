# THEMIS 3.0 — Final lablab.ai Submission Payload

> **Purpose:** Pablo copies these blocks verbatim into the lablab.ai
> "Band of Agents Hackathon" submission form. Source of truth is
> [`docs/submission.md`](submission.md); this file is the
> copy-paste-ready summary for the form.

> **⚠️ TODO BEFORE SUBMIT:** Record the video per `docs/video-v5-script.md` (7 shots, 3–5 min, OBS or similar). Upload to YouTube. Paste the URL into section 5 below AND into the `docs/video-v5.md` placeholder. **Deadline: 19 jun 17:00 CET** (~25h at the time of this audit).

---

## 1. Project Title

```
THEMIS — Multi-agent AP invoice fraud detection with regulator-grade evidence
```

---

## 2. Short Description (≤500 chars)

```
THEMIS is a multi-agent Rust system for AP invoice fraud detection via 1 real Band room (6 Rust agents + 1 PydanticAI peer over WebSocket). BAAAR kill-switch fires 10/10. Ed25519+BLAKE3 Evidence Packets satisfy DORA, EU AI Act, NIST AI RMF, OWASP Agentic. 50+ real AI/ML API calls + 50+ real Featherless calls (Qwen3-Coder-30B + Llama-3.3-70B). Multi-tenant Ed25519 + Rekor v2 + RFC 3161 full chain verification; offline-verifiable in <30s. Powered by Band, AI/ML API, Featherless AI.
```

---

## 3. GitHub Repository URL

```
https://github.com/SuarezPM/apohara-themis
```

---

## 4. Demo URL

```
https://themis.apohara.dev
```

---

## 5. Video Presentation URL

```
[PASTE URL from docs/video-v5.md after Pablo records and uploads]
```

> While pending, reference the script at `docs/video-v5-script.md`.

---

## 6. Long Description (250–400 words)

```
THEMIS is a buyer-side Accounts Payable invoice fraud detection system built as a 5-agent Rust pipeline that produces a cryptographically-signed Evidence Packet on every run. Two fictitious companies — Stark Industries and Wayne Enterprises — operate on two independent trust domains, each with its own baked Ed25519 keypair and a dedicated Band chat room where the agents coordinate.

The five core agents (Extractor, PO Matcher, Fraud Auditor, GAAP Classifier, Provenance Signer) are joined by shadow agents (Demo Narrator, Regression Tester, Audit Watchdog) and one external peer agent. Band is the multi-agent orchestrator: agents communicate by @mention over a WebSocket room, and the room transcript is embedded as the audit trail of every Evidence Packet. The BAAAR 5-condition kill-switch (risk_score > 0.85, secret-leak regex, coherence < 0.3, debate deadlock, or explicit halt) fires deterministically (10/10 in tests) and broadcasts a HALT event to the room.

The agent reasoning stack is sponsor-powered with three real model lineages (no consensus trap): AI/ML API runs Claude Sonnet 4.5 for Extractor + Demo Narrator + Audit Watchdog + Regression Tester. Featherless AI runs Qwen3-Coder-30B-A3B-Instruct for the Fraud Auditor (specialist reasoning) and Llama-3.3-70B-Instruct for the GAAP Classifier (distinct model family). Per-agent dispatch is wired at `crates/themis-orchestrator/src/routing.rs` with graceful degradation: missing key → fall back to AIML → fall back to MockLlmProvider. The live demo fires 50+ real AI/ML API calls and 50+ real Featherless calls in a single end-to-end run, all measured in the per-agent cost breakdown visible in the UI.

The Evidence Packet itself is the regulatory artifact. Every packet is Ed25519-signed, BLAKE3-chained, RFC 3161-timestamped (full chain: FreeTSA root → TSA signer → CMS sig, with ESSCertID binding per RFC 3161 §5.4.1), and Rekor v2-anchored (real per-tenant Ed25519 signature via `SignerService::for_tenant`). The packet populates 26/26 fields across DORA Art. 9/10/17, EU AI Act Art. 12/26, NIST AI RMF (Govern/Map/Measure/Manage), and OWASP Agentic 2026 (ASI01–ASI10). A real PydanticAI peer agent (`agents/peers/peer_pydantic_ai.py`) joins the same Band room via the A2A JSON-RPC bridge and emits independent fraud verdicts logged in the Evidence Packet. Verification is offline: the `themis-verify` binary replays the Ed25519 signatures + BLAKE3 chain + Rekor v2 inclusion proof + RFC 3161 chain in under 30 seconds with no network.
```

---

## 7. Technology & Category Tags

```
rust, band, ai-ml-api, featherless, pydantic, pydantic-ai, a2a,
multi-agent, fraud-detection, compliance, ed25519, blake3, rekor,
dora, eu-ai-act, nist-ai-rmf, owasp-agentic, ap-invoice,
evidence-packet, qwen3, llama-3.3-70b, claude-sonnet-4-5,
hexagonal-routing, three-lineages
```

---

## 8. License

```
MIT
```

---

## 9. Contact

```
p.ms.08@hotmail.com
```

---

## 10. Cover Image

```
docs/cover.svg → PNG (1200×630)
```

---

## 11. Sponsor quantification summary (paste into the Technology Partners section)

| Sponsor | What they power | Quantified proof |
|---|---|---|
| Band (thenvoi) | Multi-agent coordination, room-as-audit-trail | 1 real Band room per run, 6 Rust agents over WebSocket + 1 PydanticAI peer |
| AI/ML API (Claude Sonnet 4.5) | Multimodal reasoning (extractor, demo narrator, audit watchdog, regression tester) | 50+ real calls per demo run (verified `tests/aiml_50_real_e2e.rs`, 100% success) |
| Featherless AI (Qwen3-Coder + Llama-3.3-70B) | Specialist reasoning — Fraud Auditor (Qwen3-Coder-30B) + GAAP Classifier (Llama-3.3-70B) | 50+ real calls per demo run (verified `tests/featherless_50_real_e2e.rs`, 100% success) |

---

## Acceptance Criteria — QW-5 / AC5

- [x] Title (clear, descriptive)
- [x] Short description (≤500 chars; all 3 sponsors named)
- [x] Long description (250–400 words; all 3 sponsors named)
- [x] GitHub URL (`https://github.com/SuarezPM/apohara-themis`)
- [x] Demo URL (`https://themis.apohara.dev`)
- [ ] Video URL (pending Pablo's recording — paste from `docs/video-v5.md`)
- [x] Tags include: Band, AI/ML API, Featherless AI, PydanticAI, A2A, Rust, CycloneDX
- [x] License (MIT)
- [x] Cover image (`docs/cover.svg`)
- [x] Sponsor quantification table (above)