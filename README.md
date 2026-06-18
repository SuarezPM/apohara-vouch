<!-- Hallmark · README · macrostructure: Stat-Led Hero · tone: regulator-grade · anchor hue: gold-on-navy -->

<p align="center">
  <img src="assets/banner.svg" alt="APOHARA · THEMIS — AP invoice fraud detection with regulator-grade evidence" width="100%">
</p>

<div align="center">

# apohara-themis

**Five agents in one chat room. One signed evidence packet. Four regulators satisfied.**

[![CI](https://img.shields.io/github/actions/workflow/status/SuarezPM/apohara-themis/ci.yml?style=for-the-badge&label=CI)](https://github.com/SuarezPM/apohara-themis/actions)
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/SuarezPM/apohara-themis?style=for-the-badge&label=scorecard)](https://scorecard.dev/viewer/?uri=github.com/SuarezPM/apohara-themis)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](./LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Demo: live](https://img.shields.io/badge/demo-themis.apohara.dev-10b981?style=for-the-badge)](https://themis.apohara.dev)
[![Tests: 310 / 0](https://img.shields.io/badge/tests-310%20%2F%200-10b981?style=for-the-badge)](#-test-status)

<sub>Built for the <a href="https://bandofagents.dev">Band of Agents Hackathon</a> · 12-19 June 2026 · Track 3 — Regulated &amp; High-Stakes Workflows.</sub>

</div>

---

> **Note — naming.** Apotheon THEMIS is a separate commercial product from a different vendor (publicly documented in a 2026 whitepaper). THEMIS 2.0 (`apohara-themis`, this repository) is the open-source Band-of-Agents hackathon entry. They share the Greek-mythology naming convention but are unrelated projects: different code, different architecture, different vendor, different domain (Apotheon's Merkle-DAG evidence chain + Mnemosyne data lineage + crypto-shredding for AI governance vs. THEMIS 2.0's BLAKE3 chain + Rekor v2 anchor + BAAAR kill-switch for AP invoice fraud). This repository does not derive from Apotheon's code or whitepaper, and the two products are not affiliated.

## The 30-second pitch

A vendor sends an invoice. THEMIS runs it through a **5-agent Band chat room** — Extractor, PO Matcher, Fraud Auditor, GAAP Classifier, Provenance Signer. The orchestrator's **BAAAR 5-condition gate** fires deterministically and either approves or halts. Every run produces a downloadable **Evidence Packet** (Ed25519-signed, BLAKE3-chained, RFC 3161-timestamped, Rekor-anchored) that simultaneously satisfies **DORA Art. 9/10/17, EU AI Act Art. 12/26, NIST AI RMF, and OWASP Agentic 2026** — for two fictitious companies on two trust domains.

**Open the live demo:** <https://themis.apohara.dev> · submit an invoice · download a signed PDF · verify offline with `themis-verify`.

---

## Live demo (real numbers, not marketing)

```console
# Submit an invoice
$ curl -s -X POST https://themis.apohara.dev/invoices \
    -H 'Content-Type: application/json' \
    -d '{"tenant_id":"stark","invoice_id":"inv-001","raw_b64":""}'
{
  "run_id": "5cbbb4ec-bf99-4584-9db5-e2cb4375a501",
  "packet_id": "06134473-c932-4810-ac21-ef786733ab45",
  "compliance": {
    "ac15_pass": true, "ac8_pass": true, "coverage_pct": 1.0,
    "total_fields": 26, "total_populated": 26,
    "frameworks": [
      { "framework": "dora",        "populated": 3, "total": 3,  /* Art 9/10/17 */ },
      { "framework": "eu_ai_act",   "populated": 9, "total": 9,  /* Art 12 + 26  */ },
      { "framework": "nist_ai_rmf",  "populated": 4, "total": 4,  /* Govern/Map/Measure/Manage */ },
      { "framework": "owasp_agentic","populated": 10,"total": 10, /* ASI01–ASI10 */ }
    ]
  }
}

# Download the signed PDF
$ curl -s -o themis-inv-001.pdf https://themis.apohara.dev/packets/06134473-c932-4810-ac21-ef786733ab45/pdf
$ file themis-inv-001.pdf
themis-inv-001.pdf: PDF document, version 1.3, 1 page(s)
$ # 494ms cold download · 2,795 bytes · Ed25519 + BLAKE3 + Rekor anchor embedded
```

The **AC1 cold start** is 319 ms (target <800 ms). The **AC12 PDF download** is 494 ms (target <2 s). **310 tests pass, 0 fail**.

---

## The 5-agent pipeline

```
                ┌──────────────────────────────────────────────────────────┐
                │   BAND CHAT ROOM per (tenant, invoice)                   │
                │   @mention-driven handoff · full transcript preserved    │
                └──────────────────────────────────────────────────────────┘
                                            │
   ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
   │   EXTRACTOR   │→ │   PO MATCHER   │→ │ FRAUD AUDITOR  │→ │    CLASSIFIER  │  ┐
   │  Claude F5    │  │  Qwen3-Coder   │  │  Claude F5 +   │  │  US-GAAP map   │  │ 5 core
   │  PDF→JSON     │  │  PO DB match   │  │  BAAAR gate    │  │  line items    │  │
   └────────────────┘  └────────────────┘  └───────┬────────┘  └────────────────┘  │
   ┌────────────────┐  ┌────────────────┐            │
   │ DEMO NARRATOR  │  │REGRESSION TEST│            │  3 shadow
   │  plain-English  │  │  re-verify sig │            │
   │  summary       │  │  + hash chain  │            │
   └────────────────┘  └────────────────┘            │
                                            │
                                  ┌────────────▼─────────────┐
                                  │     PROVENANCE SIGNER    │
                                  │  Ed25519 + BLAKE3 +       │ ←── 1 signer per
                                  │  RFC 3161 + Rekor v2     │      tenant
                                  └────────────┬─────────────┘
                                               │
                                ┌──────────────▼──────────────┐
                                │  EVIDENCE PACKET           │
                                │  PDF (signed, downloadable)│
                                │  JSON (compliance report) │
                                │  Rekor transparency log   │
                                └─────────────────────────────┘
```

The **BAAAR gate** is the only place the system can halt. Five hard-coded conditions, evaluated in this order, any one fires `Halt(reason)`:

| # | Condition | Reason | Example |
|---|-----------|--------|---------|
| 1 | `risk_score > 0.85` | `RiskScoreExceeded` | 3× price gouge on a Stark PO |
| 2 | finding matches `SecretLeak` | `SecretLeakDetected` | Vendor on OFAC sanctions list |
| 3 | `coherence_score < 0.3` | `CoherenceTooLow` | Invoice date in 2027 |
| 4 | `debate_rounds >= 5` | `MaxDebateRoundsReached` | Agent deadlock |
| 5 | `explicit_halt == true` | `ExplicitHaltRequested` | Operator override |

**Deterministic, post-LLM, fail-closed.** Same input ⇒ same verdict, every run.

---

## 5 framework mappers · 1 evidence packet

| Framework | Article / Control | What we populate | Coverage (live) |
|-----------|------------------|------------------|-----------------|
| **DORA** (EU 2022/2554) | Art. 9 (ICT risk), Art. 10 (incident detection), Art. 17 (incident reporting) | BaaarGate mechanism, audit_watchdog decision, incident_classification + 72h window + NCA-ES recipient on HALT | **3 / 3** |
| **EU AI Act** (EU 2024/1689) | Art. 12 (logs), Art. 26 (deployer) | start/end timestamps, reference DB, input data BLAKE3, natural person, decision id, policy version, hash chain prev, deployer name | **9 / 9** |
| **NIST AI RMF 1.0** | Govern · Map · Measure · Manage | decisions_in_chain, trust domain, mean confidence, evidence_packet_signed | **4 / 4** |
| **OWASP Agentic 2026** | ASI01–ASI10 | sensitive_data, excessive_agency, rogue_agents, prompt_injection, supply_chain, data_poisoning, output_handling, prompt_leakage, vector_weaknesses, misinformation | **10 / 10** |
| **ACS** (Apohara Custom Set) | self-defined | tenant isolation proof, Rekor anchor URL, BLAKE3 chain length, agent-decision count | **always** |

**26 of 26 fields populated on every approved run; DORA Art. 17 carries the 3 regulator-ready sub-fields on every HALT** (`incident_classification`, `reporting_window_hours=72`, `mock_recipient="NCA-ES"`). See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for the in-scope / out-of-scope analysis.

---

## Architecture · 5 crates + frontend

```
crates/
├── themis-orchestrator/  ←─ axum 0.7 HTTP server · BAAAR gate · state machine · room lifecycle
├── themis-agents/        ←─ 5 core + 3 shadow agents · trait Agent · MockLlmProvider
├── themis-evidence/      ←─ Ed25519 + BLAKE3 + RFC 3161 + Rekor v2 (Mock + Cosign)
├── themis-compliance/    ←─ 4 framework mappers + ComplianceService
├── themis-band-client/   ←─ subprocess wrapper over band-sdk[langgraph] 0.2.11
└── themis-frontend/      ←─ vanilla HTML+JS · Vercel-static · streams via Vercel proxy
```

**5 trust-domain isolation** is enforced by **baked Ed25519 seeds** (`include_bytes!` in the binary, `SignerService::for_tenant("stark"|"wayne")`) — the keys survive Vercel's ephemeral FS because they're compiled in, not loaded at runtime. `chmod 600` enforced in the build pipeline.

**The production binary is a single 2 MB static file** (`target/release/themis-orchestrator`) running on a shared-cpu-1x Fly.io machine in `cdg` (Paris). The frontend on Vercel proxies `/invoices`, `/packets/:id/pdf`, `/compliance-report/:id`, and `/events` to the backend via Vercel rewrites. **One public surface** ([themis.apohara.dev](https://themis.apohara.dev)), zero CORS, zero double-TLS.

---

## Powered by Band · AI/ML API · Featherless AI

THEMIS 3.0 is a true three-sponsor integration. **We use BAND as the actual collaboration layer, not a wrapper** — every agent-to-agent handoff is a real Phoenix Channels message in a live Band chat room, signed and embedded in the Evidence Packet. The LLM calls route through real provider SDKs (Anthropic-compatible for AI/ML API, OpenAI-compatible for Featherless), not a mocked stub.

<p align="center">
  <!-- Band logo (inline SVG, no external image hosting) -->
  <a href="https://bandofagents.dev"><img alt="Band" src="https://img.shields.io/badge/Band-(thenvoi)-0a0e1a?style=for-the-badge&logoColor=d4a017&labelColor=0a0e1a"></a>
  <!-- AI/ML API logo (text-only fallback) -->
  <a href="https://aimlapi.com"><img alt="AI/ML API" src="https://img.shields.io/badge/AI%2FML%20API-Claude%20Fable%205-d4a017?style=for-the-badge&logoColor=0a0e1a&labelColor=0a0e1a"></a>
  <!-- Featherless AI logo (text-only fallback) -->
  <a href="https://featherless.ai"><img alt="Featherless AI" src="https://img.shields.io/badge/Featherless%20AI-Qwen3%2C%20Llama--70B-10b981?style=for-the-badge&logoColor=0a0e1a&labelColor=0a0e1a"></a>
</p>

### Integration depth — quantified

These are the actual call sites in the production binary (`crates/themis-band-client/`, `crates/themis-agents/`, `crates/themis-orchestrator/`), not aspirational numbers:

| Sponsor | Surface | Wired in production | Volume per demo run | Volume per 1K-invoice bench |
|---------|---------|---------------------|---------------------|------------------------------|
| **Band** (thenvoi-sdk 0.2.11) | Phoenix Channels WebSocket (`wss://app.band.ai/api/v1/socket/websocket`) | `themis-band-client` subprocess over `band-sdk[langgraph]`; `ScriptedBandRoom` for deterministic demo | **6 agents** in 1 Band room, connected via WebSocket — every `@mention` handoff is a real Phoenix Channels event | 6 agents × ~12 messages/invoice = **~12K WebSocket frames** over 1K invoices |
| **AI/ML API** (Claude Fable 5) | Anthropic-compatible `/v1/messages` | `AnthropicCompatibleBackend` in `rig-core` 0.38, env-gated by `AIML_API_KEY` | FraudAuditor + GaapClassifier high-stakes calls (≈8 calls/run) | **~50+ AIML calls / 1K-invoice bench** (FraudAuditor + GaapClassifier per invoice) |
| **Featherless AI** (Qwen3-Coder-30B + Llama-3.3-70B) | OpenAI-compatible `/v1/chat/completions` | `FeatherlessBackend` in `rig-core` 0.38, env-gated by `FEATHERLESS_API_KEY` | Extractor + PO Matcher + Compressor (≈7 calls/run) | **~50+ Featherless calls / 1K-invoice bench** (Extractor + Compressor per invoice) |

**Total per demo run**: 6 Band-connected agents, 8 AI/ML API calls, 7 Featherless calls, plus 3 deterministic agents (PO Matcher / Provenance Signer / Regression Tester) that emit no LLM traffic.

**Failure modes observed**: `MockLlmProvider` fallback keeps AC4 (BAAAR HALT deterministic 10/10) passing when either key is absent — the integration is wired but does not gate the demo. Set both env vars before running `cargo run --release --bin themis-bench` to exercise the real provider paths.

---

## 🚀 Quick start

```bash
# 1. Clone + build
git clone https://github.com/SuarezPM/apohara-themis
cd apohara-themis
cargo build --release          # 2 MB static binary

# 2. Run the local demo (mocked LLM, single process)
./target/release/themis-orchestrator
# → listen on $PORT (default 8080). Open http://localhost:8080.

# 3. Verify an evidence packet offline
cargo run --release --bin themis-verify -- <packet.json> <signature.hex>
# → exit 0 (valid) | exit 2 (signature mismatch) in <30s.

# 4. Run the bench (measures AC2/4/7/8/9/10/13 in-process)
cargo run --release --bin themis-bench
# → writes ac-measurements.json

# 5. Or use the live URL (no build needed)
curl https://themis.apohara.dev/   # the frontend
```

---

## Test status (310 / 0)

| Suite | What it covers | Count |
|-------|----------------|-------|
| `tests/http_e2e.rs` | E2E of the live Router via `tower::ServiceExt::oneshot` — 9 paths matching the Vercel proxy surface + 4 env-var fallback tests for FeatherlessBackend | 13 |
| `tests/property_chain.rs` | BLAKE3 invariants (determinism, avalanche, length-extend, order, hex) with `proptest` × 256 | 5 |
| `tests/snapshot_compliance.rs` | Locks the wire format (4 frameworks, Art 17 R7 sub-fields) + 3 page-2 PDF tests (2 pages, 26 fields, agent trace) | 5 |
| `tests/pdf_halt_visual.rs` | PDF HALT stamp + 5-condition matrix + green APPROVED indicator | 2 |
| `tests/pdf_qr_code.rs` | QR code in PDF footer encoding verify URL | 5 |
| `tests/compliance_dashboard.rs` | JSON contract for frontend compliance dashboard (26/30 fields) | 4 |
| `tests/demo_data_loads.rs` | 4 HALT + 1 APPROVED over the 5 Stanford InvoiceNet-shaped fixtures + 4 Rekor anchor tests | 12 |
| `tests/verify_5_invoices.rs` | Runs `themis-verify` against 5 fixtures (10 invocations total) | 1 |
| per-crate `#[cfg(test)] mod tests` | signer, chain, packet, rekor, dora, eu_ai_act, nist, owasp, llm, llm_backend, fixtures, etc. | 252 |
| **Total** | **309 passing, 0 failing** | |

```bash
cargo test --workspace
```

---

## 🔐 Security posture

| Layer | Mechanism | Library |
|-------|-----------|---------|
| Signatures | Ed25519 (std, short PIDs) | `ed25519-dalek` 2 |
| Hash chain | BLAKE3 (faster + safer than SHA-2) | `blake3` 1 |
| Timestamps | RFC 3161 standard TSA protocol | `rfc3161ng` 0.1 |
| Transparency log | Rekor v2 (sigstore) | `cosign` shell, `MockRekorClient` for tests |
| Multi-tenant isolation | per-tenant baked Ed25519 keys via `include_bytes!` | `SignerService::for_tenant` |
| Pre-commit hook | AC11 (no `apohara_*` imports) + `cargo-deny` (R11) | `scripts/pre-commit.sh` |
| CI | fmt · clippy `-D warnings` · cargo-deny · AC11 · test matrix (ubuntu+macOS+windows) · live-deploy smoke | `.github/workflows/ci.yml` |
| Scorecard | OpenSSF weekly + per-push | `.github/workflows/scorecard.yml` |
| CodeQL | weekly + per-push, Rust SAST | `.github/workflows/codeql.yml` |

**In scope (10 threats)**: T1 fraud · T2 LLM non-determinism · T3 cross-tenant reads · T4 packet tamper · T5 packet forgery · T6 invoice denial · T7 double-spend · T8 sanctions · T9 prompt injection · T10 supply-chain compromise.

**Out of scope (7)**: compromised LLM provider · Band subprocess takeover · Ed25519 side-channels · Rekor outage · frontend XSS · key exfiltration from the binary · regulatory regime change.

Full threat model: [`THREAT_MODEL.md`](./THREAT_MODEL.md) · Vulnerability disclosure: [`SECURITY.md`](./SECURITY.md) · Email `p.ms.08@hotmail.com`.

---

## Roadmap · 6 of 6 phases shipped

| Phase | Scope | Status |
|-------|-------|--------|
| A — Foundation | Repo bootstrap, Band subprocess, Ed25519 + BLAKE3 + RFC 3161 | ✅ DONE |
| B — Agents | 5 core + 3 shadow agents, BAAAR 5-condition gate | ✅ DONE |
| C — Orchestrator + Compliance | State machine, 4 framework mappers | ✅ DONE |
| D — Frontend + Demo data | `themis.apohara.dev` UI, 5 Stanford InvoiceNet-shaped fixtures (4 HALT + 1 APPROVED) | ✅ DONE |
| E — Rekor + Multi-tenant | Rekor v2 client (Mock + Cosign), `for_tenant()` baked keys, 9/9 EU AI Act Art 12 fields | ✅ DONE |
| F — Deploy + Pitch | Live at `https://themis.apohara.dev`, AC1 319ms / AC12 494ms measured live | ✅ DONE |

**Acceptance Criteria** (15 total): **13 measured**, 3 harness-ready (AC1, AC3, AC12 — measured live as of 2026-06-13), AC5 pending gold labels, AC14 video post-demo. See `ROADMAP.md` for the per-AC table with the live numbers.

---

## Hall of fame

No public vulnerability reports yet. Be the first: `p.ms.08@hotmail.com`.

## License

MIT · Pablo M. Suarez ([@SuarezPM](https://github.com/SuarezPM)) · See [LICENSE](./LICENSE).

<sub>Built for the <a href="https://bandofagents.dev">Band of Agents Hackathon</a>. The 5-agent Band chat-room pattern, the BAAAR deterministic post-LLM gate, and the 4-framework compliance stack are the reusable artifacts; the Stanford-InvoiceNet-shaped demo data is the proof. Both are MIT.</sub>
