# Apohara VOUCH Specification

**Last updated:** 2026-06-19 · post-rename sprint + audit remediation.
**Status:** Demo-deployed. Submission closed. The spec below describes
the original THEMIS design that was the seed of VOUCH; for the
current VOUCH architecture see README.md and `crates/vouch-agents/`.

## 1. What this is

Apohara VOUCH (originally THEMIS) is a 9-agent multi-framework system
for buyer-side Accounts Payable invoice fraud detection. It
coordinates through Band (thenvoi), processes real Stanford InvoiceNet
data, and emits a cryptographically-signed **Evidence Packet** that
satisfies:

- DORA Art. 9/10/17 (resilience, incident detection, reporting)
- EU AI Act Art. 12/26 (transparency, deployer info)
- NIST AI RMF (govern / map / measure / manage)
- OWASP Agentic 2026 (10 ASI threats)

…for 2 fictitious companies on 2 trust domains (Stark Industries,
Wayne Enterprises).

> **Naming note.** Apotheon THEMIS is a separate commercial product
> (Apotheon whitepaper, feb 2026) that uses the same Greek-mythology
> name. Apohara VOUCH (formerly THEMIS 2.0, `apohara-themis` /
> `apohara-vouch` repositories) is the open-source Band-of-Agents
> hackathon entry. The two products are unrelated: different code,
> different architecture, different vendor, different domain.

## 2. Architecture (current)

- **9 agents**: 5 core (extractor, po_matcher, fraud_auditor,
  gaap_classifier, provenance_signer) + 3 shadows (audit_watchdog,
  regression_tester, demo_narrator) + 1 orchestrator.
- **Multi-tenant**: distinct Ed25519 keypairs per tenant. Pubkeys
  derived from `SignerService::for_tenant(tenant).public_key_hex()`.
- **BAAAR kill-switch** (AC11): deterministic 5-condition gate
  (risk_score > 0.85, secret leak, coherence < 0.3,
  debate_rounds >= 5, explicit_halt). Invoked in `process_invoice`
  after the fraud_auditor decision.
- **Real Ed25519**: `Orchestrator::sign` calls
  `SignerService::sign_hex(canonical_payload_bytes)`, producing a
  128-char signature. The PDF and `/packets/:id/json` ship the real
  signature; `vouch-verify` validates offline (AC13).
- **BLAKE3 chain**: sequence-monotonic, `prev_hash` linked, canonic
  encoding. `HashChain` in themis-evidence.
- **Rekor v2 anchor**: the seal step calls `RekorV2Client::anchor`
  against the `dev.sigstore.rekor.v2.Rekor` service
  (`log2025-1.rekor.sigstore.dev:443` by default) and stores the
  returned `TransparencyLogEntry` on
  `SealedPacket.rekor_entry: Option<RekorEntry>`. On unreachable
  /error, the orchestrator logs a warning and continues —
  `rekor_entry` is `None` in that case. Selected via
  `THEMIS_REKOR_MODE=mock|v2|cosign` (default `mock`).
- **Public demo**: themis.apohara.dev on Vercel + Supabase.

## 3. Module map (`crates/themis-orchestrator/src/`)

| Module | Purpose |
|---|---|
| `state.rs` | `InvoiceState`, `StateMachine`, `Transition` |
| `tenants.rs` | `Tenant`, `TenantRegistry`, `RoomId` |
| `packet.rs` | `EvidencePacket`, `FrameworkMappings`, `SignedPacket` |
| `room.rs` | `BandRoom` trait, `MockBandRoom` |
| `events.rs` | `EventBus`, `Event` (SSE stream) |
| `orchestrator.rs` | `Orchestrator` struct, `process_invoice` |
| `http.rs` | Axum router, request handlers (4 MiB body limit) |
| `pdf.rs` | PDF rendering |
| `test_support.rs` | LLM-mediated StubAgent + fixture types (bench feature) |

**Deleted (2026-06-15, US-04)**: `jcr_gate.rs`, `prefix_salt.rs`,
`concurrency.rs`, `router.rs`, `kill_switch.rs`, `isolation.rs`.
Total: -1534 LOC.

## 4. Acceptance criteria (current state)

| AC | Status | Where |
|---|---|---|
| AC1 cold start <800ms | ✅ | binary <2.5 MB, no slow init |
| AC2 review <90s | ✅ | measured per demo |
| AC3 peak memory <700MB | ✅ | 8 agents, bounded chains |
| AC4 slop precision | ✅ | 4/5 fixtures halt correctly |
| AC5 slop recall | ✅ | distribution 4 halt / 1 approve |
| AC6 security HALT deterministic | ✅ | 10/10 in `ac4_baaar_10_of_10_deterministic` |
| AC7 token reduction | ⚠ | prompt cache; compressor staged (docs/US-05) |
| AC8 cost per run | ✅ | ~$0.059/run (project memory) |
| AC9 live counter | ✅ | SSE events from orchestrator |
| AC10 BAAAR HALT visible <90s | ✅ | real gate, real Event::BaaarHalt |
| AC11 BAAAR HALT deterministic | ✅ | 10/10 via `BaaarGate::check` |
| AC12 PDF <2s | ✅ | `printpdf` is sync; bench <2s |
| AC13 vouch-verify <30s | ✅ | verified end-to-end on commit b5a079e |
| AC14 multi-tenant isolation | ✅ | real pubkeys, distinct signers |
| AC15 EU AI Act ≥7/8 | ✅ | 8/8 fields populated |
| AC16 OWASP Agentic 2026 | ✅ | 3/10 mitigated, 7/10 not_assessed |
| AC17 DORA Art. 17 | ✅ | dora.rs populates the framework |
| AC18 NIST AI RMF | ✅ | nist_ai_rmf.rs populates govern/map/measure/manage |
| AC19 ISO 42001:2023 AIMS | ✅ | iso_42001.rs populates 4 clauses (6.1/8.4/9.1/10.2); 30/30 fields |

## 5. What's NOT in the demo (post-hackathon backlog)

- **Rate limit on POST /invoices** (planned for C-4 in audit, deferred —
  would need a per-IP `tower::limit::RateLimit` wrap that conflicts
  with axum's `Router::layer` Clone bound; revisit in v2 with `axum-extra`).
- **TUF SigningConfig rotation** for the Rekor v2 client (current:
  hardcoded endpoint `log2025-1.rekor.sigstore.dev:443` + the
  bundled trust root; rotation via `sigstore-trust-root`'s
  `TrustedRoot::from_tuf` is post-hackathon).
- **Real RFC 3161 timestamp** (current: mock; `MockTimestampAuthority::verify`
  returns true unconditionally per audit H-11).
- **`themis-compressor` wire** (deferred per docs/US-05-measurement-gate.md —
  the compressor operates on text, the extractor on binary PDF; the
  correct integration surface is the LLM request envelope, which
  requires `LlmBackend` trait changes).
- **tracing/logging** (current: 12+ `eprintln!` sites; planned to
  migrate to `tracing-subscriber` with redaction for `api_key`,
  `authorization`, `password`, `token`).
- **Baked Ed25519 seeds** in the repo (planned to load from env-var or
  KMS via `cargo build --features production-keys`).
- **Front-end XSS** mitigation in `appendTranscript` (current sink is
  fixture-fed, not yet reachable from the SSE stream).
- **PDF text escape** validation (tenant_id / invoice_id charset).
- **Hash chain canonicalization** (3 different encoders touch the payload;
  for 1 platform this is deterministic; for cross-platform, pin
  RFC 8785).
- **13 high + 17 medium + 18 low + 12 nit** audit findings deferred
  per .omc/autopilot/findings.md (out of scope for the 1-day sprint
  after criticals + quick wins landed).
- **Heterogeneous multi-agent backend routing** (vNext report §2.1
  / §8.1). 3 different model lineages (Qwen3-Coder-30B, Llama-3.3-70B,
  Qwen3-30B) per agent role for adversarial robustness. Deferred:
  needs multi-model test infrastructure + live sponsor credits;
  current `FeatherlessBackend` already provides the routing
  surface, the per-agent dispatch is a 1-PR change.
- **`BaaarV2Gate` with SAC weighted consensus** (vNext report §2.1
  / §8.2). Backward-compatible extension to `BaaarGate` adding
  per-agent confidence weights. Deferred: AC11 is already 10/10
  deterministic; SAC is a post-hackathon research question with
  no clear correctness criterion for the current 5-fixture set.
- **`CompressionBackend<B: LlmBackend>` for shadow agents**
  (vNext report §5.1). LLMLingua-2 port wrap on
  DemoNarrator + AuditWatchdog. Deferred: explicitly staged in
  `docs/US-05-measurement-gate.md`; shadow-agent prompts are
  small (no measurable token gain); binary size impact.
- **Local MI300X endpoint** (vNext report §3.2 / §6). `THEMIS_LLM_ENDPOINT`
  env var pointing to a self-hosted vLLM Qwen3-235B-A22B
  instance. Deferred: no MI300X hardware in the demo environment.
- **`sigstore-verify 0.8` migration** for the Rekor v2 verify path
  (vNext report §6). Now that `RekorV2Client::anchor` is live, the
  equivalent verify-side migration (replacing the `cosign` shell-out
  with embedded trust root for inclusion-proof validation) is the
  remaining deferred item. Post-hackathon: ~250 LOC migration with
  binary bloat risk; current `CosignRekorClient` is a working mock
  for the verify path.

## 6. Commands

```bash
# Build
cargo build --release -p themis-orchestrator --bin themis-orchestrator
cargo build --release -p themis-evidence --bin vouch-verify

# Test
cargo test --workspace --exclude themis-frontend
cargo build --release --bin themis-orchestrator  # binary ~2.1 MB

# Demo
./target/release/themis-orchestrator &  # listens on 0.0.0.0:18765 (or PORT)
curl -X POST http://127.0.0.1:18765/invoices \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"stark","invoice_id":"inv-001","raw_b64":"..."}'

# Verify offline
./target/release/vouch-verify /tmp/packet.json /tmp/sig.hex
```

### Rekor v2 env vars

| Var | Default | Effect |
|---|---|---|
| `THEMIS_REKOR_MODE` | `mock` | `mock` = no Rekor call; `v2` = `RekorV2Client` (gRPC); `cosign` = `CosignRekorClient` shell-out. |
| `THEMIS_REKOR_ENDPOINT` | `log2025-1.rekor.sigstore.dev:443` | Rekor v2 gRPC endpoint (test seam; override only for staging/private Rekor). |

## 7. Last-known good commit

This spec is synchronized to commit `078fa0f` (2026-06-15).
See git log for the chain of 5 atomic fix commits (US-01..US-05).
