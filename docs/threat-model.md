# THEMIS — Threat Model

> **Scope:** the THEMIS demo (`themis.apohara.dev`) and the 2-tenant
> Ed25519-isolated multi-agent system that produces cryptographic
> Evidence Packets.
> **Format:** STRIDE-lite. 5 threats scoped to what a Track 3
> (Regulated & High-Stakes) judge reads in 5 minutes.
> **Status:** Living doc. Last updated 2026-06-17 (vNext apply).

## Scope

THEMIS is a buyer-side AP invoice fraud detection system. It runs 5
core agents (extractor, PO matcher, fraud auditor, GAAP classifier,
provenance signer) plus 3 shadow agents (audit watchdog, regression
tester, demo narrator) per invoice. Each run produces an Evidence
Packet signed with the tenant's Ed25519 key, anchored in a BLAKE3
hash chain, with an RFC 3161 timestamp and a Rekor transparency log
entry. The orchestrator is a single Rust binary (2.1 MB) deployed to
fly.io; the frontend is static HTML + JS on Vercel.

**What this document covers:** the 5 threats most likely to surface
in a regulatory or audit review of the demo. Each threat names the
asset at risk, the attack surface, the existing mitigation, the
residual risk, and the regulatory reference.

**What this document does NOT cover:** post-hackathon enterprise
deployment (KMS-issued keys, real Rekor v2, real RFC 3161 TSA,
multi-region replication). Those are listed in
`docs/SPEC.md §5 What's NOT in the demo`.

## Assets

| Asset | Storage | Sensitivity |
|---|---|---|
| Tenant Ed25519 keypairs | baked at compile time, embedded in binary | CRITICAL — proof of multi-tenant isolation |
| BLAKE3 hash chain | in-memory + serialized into each Evidence Packet | HIGH — proof of decision ordering |
| Per-agent Ed25519 signature | serialized into each `ChainEntry` | HIGH — non-repudiation per agent |
| BAAAR decision log | in-memory, sealed into Evidence Packet | HIGH — the regulator's primary audit artifact |
| Rekor transparency log entry | planned (post-hackathon: real via sigstore-verify 0.8) | MEDIUM — tamper evidence for the packet |
| RFC 3161 timestamp | planned (post-hackathon: real TSA) | MEDIUM — temporal anchoring of the decision |
| Evidence Packet JSON | `/packets/:id/json` endpoint | MEDIUM — public-readable, integrity-checked |
| Evidence Packet PDF | `/packets/:id/pdf` endpoint | MEDIUM — public-readable, includes QR to verifier |

## Threats

### T1 — Spoofing: forged BAAAR decision log entry

- **Attack surface:** an attacker (compromised CI, malicious
  orchestrator instance, or rogue Band agent) forges a `ChainEntry`
  claiming a `BaaarOutcome::Approve` for an invoice that should have
  been HALT.
- **Mitigation (existing):** every `ChainEntry` is signed by the
  emitting agent's Ed25519 key and BLAKE3-linked to the previous
  entry's hash. `HashChain::verify()` rejects any entry whose
  signature is invalid or whose `prev_hash` does not match. The
  BAAAR gate is deterministic (5 conditions, AC11 10/10) — a
  forged approval would not match the verified decision.
- **Residual risk:** the per-agent signing key must be the agent's
  actual key, not a substituted one. If the orchestrator's agent
  registry is misconfigured, signatures verify against the wrong
  identity. Mitigation in production: KMS-issued keys per agent
  (post-hackathon).
- **Reference:** DORA Art. 9 (ICT risk management), EU AI Act Art. 12
  (record-keeping integrity), NIST AI RMF MANAGE.

### T2 — Tampering: hash chain re-ordering

- **Attack surface:** an attacker with write access to the in-memory
  chain re-orders entries to make a previously-rejected invoice
  appear approved, or to hide a HALT event.
- **Mitigation (existing):** `prev_hash` linking makes re-ordering
  detectable — every entry's hash is a function of its
  predecessor's hash, so swapping two entries invalidates all
  subsequent `prev_hash` verifications. `HashChain::sequence` is
  sequence-monotonic; the orchestrator rejects out-of-order
  appends.
- **Residual risk:** re-ordering is detectable AFTER the fact, not
  in real-time. The 500ms re-ordering buffer (SCEPTRE v2 design)
  smooths async event arrival but does not prevent it. Mitigation
  in production: append-only WORM storage (post-hackathon) for the
  chain backend.
- **Reference:** DORA Art. 10 (incident detection), EU AI Act Art. 12
  (record integrity), ISO 42001 Clause 9.1 (monitoring).

### T3 — Repudiation: agent denies emitting a decision

- **Attack surface:** after a HALT fires and triggers an incident
  report, the fraud auditor (or another agent) denies being the
  source of the decision that triggered the HALT.
- **Mitigation (existing):** every `AgentDecision` carries a
  per-agent Ed25519 signature. `HashChain::verify()` validates
  each signature against the agent's public key (the key is
  derived from the tenant's `SignerService`). The signed payload
  includes the decision type, reasoning, confidence, and
  timestamp — enough to attribute the decision to the agent.
- **Residual risk:** the per-agent public key is held by the
  orchestrator. If the orchestrator's `TenantRegistry` is
  compromised, an attacker's key can be substituted. Mitigation in
  production: public keys distributed out-of-band (per-tenant KMS
  endpoint), with a manifest signed at build time.
- **Reference:** EU AI Act Art. 12 (auditability), NIST AI RMF
  MANAGE, ISO 42001 Clause 9.1 (monitoring).

### T4 — Information disclosure: tenant key extraction from binary

- **Attack surface:** an attacker downloads the
  `themis-orchestrator` binary (public on fly.io) and extracts
  the baked Ed25519 keypair from the `.data` section.
- **Mitigation (existing):** the demo is intentionally non-secret
  — the baked keys are for the 2 fictitious companies (Stark,
  Wayne) and are clearly marked as demo-only. The binary is
  single-tenant-aware but the demo only ships 2 tenant
  configurations. Extraction would let the attacker forge
  Evidence Packets for the demo tenants, but no production
  decision is gated on a demo packet.
- **Residual risk:** if the same binary is repurposed for a real
  tenant (without re-keying), the production tenant's key is
  extractable by anyone with the binary. Mitigation in
  production: keys loaded from env-var or KMS at boot via
  `cargo build --features production-keys`; the demo binary
  is clearly distinguished.
- **Reference:** DORA Art. 9 (third-party risk), EU AI Act Art. 26
  (deployer obligations), ISO 42001 Clause 6.1 (risk assessment).

### T5 — Denial of service: 429 storm from a malicious tenant

- **Attack surface:** a tenant (or attacker spoofing a tenant)
  submits thousands of invoices per second to the
  `POST /invoices` endpoint, exhausting the orchestrator's
  concurrency budget and degrading the demo for other tenants.
- **Mitigation (existing):** `RequestBodyLimitLayer` (4 MiB)
  caps the request body size. `ConcurrencyScheduler` (after the
  2026-06-15 repair) acquires per-request cost permits via an
  RAII guard. The Band SDK subprocess has its own internal
  timeouts.
- **Residual risk:** no per-tenant rate limit. A single tenant
  can saturate the global concurrency budget. Mitigation in
  production: per-IP `tower::limit::RateLimit` wrap
  (post-hackathon, deferred per `docs/SPEC.md §5` because it
  conflicts with axum's `Router::layer` Clone bound).
- **Reference:** DORA Art. 9 (ICT resilience), NIST AI RMF
  MANAGE.

## Residual risks (consolidated)

These are the open items a regulator or auditor would flag as
"documented but not yet mitigated". They are not blockers for the
hackathon demo (the demo's threat surface is bounded by the 2
fictitious tenants), but a production deployment must address all
5:

1. **Baked keys, not KMS-issued.** T4. A production deployment
   must load keys from a KMS at boot.
2. **Mock Rekor, not real transparency log.** T2. The current
   `CosignRekorClient::verify` is a no-op (audit H-10). Post-hackathon
   migration to `sigstore-verify 0.8` with `TrustedRoot::from_embedded`
   is planned (per the vNext roadmap).
3. **Mock RFC 3161, not real TSA.** T2. `MockTimestampAuthority::verify`
   returns true unconditionally (audit H-11). Post-hackathon: real
   TSA integration.
4. **No per-tenant rate limit.** T5. Post-hackathon: per-IP
   rate limit via `axum-extra`.
5. **No WORM chain storage.** T2. In-memory chain is lost on
   orchestrator restart. Post-hackathon: append-only WORM backend.

## References (regulatory + standards)

- **DORA** — EU Regulation 2022/2554, Digital Operational Resilience
  Act, Articles 9 (ICT risk management), 10 (incident detection),
  17 (incident reporting).
- **EU AI Act** — EU Regulation 2024/1689, Articles 12 (record-keeping
  for high-risk AI), 26 (deployer obligations). Mandatory for
  high-risk AI systems from **2 August 2026** (47 days from this
  document).
- **NIST AI RMF 1.0** — Govern / Map / Measure / Manage functions.
  THEMIS coverage: all 4 functions populated in the Evidence Packet
  (NIST AI RMF column in the compliance dashboard).
- **OWASP Agentic 2026** — 10 ASI threats (ASI01–ASI10). THEMIS
  coverage: 3/10 mitigated, 7/10 not_assessed (per `docs/SPEC.md §4
  AC16`).
- **ISO/IEC 42001:2023** — AI Management System (AIMS) standard.
  Clauses 6.1 (risk assessment), 8.4 (impact assessment), 9.1
  (monitoring), 10.2 (continual improvement). The 6th framework
  added to THEMIS in vNext apply (2026-06-17).

## Review cadence

This document is reviewed:
- On every commit that touches `crates/themis-orchestrator/src/`,
  `crates/themis-evidence/src/`, or `crates/themis-compliance/src/`.
- On every release tag (`v*`).
- Quarterly, if there's bandwidth.

The next scheduled review: post-hackathon (2026-06-20+), when the
residual risks are prioritized against the vNext roadmap.
