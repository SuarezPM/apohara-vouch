# Threat Model — THEMIS

This document specifies what THEMIS protects against and what it does
**not** protect against. It is the source of truth for the security
claims in the demo and the ROADMAP risk register.

## In scope (we defend against)

| ID  | Threat                                                         | Mitigation                                         |
|-----|----------------------------------------------------------------|---------------------------------------------------|
| T1  | Vendor (invoice submitter) submits a fraudulent invoice        | BAAAR 5-condition gate (deterministic, post-LLM)  |
| T2  | LLM agent produces a non-deterministic verdict that changes   | `seed: 42` + temperature=0 in every LLM call       |
|     | between two runs of the same input                               | (audit chain)                                     |
| T3  | Tenant A reads or modifies Tenant B's data                     | Ed25519 keys baked per-tenant, separate Band rooms |
| T4  | Adversary tampers with an Evidence Packet after sealing        | BLAKE3 hash chain + Ed25519 signature              |
| T5  | Adversary forges an Evidence Packet                            | Ed25519 signature over BLAKE3(packet)              |
| T6  | Adversary denies having submitted a particular invoice         | RFC 3161 timestamp + Rekor v2 transparency log     |
| T7  | Vendor submits the same invoice twice (double-spend)            | BAAAR `duplicate` finding → Halt                   |
| T8  | Vendor appears on a sanctions list (OFAC)                      | BAAAR `secret_leak` finding → Halt + Art 17 incident report |
| T9  | An LLM prompt-injection attack changes the verdict             | Compressor + JCR Safety Gate (per ContextForge)    |
| T10 | Supply-chain attack via malicious crate                        | `cargo-deny` advisories + pinned deps + `cargo install --locked` |

## Out of scope (we explicitly do NOT defend against)

| ID   | Threat                                                                 |
|------|-------------------------------------------------------------------------|
| O1   | A compromised LLM provider (e.g., Anthropic, Featherless) colludes     |
|      | with a vendor. The BAAAR gate runs AFTER the LLM verdict; a malicious |
|      | LLM could emit a low-risk score for a known-fraudulent invoice.       |
|      | Defense: in production, run with multi-provider quorum (2 of 3 LLMs    |
|      | must agree on the verdict). Out of scope for the hackathon.            |
| O2   | An attacker who controls Band's `band-sdk[langgraph]` subprocess can   |
|      | inject arbitrary messages into the transcript. Defense: subprocess     |
|      | runs with seccomp/landlock (not in hackathon scope; see agentguard).   |
| O3   | Side-channel attacks on Ed25519 (e.g., timing). Defense: use           |
|      | constant-time crypto (ed25519-dalek is constant-time).                 |
| O4   | Loss of Rekor v2 (sigstore going down). Defense: the BLAKE3 hash is   |
|      | the source of truth; a verifier does not need Rekor.                   |
| O5   | A frontend XSS injecting malicious POSTs to /invoices. Defense:      |
|      | CSP headers on the Vercel frontend (X-Content-Type-Options: nosniff).|
| O6   | The auditor stealing the Ed25519 private key from the binary.          |
|      | Defense: keys are baked via `include_bytes!` (public in the binary);   |
|      | for real deployments, use HSM-backed signing.                          |
| O7   | Regulatory regime change. Defense: the 4 framework mappers are         |
|      | versioned; a new regulation is a new mapper (not a breaking change).   |

## Trust assumptions

- **The user trusts THEMIS to honestly emit Evidence Packets for
  invoices it receives.** This is the central trust: the user
  trusts THEMIS's stack (Rust runtime, ed25519-dalek, blake3,
  rfc3161ng, MockRekorClient or cosign). The threat model assumes
  these libraries are correctly implemented and the Rust toolchain
  is not compromised.
- **The user trusts the Vercel frontend proxy + fly.io backend
  to faithfully route the /invoices and /packets/:id/pdf
  requests.** A breach of either would let an attacker serve
  forged packets; defense is HTTPS + Vercel's auth + Fly's
  per-app access tokens.
- **The user does NOT trust the LLM provider.** The BAAAR gate
  is the last line of defense; even a fully compromised LLM
  cannot lower the BAAAR thresholds (those are hard-coded in
  `themis_agents::baaar::RISK_SCORE_HALT = 0.85` etc.).

## Residual risks

- The harness orchestrator uses a `MockRekorClient` for the demo.
  In production, swap in `CosignRekorClient` and verify the
  bundle URL resolves to a real sigstore entry.
- The `MockLlmProvider` returns canned responses. In production,
  swap in `AnthropicBackend` (AI/ML API) and verify
  non-determinism is acceptable per the audit chain.
- The live deploy runs on a single Fly.io shared-cpu-1x machine
  in the `cdg` region. A region outage takes the demo down.
  Defense: fly volumes + cross-region (future work).

## Mapping to the ROADMAP risk register

The risks in `ROADMAP.md` §Riesgos activos (R1, R3, R4, R5, R8, R9)
are the operational counterparts of T1–T10 above. T1↔R5, T3↔R4, T10↔R8.
