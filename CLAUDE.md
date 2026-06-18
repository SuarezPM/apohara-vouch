# Apohara Themis — Project memory

> Project-specific. Loads ON TOP of the global `~/.claude/CLAUDE.md`. Do NOT repeat
> global rules here. Updated 2026-06-12 (kickoff, repo bootstrap).

## 1. What this is

Apohara Themis is a 5-agent Rust system for buyer-side Accounts Payable invoice fraud
detection. Agents coordinate through Band, process real Stanford InvoiceNet data, and
emit a cryptographically-signed **Evidence Packet** that satisfies DORA Art. 9/10/17 +
EU AI Act Art. 12/26 + NIST AI RMF + OWASP Agentic 2026 simultaneously, for two
fictitious companies on two trust domains.

- **Hackathon:** Band of Agents Hackathon (12-19 jun 2026). Track 3 (Regulated & High-Stakes).
- **Sponsors:** Band (thenvoi) · AI/ML API (Claude Sonnet 4.5 via AIML API gateway) · Featherless AI (Qwen3-Coder-30B)
- **Demo:** `https://themis.apohara.dev` (Vercel + Supabase)
- **Repo:** `https://github.com/SuarezPM/apohara-themis`
- **License:** MIT · Author: Pablo M. Suarez (@SuarezPM)

## 2. Stack (Rust full)

- Runtime: Rust 1.75+ stable, single Cargo workspace
- Async: Tokio + Axum 0.7 (HTTP + WebSocket)
- Band client: subprocess wrapper over official Band Python SDK 0.2.11 (`band-sdk[langgraph]`)
- LLM: `rig-core` 0.38 (Anthropic-compatible + OpenAI-compatible for Featherless)
- Crypto: `ed25519-dalek` 2 + `blake3` 1 + `rfc3161ng` 0.1
- Tests: `cargo test` (built-in)
- Deploy: Vercel (frontend) + Supabase (Postgres, audit log) + apohara.dev (DNS)

## 3. Workspace layout (`crates/`)

- `themis-band-client/` — subprocess wrapper around the Band Python SDK
- `themis-orchestrator/` — room lifecycle, 5-agent state machine, BAAAR HALT
- `themis-agents/` — 5 agent implementations: Extractor, PO Matcher, Fraud Auditor, GAAP Classifier, Provenance Signer
- `themis-evidence/` — Ed25519 + BLAKE3 + RFC 3161 + Rekor v2
- `themis-compliance/` — DORA / EU AI Act / NIST AI RMF / OWASP Agentic mappers
- `themis-frontend/` — HTML + vanilla JS, streams via `EventSource`

AGON (Rust Band SDK extraction) is an **internal sub-crate**, not a standalone crates.io publication.

## 4. Defenses & evidence (claims are FP-measured)

- **BAAAR kill-switch** fires on `risk_score > 0.85` (default; TBD by day 3) or
  `security_severity == CRITICAL` or `coherence_score < 0.3` or
  `debate_rounds >= 5` or `explicit_halt_requested`. On fire: HALT event posted to Band.
- **Evidence Packet:** Ed25519-signed JSON + PDF. 8 EU AI Act Art. 12 fields
  (start_time, end_time, reference_database, input_data, natural_person_id,
  decision_id, policy_version, hash_chain_prev). AC15: ≥7/8 populated.
- **BLAKE3 hash chain:** sequence-monotonic, re-ordering buffer per SCEPTRE v2 design.
- **Multi-tenant:** 2 fictitious companies, 2 trust domains, separate Ed25519 keypairs
  per tenant (baked at compile time via `include_bytes!` to survive Vercel's ephemeral FS).
- **themis-verify** binary replaces `openssl dgst -sha512` for AC7 (openssl doesn't support Ed25519).

## 5. Commands (run inside `apohara-themis/`)

```bash
cargo build --release          # 22 MB single static binary
cargo test                     # unit + integration
cargo clippy --all-targets     # lint
cargo check --workspace        # fast type check
cargo run --bin themis-verify  # offline verification of any evidence packet
```

## 6. Multi-provider & secrets (chmod 600 outside repo)

- Claude Sonnet 4.5 (via AI/ML API gateway, $10 hackathon credits, first 500)
- Qwen3-Coder-30B: Featherless ($25/participant, code BOA26, valid 1 month)
- Band Pro promo: `BANDHACK26` (1 month free, requires card)
- All secrets: `~/.config/apohara/secrets.env` (chmod 600, outside repo)

## 7. Memory & infra

- 3-layer memory: engram is the only active layer. qdrant retired 2026-06-04. cognee deferred.
- `.claude/rules/` auto-loads: see `coding-style`, `security`, `git-workflow`,
  `performance`, `testing`, `karpathy-guidelines`, `visual-verdict`.
- `.archive/pre-themis/` — pre-hackathon development snapshot (gitignored, local only).

## 8. The Brain ↔ Themis contract

Two repos, two roles.

**`apohara-themis/` (this repo) — code & decisions**
- Source code, Cargo manifests, tests, deploy
- Locked spec lives here (in `.archive/pre-themis/.omc/specs/` and this repo's `docs/` once published)

**`apohara-hackathon-brain/` (sibling repo) — research & iteration**
- Spec iterations (POLYPHON → ARBITER+NEXUS → CIPHER+CRISP → ΣYNTHEX → SCEPTRE
  → MOIRAI v1/v2/v3 → ΣYNTHEX-2 → THEMIS)
- Deep research reports (EXA, Bright Data, competitor maps)
- Stack analysis, the Devil's Advocate reports
- The 8 marketing/pitch drafts

**When to go to the brain:** new LLM provider question, competitor analysis, pitch review.
**When to stay in Themis:** writing code, running tests, deploying, updating the spec.

The brain is research output, not source of truth. The spec is the source of truth.
