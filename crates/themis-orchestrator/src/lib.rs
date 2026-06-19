//! themis-orchestrator — the seam between Band and the agents.
//!
//! Owns the per-invoice state machine, the BAAAR kill-switch
//! (re-exported from themis-agents::baaar), the Evidence Packet
//! assembly, and the multi-tenant registry. Calls agents in
//! sequence, accumulates their `AgentDecision`s, and seals the
//! packet on completion.
//!
//! Module map:
//!
//! * **`state.rs`** — `InvoiceState`, `StateMachine`, `Transition`
//! * **`tenants.rs`** — `Tenant`, `TenantRegistry`, `RoomId`
//! * **`packet.rs`** — `EvidencePacket`, `FrameworkMappings`, `SignedPacket`
//! * **`room.rs`** — `BandRoom` trait, `MockBandRoom`
//! * **`events.rs`** — `EventBus`, `Event` (SSE stream)
//! * **`orchestrator.rs`** — `Orchestrator` struct, `process_invoice`
//! * **`http.rs`** — Axum router, request handlers
//! * **`pdf.rs`** — PDF rendering
//! * **`test_support.rs`** — shared LLM-mediated StubAgent + fixture
//!   types for the demo_data_loads integration test and the
//!   themis-bench binary
//!
//! **Deleted (RALPH-foundation scaffold, no production callers):**
//! `jcr_gate.rs`, `prefix_salt.rs`, `concurrency.rs`, `router.rs`,
//! `kill_switch.rs`, `isolation.rs` (test-only, moved to tests/).

#![warn(missing_docs)]

/// Crate version + name.
pub fn version() -> &'static str {
    "themis-orchestrator"
}

pub mod art50;
/// BAAAR determinism proptest harness (Story C-09 / G29 / AC9).
///
/// The original spec called for a Z3-proved determinism proof ported
/// from `apohara-contextforge`'s `z3_inv15_proof.py`. That code lives
/// in Python; a direct Rust port is deferred to a follow-up. The MVP
/// in this module is a pure-function extraction of the 5 BAAAR halt
/// conditions plus a 1210-case proptest asserting same-input → same
/// output. See `tests/baaar_z3_1210.rs` for the harness.
pub mod baaar_z3;
/// Band live room integration (Story Ola-A): the HTTP handlers
/// for `GET /band-live` (SSE), `GET /metrics/band` (JSON), and
/// `POST /band/start-room` (spawns the 6-agent WebSocket fleet).
pub mod band_live;
/// Circuit breaker + exponential backoff for the agent call loop
/// (Story C-05 / G21 / AC5 — ASI08 Cascading Failures defense).
/// 3-state breaker (`Closed` / `Open` / `HalfOpen`), threshold=5
/// failures, 30s timeout, exponential backoff 100/200/400/800/1600ms.
pub mod circuit_breaker;
/// INV-15 verification seam at the LLM call boundary
/// (Story C-03 / G14 / G19 / AC3). Pairs with
/// `themis-compliance::inv15` — this module is the wiring, not
/// the verifier. See `context.rs` for the integration plan and
/// the note about the `LlmBackend::send` follow-up.
pub mod context;
/// Dual-LLM split — privileged + quarantined contexts (Story C-07 /
/// G14 / AC7, ASI01 3rd defense). Pattern from Microsoft Zero Trust
/// SFI 2026. See `dual_llm.rs` for the full surface and the MVP
/// scope (trait + mock; production wiring lands in a follow-up).
pub mod dual_llm;
pub mod events;
pub mod featherless_openclaw;
pub mod fixtures;
pub mod http;
/// Alert-fatigue detector — Story C-06 / G22 / AC6 (ASI09
/// Human-Agent Trust Exploitation defense). Suspends HITL when
/// the human approves more than 5 BAAAR HALT overrides in 60s;
/// requires explicit re-auth before further approvals.
pub mod human_guard;
/// Tenant keyring — Story C-13 / G16, G28 / AC13.
///
/// BIP32-*style* (HMAC-SHA512, first 32 bytes) Ed25519 keyring
/// derived from a master seed. Per-tenant keys are derived on
/// demand and cached. The A2A handler (Story C-12) consumes
/// this for cross-framework peer integration.
pub mod keyring;
pub mod llm_backend;
pub mod mcp_proxy;
pub mod orchestrator;
pub mod packet;
pub mod pdf;
pub mod rekor_backend;
/// Exponential backoff retry helper (Story C-05 / G21 / AC5).
/// Pairs with `circuit_breaker` for defense-in-depth on the agent
/// call loop.
pub mod retry;
/// Rogue-agent monitor — Story C-06 / G23 / AC6 (ASI10 Rogue
/// Agents defense). Quarantines any agent that sends >10
/// messages without `@mention`-ing another agent.
pub mod rogue_monitor;
pub mod room;
/// Per-agent LLM backend routing (Story Ola-C). Maps each
/// agent name to its provider: `fraud_auditor` → Featherless
/// (Qwen3-Coder-30B-A3B-Instruct); the other 5 LLM-driven
/// agents → AIML API. See `routing.rs` for the full table.
pub mod routing;
/// TOML override layer on top of `routing.rs`. See
/// `routing_config.rs` for the schema.
pub mod routing_config;
/// AgentGuard subprocess sandbox (Story C-02). Owns the
/// `apohara-agentguard` firewall integration — do NOT modify
/// outside the C-02 story scope.
pub mod sandbox;
pub mod state;
/// AgentGuard subprocess wiring (Story C-02). Owns the
/// `apohara-agentguard` subprocess lifecycle — do NOT modify
/// outside the C-02 story scope.
pub mod subprocess;
pub mod tenants;

/// A2A 1.0 (Google Agent2Agent) JSON-RPC 2.0 endpoint. Story
/// C-01 / G24-G26. See `a2a_handler.rs` for the full surface.
pub mod a2a_handler;

// `test_support` is shared between the integration test
// (tests/demo_data_loads.rs) and the bench binary. Cargo's
// `cfg(test)` only covers the lib's `#[cfg(test)] mod tests`, not
// integration tests in `tests/`, so we use a feature flag
// (`--features bench`) that the bench binary and CI both set.
// Integration tests pass `--features bench` to `cargo test`.
// `#[allow(dead_code)]` on the module silences the warning when
// only the bench (or only the test) is being built.
#[allow(dead_code)]
#[cfg(any(test, feature = "bench"))]
pub mod test_support;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-orchestrator");
    }
}
