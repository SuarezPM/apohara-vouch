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
pub mod events;
pub mod featherless_openclaw;
pub mod fixtures;
pub mod http;
pub mod llm_backend;
pub mod orchestrator;
pub mod packet;
pub mod pdf;
pub mod rekor_backend;
pub mod room;
pub mod state;
pub mod tenants;

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
