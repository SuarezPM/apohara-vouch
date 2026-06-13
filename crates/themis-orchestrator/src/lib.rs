//! themis-orchestrator — the seam between Band and the agents.
//!
//! Owns the per-invoice state machine, the LlmBackend router, the
//! BAAAR kill-switch, the Evidence Packet assembly, and the
//! multi-tenant registry. Calls agents in sequence, accumulates
//! their `AgentDecision`s, and seals the packet on completion.
//!
//! Module map (after this PRD):
//!
//! * **`state.rs`** — `InvoiceState`, `StateMachine`, `Transition`
//! * **`tenants.rs`** — `Tenant`, `TenantRegistry`, `RoomId`
//! * **`router.rs`** — `LlmBackendRouter`
//! * **`kill_switch.rs`** — `BaaarGate`, re-export `Outcome` / `BaaarReason`
//! * **`packet.rs`** — `EvidencePacket`, `FrameworkMappings`, `SignedPacket`
//! * **`room.rs`** — `BandRoom` trait, `MockBandRoom`
//! * **`orchestrator.rs`** — `Orchestrator` struct, `process_invoice`
//! * **`isolation.rs`** — cross-tenant isolation tests
//! * **`jcr_gate.rs`** (RALPH Foundation) — JCR Safety Gate
//! * **`prefix_salt.rs`** (RALPH Foundation) — Prefix Salt Planner
//! * **`concurrency.rs`** (RALPH Foundation) — Concurrency Scheduler
//! * **`test_support.rs`** — shared LLM-mediated StubAgent + fixture
//!   types for the demo_data_loads integration test and the
//!   themis-bench binary

#![warn(missing_docs)]

/// Crate version + name.
pub fn version() -> &'static str {
    "themis-orchestrator"
}

pub mod concurrency;
pub mod events;
pub mod http;
pub mod isolation;
pub mod jcr_gate;
pub mod kill_switch;
pub mod orchestrator;
pub mod packet;
pub mod pdf;
pub mod prefix_salt;
pub mod room;
pub mod router;
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
