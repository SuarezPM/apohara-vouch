//! themis-orchestrator — Band room state machine for THEMIS.
//!
//! Owns the 5-agent state machine (Extractor → PO Matcher → Fraud Auditor
//! → GAAP Classifier → Provenance Signer), the BAAAR kill-switch, the
//! JCR Safety Gate (arXiv:2601.08343, INV-15), the Prefix Salt Planner
//! (SHA-256 namespace `apohara.apc.v1`), and the Concurrency Scheduler
//! (tokio Semaphore, 10ms stagger, pre-warm ping).
//!
//! This crate is the seam between Band (chat-room coordination) and the
//! per-agent `themis-agents` crate. The orchestrator never executes a
//! sub-task directly; it routes `@mention` traffic and applies the gates.

#![warn(missing_docs)]

/// Crate version + name. Used by US-001 acceptance test.
pub fn version() -> &'static str {
    "themis-orchestrator"
}

pub mod concurrency;
pub mod jcr_gate;
pub mod prefix_salt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-orchestrator");
    }
}
