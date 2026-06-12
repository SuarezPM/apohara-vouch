//! themis-agents — 5 core + 3 shadow agents for THEMIS.
//!
//! Core: Extractor, PO Matcher, Fraud Auditor, GAAP Classifier,
//! Provenance Signer. Shadow: Audit Watchdog, Regression Tester,
//! Demo Narrator. Each agent implements the `Agent` trait and is
//! backed by the orchestrator's LLM router.
//!
//! Real agent impls arrive in the follow-up sprint (Phase B of the
//! plan). This crate exists to anchor the workspace layout for US-001.

#![warn(missing_docs)]

/// Crate version + name. Used by US-001 acceptance test.
pub fn version() -> &'static str {
    "themis-agents"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-agents");
    }
}
