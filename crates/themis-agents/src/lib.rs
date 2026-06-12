//! themis-agents — 5 core + 3 shadow agents for THEMIS.
//!
//! Core: Extractor, PO Matcher, Fraud Auditor, GAAP Classifier,
//! Provenance Signer. Shadow: Audit Watchdog, Regression Tester,
//! Demo Narrator. Each agent implements the `Agent` trait and is
//! backed by the `LlmBackend` trait (Anthropic, OpenAI-compat, Z.ai,
//! Google) — same trait, different providers per the multi-sponsor
//! routing (see `.archive/pre-themis/.omc/plans/ralplan-themis-hackathon.md`).
//!
//! ## Architecture
//!
//! * **`traits.rs`** — `Agent` trait (process + name) and `AgentContext`.
//! * **`llm.rs`** — `LlmBackend` trait + `LlmRequest`/`LlmResponse` +
//!   `MockLlmProvider` for tests + 4 routing-target stub impls.
//! * **`decision.rs`** — `AgentDecision` + `DecisionType` + `AgentError`.
//! * **5 agent files** — `extractor.rs`, `po_matcher.rs`,
//!   `fraud_auditor.rs`, `gaap_classifier.rs`, `provenance_signer.rs`.
//! * **3 shadow files** — `audit_watchdog.rs`, `regression_tester.rs`,
//!   `demo_narrator.rs`.
//! * **`baaar.rs`** — the kill-switch (Fraud Auditor hosts it but the
//!   logic is in its own module so it can be tested in isolation).

#![warn(missing_docs)]

/// Crate version + name.
pub fn version() -> &'static str {
    "themis-agents"
}

pub mod traits;
pub mod llm;
pub mod decision;
pub mod baaar;
pub mod extractor;
pub mod po_matcher;
pub mod fraud_auditor;
pub mod gaap_classifier;
pub mod provenance_signer;
pub mod audit_watchdog;
pub mod regression_tester;
pub mod demo_narrator;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-agents");
    }
}
