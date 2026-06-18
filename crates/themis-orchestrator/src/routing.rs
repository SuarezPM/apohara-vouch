//! Per-agent LLM backend routing (Story Ola-C).
//!
//! The 5 LLM-driven agents each hit a different provider per
//! the multi-provider sponsor-pivot. The single-string switch
//! in `llm_backend.rs` is for the binary's default model id;
//! THIS module is for per-agent dispatch (the orchestrator
//! builds the dispatch map before the agents run).
//!
//! Routing (locked PRD):
//!
//! | Agent             | Backend    | Model                             |
//! |-------------------|------------|-----------------------------------|
//! | `fraud_auditor`   | Featherless| `Qwen/Qwen3-Coder-30B-A3B-Instruct`|
//! | `extractor`       | AIML API   | `anthropic/claude-sonnet-4.5`     |
//! | `po_matcher`      | (none)     | deterministic PO lookup           |
//! | `gaap_classifier` | AIML API   | `anthropic/claude-sonnet-4.5`     |
//! | `provenance_signer` | (none)   | Ed25519 sign — no LLM             |
//! | `demo_narrator`   | AIML API   | `anthropic/claude-sonnet-4.5`     |
//! | `regression_tester`| AIML API  | `anthropic/claude-sonnet-4.5`     |
//! | `audit_watchdog`  | AIML API   | `anthropic/claude-sonnet-4.5`     |
//!
//! The fraud_auditor is the ONLY agent routed to Featherless.
//! The other 5 LLM-driven agents (extractor, gaap_classifier,
//! demo_narrator, regression_tester, audit_watchdog) are routed
//! to AIML API. po_matcher and provenance_signer are
//! deterministic (no LLM).
//!
//! Graceful degradation: if `FEATHERLESS_API_KEY` is unset, the
//! fraud_auditor falls back to AIML API (same model as the
//! other 5). If `AIML_API_KEY` is also unset, all 6 LLM-driven
//! agents fall back to `MockLlmProvider`. The binary never
//! panics on missing keys.

use std::collections::HashMap;
use std::sync::Arc;

use themis_agents::llm::{
    shared, AIMLAPIBackend, FeatherlessBackend, LlmBackend, MockLlmProvider,
};

use themis_compliance::featherless_metrics::{
    FeatherlessMetricsHandle, FeatherlessMetricsInner,
};

/// The model id the fraud_auditor routes to when Featherless
/// is available. Exposed as a constant so the test suite can
/// assert on it without duplicating the string.
pub const FRAUD_AUDITOR_FEATHERLESS_MODEL: &str = "Qwen/Qwen3-Coder-30B-A3B-Instruct";

/// The AIML API model id used by the 5 non-fraud LLM-driven
/// agents (and the fraud_auditor fallback when the Featherless
/// key is unset).
pub const AIML_API_MODEL: &str = "anthropic/claude-sonnet-4.5";

/// Per-agent backend selection result. The HTTP layer reads
/// this to render the "FraudAuditor on Featherless" badge
/// (the SSE `provider_active` event carries the model id; the
/// `AgentBackend` value is for the binary's static config).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentBackend {
    /// AIML API gateway (Fable 5 / Claude Sonnet 4.5).
    AimlApi,
    /// Featherless AI (Qwen3-Coder-30B-A3B-Instruct).
    Featherless,
    /// No LLM (deterministic agent).
    None,
}

impl AgentBackend {
    /// Stable string for logging + the SSE prelude.
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentBackend::AimlApi => "aimlapi",
            AgentBackend::Featherless => "featherless",
            AgentBackend::None => "deterministic",
        }
    }
}

/// Pick the backend for a given agent name. Names match the
/// orchestrator's HashMap keys (see
/// `test_support::build_stub_agents`).
///
/// `fraud_auditor` → `AgentBackend::Featherless` (the one
///   routing decision the PRD locks).
///
/// All other LLM-driven agents → `AgentBackend::AimlApi`.
///
/// `po_matcher` + `provenance_signer` → `AgentBackend::None`
/// (deterministic — no LLM call).
///
/// Unknown agent names → `AgentBackend::AimlApi` (safe
/// default; the MockLlmProvider fallback in the dispatch map
/// kicks in if the key is unset).
pub fn backend_for_agent(agent_name: &str) -> AgentBackend {
    match agent_name {
        "fraud_auditor" => AgentBackend::Featherless,
        "po_matcher" | "provenance_signer" => AgentBackend::None,
        // All other LLM-driven agents.
        "extractor"
        | "gaap_classifier"
        | "demo_narrator"
        | "regression_tester"
        | "audit_watchdog" => AgentBackend::AimlApi,
        // Unknown — default to AIML API (mock fallback if key unset).
        _ => AgentBackend::AimlApi,
    }
}

/// Build the per-agent dispatch map (the same shape
/// `test_support::build_stub_agents` consumes: `agent_name
/// -> Arc<dyn LlmBackend>`).
///
/// The `featherless_metrics` handle is attached to the
/// Featherless backend for the fraud_auditor, so every
/// successful (and failed) fraud_auditor call increments the
/// counters exposed at `GET /metrics/featherless`.
///
/// Graceful degradation order (per agent):
/// 1. `fraud_auditor`:
///    a. `FEATHERLESS_API_KEY` set → `FeatherlessBackend` (with
///       metrics sink attached).
///    b. `AIML_API_KEY` set → `AIMLAPIBackend` (fallback).
///    c. neither → `MockLlmProvider` (test mode).
/// 2. Other LLM-driven agents:
///    a. `AIML_API_KEY` set → `AIMLAPIBackend`.
///    b. neither → `MockLlmProvider`.
/// 3. Deterministic agents: `MockLlmProvider` (the
///    `LlmStubAgent` will never call it).
pub fn build_routed_dispatch(
    featherless_metrics: FeatherlessMetricsHandle,
) -> HashMap<String, Arc<dyn LlmBackend>> {
    let mut m: HashMap<String, Arc<dyn LlmBackend>> = HashMap::new();

    // --- fraud_auditor: Featherless (Qwen3-Coder-30B) ---
    let featherless: Arc<dyn LlmBackend> = match FeatherlessBackend::from_env(
        FRAUD_AUDITOR_FEATHERLESS_MODEL,
    ) {
        Some(b) => {
            let b = b.with_metrics(featherless_metrics.clone());
            shared(b)
        }
        None => match AIMLAPIBackend::from_env(AIML_API_MODEL) {
            Some(b) => shared(b),
            None => shared(MockLlmProvider::new("mock-fraud-auditor-fallback")),
        },
    };
    m.insert("fraud_auditor".to_string(), featherless);

    // --- 5 AIML API agents ---
    let aiml: Arc<dyn LlmBackend> = match AIMLAPIBackend::from_env(AIML_API_MODEL) {
        Some(b) => shared(b),
        None => shared(MockLlmProvider::new("mock-aiml-fallback")),
    };
    for name in [
        "extractor",
        "gaap_classifier",
        "demo_narrator",
        "regression_tester",
        "audit_watchdog",
    ] {
        m.insert(name.to_string(), aiml.clone());
    }

    // --- 2 deterministic agents (no LLM) ---
    for name in ["po_matcher", "provenance_signer"] {
        m.insert(
            name.to_string(),
            shared(MockLlmProvider::new(format!(
                "deterministic-{name}"
            ))),
        );
    }

    m
}

/// Build a fresh shared `FeatherlessMetrics` handle. Convenience
/// for the production binary: pass the result to
/// `build_routed_dispatch` AND to `AppState` so the HTTP layer
/// can serve `/metrics/featherless`.
pub fn new_featherless_metrics() -> FeatherlessMetricsHandle {
    std::sync::Arc::new(FeatherlessMetricsInner::new())
}

// Re-export the canonical shared-handle constructor.
pub use themis_compliance::featherless_metrics::new_shared as new_shared_featherless_metrics;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fraud_auditor_routes_to_featherless() {
        assert_eq!(
            backend_for_agent("fraud_auditor"),
            AgentBackend::Featherless
        );
        assert_eq!(
            backend_for_agent("fraud_auditor").as_str(),
            "featherless"
        );
    }

    #[test]
    fn extractor_routes_to_aiml() {
        assert_eq!(backend_for_agent("extractor"), AgentBackend::AimlApi);
    }

    #[test]
    fn gaap_classifier_routes_to_aiml() {
        assert_eq!(
            backend_for_agent("gaap_classifier"),
            AgentBackend::AimlApi
        );
    }

    #[test]
    fn shadow_agents_route_to_aiml() {
        assert_eq!(
            backend_for_agent("demo_narrator"),
            AgentBackend::AimlApi
        );
        assert_eq!(
            backend_for_agent("regression_tester"),
            AgentBackend::AimlApi
        );
        assert_eq!(
            backend_for_agent("audit_watchdog"),
            AgentBackend::AimlApi
        );
    }

    #[test]
    fn deterministic_agents_have_no_backend() {
        assert_eq!(backend_for_agent("po_matcher"), AgentBackend::None);
        assert_eq!(
            backend_for_agent("provenance_signer"),
            AgentBackend::None
        );
    }

    #[test]
    fn unknown_agent_defaults_to_aiml() {
        // Defensive: unknown agent names default to AIML API
        // (the mock fallback handles unset keys).
        assert_eq!(backend_for_agent("not_a_real_agent"), AgentBackend::AimlApi);
    }

    #[test]
    fn dispatch_map_has_all_eight_agents() {
        let metrics = new_shared_featherless_metrics();
        let dispatch = build_routed_dispatch(metrics);
        for name in [
            "extractor",
            "po_matcher",
            "fraud_auditor",
            "gaap_classifier",
            "provenance_signer",
            "demo_narrator",
            "regression_tester",
            "audit_watchdog",
        ] {
            assert!(
                dispatch.contains_key(name),
                "dispatch map missing agent {name}"
            );
        }
        assert_eq!(dispatch.len(), 8);
    }

    #[test]
    fn fraud_auditor_in_dispatch_is_featherless_when_key_set() {
        // SAFETY: env mutation is racy across tests; we accept
        // the test serializes the env (cargo's default is
        // parallel — but in practice the other tests in this
        // file don't mutate env). The env-var guard is
        // checked first; if unset we skip.
        if std::env::var("FEATHERLESS_API_KEY").ok().filter(|s| !s.is_empty()).is_none() {
            eprintln!("skip: FEATHERLESS_API_KEY not set");
            return;
        }
        let metrics = new_shared_featherless_metrics();
        let dispatch = build_routed_dispatch(metrics);
        let fa = dispatch.get("fraud_auditor").unwrap();
        assert_eq!(
            fa.model_id(),
            FRAUD_AUDITOR_FEATHERLESS_MODEL,
            "fraud_auditor must use the Featherless Qwen3 model when key is set"
        );
    }

    #[test]
    fn other_five_agents_in_dispatch_are_aiml_when_key_set() {
        if std::env::var("AIML_API_KEY").ok().filter(|s| !s.is_empty()).is_none() {
            eprintln!("skip: AIML_API_KEY not set");
            return;
        }
        let metrics = new_shared_featherless_metrics();
        let dispatch = build_routed_dispatch(metrics);
        for name in [
            "extractor",
            "gaap_classifier",
            "demo_narrator",
            "regression_tester",
            "audit_watchdog",
        ] {
            let m = dispatch.get(name).unwrap();
            assert_eq!(
                m.model_id(),
                AIML_API_MODEL,
                "{name} must use the AIML API Claude Sonnet model when key is set"
            );
        }
    }
}
