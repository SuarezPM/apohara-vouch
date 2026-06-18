//! LLM backend selection for the production binary.
//!
//! Honors both sponsors' kickoff claims:
//!
//! - **AIML API** (Valerie, 12 jun 2026): "One API for 500+ models",
//!   "different agents want different brains", "switch models is
//!   changing just one string".
//! - **Featherless** (Isaac, 12 jun 2026): "30,000+ open source models",
//!   "agent infrastructure platform".
//!
//! The single-string switch is `THEMIS_LLM_PROVIDER`:
//! - unset (default): try AIML API first, then Featherless, then mock
//! - "aimlapi": force AIML API (Anthropic Sonnet 4.5)
//! - "featherless": force Featherless (Qwen3-Coder-30B-A3B)
//! - "mock": force the mock (test mode / no LLM cost)
//!
//! The model id is overridable per-provider via `THEMIS_LLM_MODEL`
//! (the "change one string" claim — switch model without changing
//! any code).
//!
//! Graceful degradation: missing or invalid env vars fall back
//! to the next provider in the chain. The binary never panics
//! on startup because of a missing LLM key.

use themis_agents::llm::{AIMLAPIBackend, FeatherlessBackend};

/// Default model for the AIML API provider (Anthropic Sonnet 4.5
/// via the AIML API gateway — the export-control workaround + the
/// "different agents want different brains" claim).
pub const AIML_API_MODEL: &str = "anthropic/claude-sonnet-4.5";

/// Default model for the Featherless provider (Qwen3-Coder-30B
/// — open source, code analysis workhorse).
pub const FEATHERLESS_MODEL: &str = "Qwen/Qwen3-Coder-30B-A3B-Instruct";

/// Default AIML API base URL. Overridable via `AIMLAPI_BASE_URL`
/// env var (e.g. for tests pointing at a local WireMock server).
pub const AIMLAPI_DEFAULT_BASE_URL: &str = "https://api.aimlapi.com";

/// Which LLM provider the binary should use. The env-var value
/// is the single string that switches providers (no code change).
pub fn select_provider() -> &'static str {
    match std::env::var("THEMIS_LLM_PROVIDER")
        .ok()
        .map(|s| s.trim().to_lowercase())
        .as_deref()
    {
        Some("aimlapi") | Some("ai-ml") | Some("aiml") => "aimlapi",
        Some("featherless") => "featherless",
        Some("mock") => "mock",
        _ => "auto",
    }
}

/// Resolve the model id for the active provider. Reads
/// `THEMIS_LLM_MODEL` (override) or falls back to the
/// provider's default. The override is leaked to &'static str
/// (called once at startup, bounded by process lifetime).
pub fn resolve_model(provider: &str) -> &'static str {
    if let Ok(m) = std::env::var("THEMIS_LLM_MODEL") {
        let m = m.trim();
        if !m.is_empty() {
            return Box::leak(m.to_string().into_boxed_str());
        }
    }
    match provider {
        "aimlapi" => AIML_API_MODEL,
        "featherless" => FEATHERLESS_MODEL,
        _ => "mock-demo",
    }
}

#[cfg(test)]
mod us04_tests {
    use super::*;
    use themis_agents::baaar::AgentRole;

    /// US-04: each agent role resolves to its expected
    /// model_id per the multi-model dispatch table.
    #[test]
    fn model_id_for_agent_routes_per_agent() {
        assert_eq!(
            model_id_for_agent(AgentRole::Extractor),
            "Qwen/Qwen3-Coder-30B-A3B-Instruct"
        );
        assert_eq!(
            model_id_for_agent(AgentRole::PoMatcher),
            "Qwen/Qwen3-Coder-30B-A3B-Instruct"
        );
        assert_eq!(
            model_id_for_agent(AgentRole::FraudAuditor),
            "anthropic/claude-sonnet-4.5"
        );
        assert_eq!(
            model_id_for_agent(AgentRole::GaapClassifier),
            "meta-llama/Llama-3.3-70B-Instruct"
        );
        // Signer + shadow agents are deterministic.
        assert_eq!(
            model_id_for_agent(AgentRole::ProvenanceSigner),
            "deterministic-signer"
        );
        assert_eq!(
            model_id_for_agent(AgentRole::AuditWatchdog),
            "deterministic-signer"
        );
        assert_eq!(
            model_id_for_agent(AgentRole::RegressionTester),
            "deterministic-signer"
        );
        assert_eq!(
            model_id_for_agent(AgentRole::DemoNarrator),
            "deterministic-signer"
        );
    }
}

/// Pick the LLM model_id for a specific agent role. US-04:
/// the orchestrator emits `Event::ProviderActive` per agent
/// with the agent-specific model_id, so the frontend renders
/// a distinct badge per agent ("FraudAuditor on
/// claude-sonnet-4.5", "GAAP on Llama-3.3-70B", etc.).
///
/// Routing:
///   - Extractor       → Featherless Qwen3-Coder-30B (structured JSON)
///   - PoMatcher       → Featherless Qwen3-Coder-30B (deterministic lookup)
///   - FraudAuditor    → AIML API Claude Sonnet 4.5 (reasoning + risk)
///   - GaapClassifier  → AIML API Llama-3.3-70B (statistical lineage)
///   - ProvenanceSigner + shadow agents → "deterministic-signer"
///
/// The string is used purely for the SSE badge. The agent's
/// own `process()` call site decides whether to actually
/// call the LLM (and falls back to mock internally when
/// the corresponding env key is unset).
pub fn model_id_for_agent(role: themis_agents::baaar::AgentRole) -> &'static str {
    use themis_agents::baaar::AgentRole::*;
    match role {
        Extractor => "Qwen/Qwen3-Coder-30B-A3B-Instruct",
        PoMatcher => "Qwen/Qwen3-Coder-30B-A3B-Instruct",
        FraudAuditor => "anthropic/claude-sonnet-4.5",
        GaapClassifier => "meta-llama/Llama-3.3-70B-Instruct",
        ProvenanceSigner | AuditWatchdog | RegressionTester | DemoNarrator => {
            "deterministic-signer"
        }
    }
}

/// Pick the LLM backend for this run. The result is the model_id
/// that `AppState.model_id` advertises to the SSE stream (the
/// frontend's provider badge reads from there).
///
/// Resolution order (when `THEMIS_LLM_PROVIDER` is unset):
/// 1. `AIML_API_KEY` set → AIML API
/// 2. `FEATHERLESS_API_KEY` set → Featherless
/// 3. neither → MockLlmProvider
pub fn select_backend() -> &'static str {
    select_backend_with(None)
}

/// Like [`select_backend`] but with an explicit AIML API base URL
/// override. When `aimlapi_base_url` is `None`, the function reads
/// the `AIMLAPI_BASE_URL` env var (with `https://api.aimlapi.com`
/// as the implicit default). The URL is honored only on the
/// AIML-API code path; Featherless + mock ignore it. This is the
/// test seam: the integration test in
/// `tests/aiml_wiremock_e2e.rs` passes a WireMock URI here.
pub fn select_backend_with(aimlapi_base_url: Option<String>) -> &'static str {
    let provider = select_provider();
    // Resolve the AIML base URL: explicit arg wins, then env var,
    // then the production default. Trimmed; empty → default.
    let aiml_url: Option<String> = aimlapi_base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            std::env::var("AIMLAPI_BASE_URL")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });

    // Explicit overrides.
    match provider {
        "mock" => {
            tracing::info!("[themis-orchestrator] LLM: MockLlmProvider (THEMIS_LLM_PROVIDER=mock)");
            return "mock-demo";
        }
        "aimlapi" => {
            let model = resolve_model("aimlapi");
            if AIMLAPIBackend::from_env_with_url(model, aiml_url.clone()).is_some() {
                tracing::info!("[themis-orchestrator] LLM: AIMLAPIBackend({model}) — live (THEMIS_LLM_PROVIDER=aimlapi)");
                return model;
            }
            tracing::info!("[themis-orchestrator] LLM: AIML API requested but AIML_API_KEY not set; falling back to mock");
            return "mock-demo";
        }
        "featherless" => {
            let model = resolve_model("featherless");
            if FeatherlessBackend::from_env(model).is_some() {
                tracing::info!("[themis-orchestrator] LLM: FeatherlessBackend({model}) — live (THEMIS_LLM_PROVIDER=featherless)");
                return model;
            }
            tracing::info!("[themis-orchestrator] LLM: Featherless requested but FEATHERLESS_API_KEY not set; falling back to mock");
            return "mock-demo";
        }
        _ => {}
    }

    // Auto: try AIML API first, then Featherless, then mock.
    let aiml_model = resolve_model("aimlapi");
    if AIMLAPIBackend::from_env_with_url(aiml_model, aiml_url).is_some() {
        tracing::info!(
            "[themis-orchestrator] LLM: AIMLAPIBackend({aiml_model}) — live (auto-selected)"
        );
        return aiml_model;
    }
    let featherless_model = resolve_model("featherless");
    if FeatherlessBackend::from_env(featherless_model).is_some() {
        tracing::info!("[themis-orchestrator] LLM: FeatherlessBackend({featherless_model}) — live (auto-selected, AIML API not set)");
        return featherless_model;
    }
    tracing::info!("[themis-orchestrator] LLM: MockLlmProvider — neither AIML_API_KEY nor FEATHERLESS_API_KEY is set");
    "mock-demo"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Global mutex serializes tests that mutate env vars.
    // std::env is process-global; cargo test runs in parallel,
    // so env mutations race. The mutex forces tests to be
    // sequential. Cost: ~1ms per test (negligible).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// `THEMIS_LLM_PROVIDER=mock` → mock, regardless of keys.
    #[test]
    fn select_backend_mock_when_provider_explicit() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("THEMIS_LLM_PROVIDER", "mock");
            std::env::remove_var("AIML_API_KEY");
            std::env::remove_var("FEATHERLESS_API_KEY");
        }
        assert_eq!(select_backend(), "mock-demo");
    }

    /// `THEMIS_LLM_PROVIDER=aimlapi` + `AIML_API_KEY=sk-test` →
    /// AIML API.
    #[test]
    fn select_backend_aimlapi_when_provider_explicit_and_key_set() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("THEMIS_LLM_PROVIDER", "aimlapi");
            std::env::set_var("AIML_API_KEY", "sk-test-dummy-key");
            std::env::remove_var("FEATHERLESS_API_KEY");
        }
        let model_id = select_backend();
        assert_eq!(
            model_id, AIML_API_MODEL,
            "expected AIML API when provider=aimlapi + key set, got {model_id}"
        );
    }

    /// `THEMIS_LLM_PROVIDER=featherless` + `FEATHERLESS_API_KEY=k` →
    /// Featherless.
    #[test]
    fn select_backend_featherless_when_provider_explicit_and_key_set() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("THEMIS_LLM_PROVIDER", "featherless");
            std::env::remove_var("AIML_API_KEY");
            std::env::set_var("FEATHERLESS_API_KEY", "sk-test-dummy");
        }
        let model_id = select_backend();
        assert_eq!(
            model_id, FEATHERLESS_MODEL,
            "expected Featherless when provider=featherless + key set, got {model_id}"
        );
    }

    /// Auto: prefer AIML API over Featherless when both keys are set.
    #[test]
    fn select_backend_auto_prefers_aimlapi_over_featherless() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("THEMIS_LLM_PROVIDER");
            std::env::set_var("AIML_API_KEY", "sk-test-aiml");
            std::env::set_var("FEATHERLESS_API_KEY", "sk-test-feather");
        }
        let model_id = select_backend();
        assert_eq!(
            model_id, AIML_API_MODEL,
            "AIML API should be preferred when both keys are set, got {model_id}"
        );
    }

    /// `THEMIS_LLM_MODEL=foo` overrides the default model.
    #[test]
    fn select_backend_respects_model_override() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("THEMIS_LLM_PROVIDER", "featherless");
            std::env::set_var("THEMIS_LLM_MODEL", "meta-llama/Llama-3.3-70B-Instruct");
            std::env::remove_var("AIML_API_KEY");
            std::env::set_var("FEATHERLESS_API_KEY", "k");
        }
        let model_id = select_backend();
        assert_eq!(model_id, "meta-llama/Llama-3.3-70B-Instruct");
    }

    /// No keys at all → MockLlmProvider (graceful degradation).
    #[test]
    fn select_backend_falls_back_to_mock_when_no_keys() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("THEMIS_LLM_PROVIDER");
            std::env::remove_var("AIML_API_KEY");
            std::env::remove_var("FEATHERLESS_API_KEY");
        }
        let model_id = select_backend();
        assert_eq!(
            model_id, "mock-demo",
            "expected mock fallback when no keys set, got {model_id}"
        );
    }
}
