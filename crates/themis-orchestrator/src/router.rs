//! LlmBackendRouter — maps each agent name to the right LLM backend.
//!
//! Routing table per the plan (PRD section "8. LLM backbone"):
//!
//! | agent             | model_id                | sponsor            |
//! |-------------------|-------------------------|--------------------|
//! | extractor         | gemini-3.1-flash-lite   | AI/ML API          |
//! | po_matcher        | qwen3-coder-30b         | Featherless flat   |
//! | fraud_auditor     | claude-sonnet-4.6       | AI/ML API          |
//! | gaap_classifier   | glm-5.1                 | Featherless flat   |
//! | provenance_signer | claude-haiku-4.5        | AI/ML API          |
//! | audit_watchdog    | qwen3-coder-30b         | Featherless flat   |
//! | regression_tester | deepseek-v4-flash       | Featherless flat   |
//! | demo_narrator     | claude-haiku-4.5        | AI/ML API          |

use std::collections::HashMap;
use std::sync::Arc;

use themis_agents::llm::LlmBackend;

/// Map from agent name → model_id. Default routing per the plan.
pub fn default_agent_to_model() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("extractor", "gemini-3.1-flash-lite");
    m.insert("po_matcher", "qwen3-coder-30b");
    m.insert("fraud_auditor", "claude-sonnet-4.6");
    m.insert("gaap_classifier", "glm-5.1");
    m.insert("provenance_signer", "claude-haiku-4.5");
    m.insert("audit_watchdog", "qwen3-coder-30b");
    m.insert("regression_tester", "deepseek-v4-flash");
    m.insert("demo_narrator", "claude-haiku-4.5");
    m
}

/// The router: a flat map of `model_id → Arc<dyn LlmBackend>` plus
/// the agent→model_id mapping. `for_agent("fraud_auditor")` returns
/// the backend the Fraud Auditor should call.
pub struct LlmBackendRouter {
    /// model_id → Arc<dyn LlmBackend>
    backends: HashMap<String, Arc<dyn LlmBackend>>,
    /// agent name → model_id (default routing per the plan)
    agent_to_model: HashMap<String, &'static str>,
}

impl LlmBackendRouter {
    /// New empty router.
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
            agent_to_model: HashMap::new(),
        }
    }

    /// Build the router with the default agent→model mapping plus
    /// the supplied backends (keyed by model_id). Backends that are
    /// referenced by the default routing but not present in the
    /// supplied map simply return `None` from `for_agent`.
    pub fn with_default_routing(backends: HashMap<String, Arc<dyn LlmBackend>>) -> Self {
        let mut router = Self::new();
        for (model_id, backend) in backends {
            router.backends.insert(model_id, backend);
        }
        for (agent, model_id) in default_agent_to_model() {
            router.agent_to_model.insert(agent.to_string(), model_id);
        }
        router
    }

    /// Register a backend for a model_id (custom routing override).
    pub fn register_backend(&mut self, model_id: impl Into<String>, backend: Arc<dyn LlmBackend>) {
        self.backends.insert(model_id.into(), backend);
    }

    /// Map an agent name to its default model_id.
    pub fn model_id_for(&self, agent: &str) -> Option<&'static str> {
        self.agent_to_model.get(agent).copied()
    }

    /// Look up the backend for an agent (by agent name).
    pub fn for_agent(&self, agent: &str) -> Option<Arc<dyn LlmBackend>> {
        let model_id = self.model_id_for(agent)?;
        self.backends.get(model_id).cloned()
    }

    /// Look up a backend by model_id directly.
    pub fn for_model(&self, model_id: &str) -> Option<Arc<dyn LlmBackend>> {
        self.backends.get(model_id).cloned()
    }

    /// All agents in the default routing table.
    pub fn agents(&self) -> Vec<&'static str> {
        let mut a: Vec<&'static str> = self.agent_to_model.keys().map(|s| {
            // Box::leak trick to get 'static from &String — fine for
            // a small bounded set, populated once.
            Box::leak(s.clone().into_boxed_str()) as &'static str
        }).collect();
        a.sort();
        a
    }
}

impl Default for LlmBackendRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use themis_agents::llm::MockLlmProvider;

    fn mock_backends() -> HashMap<String, Arc<dyn LlmBackend>> {
        let mut m: HashMap<String, Arc<dyn LlmBackend>> = HashMap::new();
        m.insert(
            "gemini-3.1-flash-lite".to_string(),
            Arc::new(MockLlmProvider::new("gemini-3.1-flash-lite")),
        );
        m.insert(
            "qwen3-coder-30b".to_string(),
            Arc::new(MockLlmProvider::new("qwen3-coder-30b")),
        );
        m.insert(
            "claude-sonnet-4.6".to_string(),
            Arc::new(MockLlmProvider::new("claude-sonnet-4.6")),
        );
        m.insert(
            "glm-5.1".to_string(),
            Arc::new(MockLlmProvider::new("glm-5.1")),
        );
        m.insert(
            "claude-haiku-4.5".to_string(),
            Arc::new(MockLlmProvider::new("claude-haiku-4.5")),
        );
        m.insert(
            "deepseek-v4-flash".to_string(),
            Arc::new(MockLlmProvider::new("deepseek-v4-flash")),
        );
        m
    }

    #[test]
    fn default_routing_has_eight_agents() {
        let router = LlmBackendRouter::with_default_routing(mock_backends());
        assert_eq!(router.agents().len(), 8);
    }

    #[test]
    fn all_eight_agents_route_to_a_backend() {
        let router = LlmBackendRouter::with_default_routing(mock_backends());
        for agent in [
            "extractor",
            "po_matcher",
            "fraud_auditor",
            "gaap_classifier",
            "provenance_signer",
            "audit_watchdog",
            "regression_tester",
            "demo_narrator",
        ] {
            assert!(router.for_agent(agent).is_some(), "{agent} has no backend");
        }
    }

    #[test]
    fn model_id_for_returns_expected_per_agent() {
        let router = LlmBackendRouter::with_default_routing(mock_backends());
        assert_eq!(router.model_id_for("extractor"), Some("gemini-3.1-flash-lite"));
        assert_eq!(router.model_id_for("fraud_auditor"), Some("claude-sonnet-4.6"));
        assert_eq!(router.model_id_for("gaap_classifier"), Some("glm-5.1"));
        assert_eq!(router.model_id_for("provenance_signer"), Some("claude-haiku-4.5"));
        assert_eq!(router.model_id_for("po_matcher"), Some("qwen3-coder-30b"));
        assert_eq!(router.model_id_for("audit_watchdog"), Some("qwen3-coder-30b"));
        assert_eq!(router.model_id_for("regression_tester"), Some("deepseek-v4-flash"));
        assert_eq!(router.model_id_for("demo_narrator"), Some("claude-haiku-4.5"));
    }

    #[test]
    fn unknown_agent_returns_none() {
        let router = LlmBackendRouter::with_default_routing(mock_backends());
        assert!(router.for_agent("nope").is_none());
        assert!(router.model_id_for("nope").is_none());
    }

    #[test]
    fn default_routing_model_ids_match_plan() {
        // Pin the 8 model_ids so a plan change is a deliberate edit.
        let router = LlmBackendRouter::with_default_routing(HashMap::new());
        assert_eq!(router.model_id_for("extractor"), Some("gemini-3.1-flash-lite"));
        assert_eq!(router.model_id_for("po_matcher"), Some("qwen3-coder-30b"));
        assert_eq!(router.model_id_for("fraud_auditor"), Some("claude-sonnet-4.6"));
        assert_eq!(router.model_id_for("gaap_classifier"), Some("glm-5.1"));
        assert_eq!(router.model_id_for("provenance_signer"), Some("claude-haiku-4.5"));
        assert_eq!(router.model_id_for("audit_watchdog"), Some("qwen3-coder-30b"));
        assert_eq!(router.model_id_for("regression_tester"), Some("deepseek-v4-flash"));
        assert_eq!(router.model_id_for("demo_narrator"), Some("claude-haiku-4.5"));
    }

    #[test]
    fn register_backend_overrides() {
        let mut router = LlmBackendRouter::new();
        let backend: Arc<dyn LlmBackend> = Arc::new(MockLlmProvider::new("custom"));
        router.register_backend("custom-model", backend);
        assert!(router.for_model("custom-model").is_some());
        assert!(router.for_model("missing").is_none());
    }

    #[test]
    fn for_model_returns_correct_backend() {
        let router = LlmBackendRouter::with_default_routing(mock_backends());
        let b = router.for_model("claude-sonnet-4.6").unwrap();
        assert_eq!(b.model_id(), "claude-sonnet-4.6");
    }
}
