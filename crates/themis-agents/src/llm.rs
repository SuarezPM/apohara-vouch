//! LlmBackend trait + request/response types + MockLlmProvider for
//! tests + 4 routing-target stub impls.
//!
//! The trait is abstract enough to wrap Anthropic, OpenAI-compat
//! (DeepSeek, Qwen3-Coder via Featherless), Z.ai (GLM-5.1), and
//! Google (Gemini 3.1 Flash-Lite). Each provider has a stub impl in
//! this module — real HTTP wiring is a follow-up sprint.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::decision::AgentError;

/// A request to an LLM. Backend-agnostic — the concrete provider's
/// transport adapter maps these fields to its own wire format.
#[derive(Debug, Clone, PartialEq)]
pub struct LlmRequest {
    /// System prompt (preamble). Cached by the provider when possible.
    pub system_prompt: String,
    /// User prompt (the actual question).
    pub user_prompt: String,
    /// Max tokens to generate.
    pub max_tokens: u32,
    /// Sampling temperature. 0.0 for deterministic (used by
    /// GAAP Classifier).
    pub temperature: f32,
    /// Optional seed for determinism.
    pub seed: Option<u64>,
}

/// A response from an LLM.
#[derive(Debug, Clone, PartialEq)]
pub struct LlmResponse {
    /// Generated text.
    pub text: String,
    /// Input tokens billed.
    pub input_tokens: u32,
    /// Output tokens billed.
    pub output_tokens: u32,
    /// Model identifier (for telemetry + Evidence Packet).
    pub model_id: String,
}

/// The trait every LLM provider implements. Backends are concrete
/// structs (`AnthropicBackend`, `OpenAiCompatBackend`, etc.) and live
/// behind `Arc<dyn LlmBackend>` in agent constructors.
#[async_trait]
pub trait LlmBackend: Send + Sync + 'static {
    /// Stable model identifier (e.g. "claude-sonnet-4.6",
    /// "glm-5.1"). Used by the orchestrator's router and by the
    /// Evidence Packet's cost breakdown.
    fn model_id(&self) -> &'static str;

    /// Send a request, get a response. Errors are `AgentError`
    /// variants so callers can pattern-match on rate-limit /
    /// malformed / unavailable.
    async fn complete(&self, req: LlmRequest) -> Result<LlmResponse, AgentError>;
}

/// Mock LLM provider for tests. Returns canned responses keyed by
/// substring of `user_prompt`, tracks call count, and can simulate
/// rate-limiting after N calls.
#[derive(Debug, Default)]
pub struct MockLlmProvider {
    /// Canned responses, keyed by substring of `user_prompt`.
    responses: Mutex<HashMap<String, LlmResponse>>,
    /// Default response when no substring matches.
    default: Mutex<Option<LlmResponse>>,
    /// Total `complete()` invocations.
    call_count: AtomicU32,
    /// After this many calls, every call returns `RateLimited`. 0
    /// means "never rate-limit".
    rate_limit_after: AtomicU32,
    /// Model ID for the canned response.
    model_id: String,
}

impl MockLlmProvider {
    /// New empty mock with a model id. No responses registered; calls
    /// return `LlmUnavailable` until you add responses. Rate-limiting
    /// is disabled by default (`u32::MAX`).
    pub fn new(model_id: impl Into<String>) -> Self {
        Self {
            responses: Mutex::new(HashMap::new()),
            default: Mutex::new(None),
            call_count: AtomicU32::new(0),
            rate_limit_after: AtomicU32::new(u32::MAX),
            model_id: model_id.into(),
        }
    }

    /// Register a canned response for requests whose `user_prompt`
    /// contains the given substring. The first substring that
    /// matches wins.
    pub fn with_response(
        self,
        prompt_substring: impl Into<String>,
        response: LlmResponse,
    ) -> Self {
        self.responses
            .lock()
            .expect("MockLlmProvider responses mutex poisoned")
            .insert(prompt_substring.into(), response);
        self
    }

    /// Set the default response (returned when no substring matches).
    pub fn with_default(self, response: LlmResponse) -> Self {
        *self
            .default
            .lock()
            .expect("MockLlmProvider default mutex poisoned") = Some(response);
        self
    }

    /// Set the model id.
    pub fn with_model_id(mut self, model_id: impl Into<String>) -> Self {
        self.model_id = model_id.into();
        self
    }

    /// After `n` successful calls, every subsequent call returns
    /// `RateLimited` (with 60s retry hint). 0 = rate-limit the very
    /// first call (useful to test error propagation).
    pub fn with_rate_limit_after(self, n: u32) -> Self {
        self.rate_limit_after.store(n, Ordering::SeqCst);
        self
    }

    /// Total `complete()` invocations so far.
    pub fn call_count(&self) -> u32 {
        self.call_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl LlmBackend for MockLlmProvider {
    fn model_id(&self) -> &'static str {
        // Leak the String to get a 'static &str — MockLlmProvider is
        // for tests, the leak is bounded by test count.
        Box::leak(self.model_id.clone().into_boxed_str())
    }

    async fn complete(&self, req: LlmRequest) -> Result<LlmResponse, AgentError> {
        let n = self.call_count.fetch_add(1, Ordering::SeqCst) + 1;
        let limit = self.rate_limit_after.load(Ordering::SeqCst);
        // limit == 0: rate-limit the very first call.
        // limit == N: first N calls pass, then rate-limit kicks in.
        if n > limit {
            return Err(AgentError::RateLimited {
                retry_after_ms: 60_000,
            });
        }

        // Find first matching substring.
        let responses = self
            .responses
            .lock()
            .expect("MockLlmProvider responses mutex poisoned");
        for (substr, resp) in responses.iter() {
            if req.user_prompt.contains(substr) || req.system_prompt.contains(substr) {
                return Ok(resp.clone());
            }
        }
        drop(responses);

        // No match — return default or error.
        let default = self
            .default
            .lock()
            .expect("MockLlmProvider default mutex poisoned")
            .clone();
        default.ok_or_else(|| {
            AgentError::LlmUnavailable(format!(
                "MockLlmProvider: no response registered for prompt starting with {:?}",
                &req.user_prompt[..req.user_prompt.len().min(40)]
            ))
        })
    }
}

// --- Routing-target stub backends ---
// Real HTTP wiring is a follow-up sprint. These exist so the
// orchestrator's LlmBackend trait abstraction has concrete
// implementable types for each of the 4 routing targets in the plan.

/// Stub for Claude Sonnet 4.6 / Haiku 4.5 (AI/ML API gateway).
#[derive(Debug, Clone)]
pub struct AnthropicBackend {
    model_id: &'static str,
}

impl AnthropicBackend {
    /// New Anthropic backend for the given model.
    pub fn new(model_id: &'static str) -> Self {
        Self { model_id }
    }
}

#[async_trait]
impl LlmBackend for AnthropicBackend {
    fn model_id(&self) -> &'static str {
        self.model_id
    }

    async fn complete(&self, _req: LlmRequest) -> Result<LlmResponse, AgentError> {
        Err(AgentError::LlmUnavailable(format!(
            "AnthropicBackend({}) HTTP wiring is a follow-up sprint",
            self.model_id
        )))
    }
}

/// Stub for OpenAI-compatible providers (Featherless): DeepSeek
/// V4-Flash, Qwen3-Coder-30B-A3B.
#[derive(Debug, Clone)]
pub struct OpenAiCompatBackend {
    model_id: &'static str,
}

impl OpenAiCompatBackend {
    /// New OpenAI-compat backend for the given model.
    pub fn new(model_id: &'static str) -> Self {
        Self { model_id }
    }
}

#[async_trait]
impl LlmBackend for OpenAiCompatBackend {
    fn model_id(&self) -> &'static str {
        self.model_id
    }

    async fn complete(&self, _req: LlmRequest) -> Result<LlmResponse, AgentError> {
        Err(AgentError::LlmUnavailable(format!(
            "OpenAiCompatBackend({}) HTTP wiring is a follow-up sprint",
            self.model_id
        )))
    }
}

/// Stub for Z.ai direct (GLM-5.1). Note: in production we use
/// Featherless flat-rate, not Z.ai direct (see plan §Known risks).
#[derive(Debug, Clone)]
pub struct ZaiBackend {
    model_id: &'static str,
}

impl ZaiBackend {
    /// New Z.ai backend for the given model.
    pub fn new(model_id: &'static str) -> Self {
        Self { model_id }
    }
}

#[async_trait]
impl LlmBackend for ZaiBackend {
    fn model_id(&self) -> &'static str {
        self.model_id
    }

    async fn complete(&self, _req: LlmRequest) -> Result<LlmResponse, AgentError> {
        Err(AgentError::LlmUnavailable(format!(
            "ZaiBackend({}) HTTP wiring is a follow-up sprint",
            self.model_id
        )))
    }
}

/// Stub for Google Gemini (3.1 Flash-Lite for vision in Extractor).
#[derive(Debug, Clone)]
pub struct GoogleBackend {
    model_id: &'static str,
}

impl GoogleBackend {
    /// New Google backend for the given model.
    pub fn new(model_id: &'static str) -> Self {
        Self { model_id }
    }
}

#[async_trait]
impl LlmBackend for GoogleBackend {
    fn model_id(&self) -> &'static str {
        self.model_id
    }

    async fn complete(&self, _req: LlmRequest) -> Result<LlmResponse, AgentError> {
        Err(AgentError::LlmUnavailable(format!(
            "GoogleBackend({}) HTTP wiring is a follow-up sprint",
            self.model_id
        )))
    }
}

/// Helper to wrap any LlmBackend in an Arc.
pub fn shared(backend: impl LlmBackend) -> Arc<dyn LlmBackend> {
    Arc::new(backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(prompt: &str) -> LlmRequest {
        LlmRequest {
            system_prompt: "sys".to_string(),
            user_prompt: prompt.to_string(),
            max_tokens: 1024,
            temperature: 0.0,
            seed: None,
        }
    }

    fn resp(text: &str) -> LlmResponse {
        LlmResponse {
            text: text.to_string(),
            input_tokens: 100,
            output_tokens: 50,
            model_id: "mock".to_string(),
        }
    }

    #[tokio::test]
    async fn mock_returns_response_by_substring() {
        let mock = MockLlmProvider::new("mock")
            .with_response("hello", resp("world"));
        let out = mock.complete(req("say hello")).await.unwrap();
        assert_eq!(out.text, "world");
        assert_eq!(mock.call_count(), 1);
    }

    #[tokio::test]
    async fn mock_increments_call_count() {
        let mock = MockLlmProvider::new("mock").with_response("x", resp("y"));
        for _ in 0..5 {
            let _ = mock.complete(req("x")).await.unwrap();
        }
        assert_eq!(mock.call_count(), 5);
    }

    #[tokio::test]
    async fn mock_returns_unavailable_when_no_match() {
        let mock = MockLlmProvider::new("mock");
        let err = mock.complete(req("nothing registered")).await.unwrap_err();
        assert!(matches!(err, AgentError::LlmUnavailable(_)));
    }

    #[tokio::test]
    async fn mock_default_response_when_no_substring_match() {
        let mock = MockLlmProvider::new("mock")
            .with_default(resp("default"));
        let out = mock.complete(req("anything")).await.unwrap();
        assert_eq!(out.text, "default");
    }

    #[tokio::test]
    async fn mock_rate_limit_after_n_calls() {
        // limit = 2: first 2 calls pass, the 3rd is rate-limited.
        let mock = MockLlmProvider::new("mock")
            .with_response("x", resp("y"))
            .with_rate_limit_after(2);
        assert!(mock.complete(req("x")).await.is_ok());
        assert!(mock.complete(req("x")).await.is_ok());
        // 3rd call: rate limited (n=3 > limit=2).
        let err = mock.complete(req("x")).await.unwrap_err();
        assert!(matches!(err, AgentError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn mock_rate_limit_zero_blocks_first_call() {
        // limit = 0: even the first call (n=1 > 0) is rate-limited.
        let mock = MockLlmProvider::new("mock")
            .with_response("x", resp("y"))
            .with_rate_limit_after(0);
        let err = mock.complete(req("x")).await.unwrap_err();
        assert!(matches!(err, AgentError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn mock_substring_match_in_system_prompt() {
        let mock = MockLlmProvider::new("mock")
            .with_response("classify", resp("gaap"));
        let r = LlmRequest {
            system_prompt: "you classify accounts".to_string(),
            user_prompt: "what is 6100".to_string(),
            max_tokens: 100,
            temperature: 0.0,
            seed: None,
        };
        let out = mock.complete(r).await.unwrap();
        assert_eq!(out.text, "gaap");
    }

    #[test]
    fn stub_backends_have_correct_model_ids() {
        assert_eq!(AnthropicBackend::new("claude-sonnet-4.6").model_id(), "claude-sonnet-4.6");
        assert_eq!(AnthropicBackend::new("claude-haiku-4.5").model_id(), "claude-haiku-4.5");
        assert_eq!(OpenAiCompatBackend::new("deepseek-v4-flash").model_id(), "deepseek-v4-flash");
        assert_eq!(OpenAiCompatBackend::new("qwen3-coder-30b").model_id(), "qwen3-coder-30b");
        assert_eq!(ZaiBackend::new("glm-5.1").model_id(), "glm-5.1");
        assert_eq!(GoogleBackend::new("gemini-3.1-flash-lite").model_id(), "gemini-3.1-flash-lite");
    }

    #[tokio::test]
    async fn stub_backends_return_unavailable_until_wired() {
        let b = AnthropicBackend::new("claude-sonnet-4.6");
        let err = b.complete(req("hi")).await.unwrap_err();
        assert!(matches!(err, AgentError::LlmUnavailable(_)));
    }

    #[test]
    fn shared_wraps_in_arc() {
        let mock = MockLlmProvider::new("m");
        let arc: Arc<dyn LlmBackend> = shared(mock);
        assert_eq!(arc.model_id(), "m");
    }
}
