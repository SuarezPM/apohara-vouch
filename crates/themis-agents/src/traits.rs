//! Agent trait and the context it operates on.

use async_trait::async_trait;
use std::collections::HashMap;

use crate::decision::{AgentDecision, AgentError};

/// Per-invoice context passed to every `Agent::process()` call. The
/// orchestrator builds this before invoking each agent; agents are
/// pure functions of the context.
#[derive(Debug, Clone, Default)]
pub struct AgentContext {
    /// Tenant (e.g. "stark", "wayne").
    pub tenant_id: String,
    /// Invoice identifier.
    pub invoice_id: String,
    /// Raw invoice bytes (PDF, image, or pre-parsed JSON).
    pub raw_invoice: Vec<u8>,
    /// Filename or content-type hint.
    pub content_type: String,
    /// Decisions emitted by upstream agents in this run. Empty at the
    /// start; the orchestrator appends as each agent completes.
    pub upstream_decisions: Vec<AgentDecision>,
    /// Per-invoice metadata (e.g. PO database, demo fixture flags).
    pub metadata: HashMap<String, String>,
}

impl AgentContext {
    /// Convenience constructor.
    pub fn new(tenant_id: impl Into<String>, invoice_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            invoice_id: invoice_id.into(),
            ..Self::default()
        }
    }

    /// Builder: set the raw invoice bytes.
    pub fn with_raw_invoice(mut self, bytes: Vec<u8>, content_type: impl Into<String>) -> Self {
        self.raw_invoice = bytes;
        self.content_type = content_type.into();
        self
    }

    /// Builder: append an upstream decision.
    pub fn with_upstream(mut self, decision: AgentDecision) -> Self {
        self.upstream_decisions.push(decision);
        self
    }

    /// Builder: set a metadata key.
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// The trait every THEMIS agent implements. The trait is async
/// (most agents do LLM I/O), Send + Sync (agents live behind Arc),
/// and `'static` (the trait object outlives the orchestrator
/// process).
#[async_trait]
pub trait Agent: Send + Sync + 'static {
    /// Stable identifier (matches `DecisionType::as_str()` for this
    /// agent's primary output).
    fn name(&self) -> &'static str;

    /// Run the agent on the given context. Returns the canonical
    /// `AgentDecision` on success, or an `AgentError` on failure.
    /// Failures propagate — the orchestrator decides whether to
    /// retry, HALT, or continue.
    async fn process(&self, ctx: AgentContext) -> Result<AgentDecision, AgentError>;
}
