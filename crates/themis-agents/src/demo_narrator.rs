//! Demo Narrator (shadow) — produces a 1-paragraph human-readable
//! summary of the decision chain. Cheap Haiku 4.5 call in production;
//! in tests the LLM is mocked.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::decision::{AgentDecision, AgentError, DecisionType};
use crate::llm::{LlmBackend, LlmRequest};
use crate::traits::{Agent, AgentContext};

/// The Demo Narrator's output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Narration {
    /// The narrative summary (1-3 sentences).
    pub summary: String,
    /// Number of decisions narrated.
    pub decisions_count: usize,
}

/// The Demo Narrator shadow agent.
pub struct DemoNarrator {
    llm: Arc<dyn LlmBackend>,
}

impl DemoNarrator {
    /// New narrator.
    pub fn new(llm: Arc<dyn LlmBackend>) -> Self {
        Self { llm }
    }
}

#[async_trait]
impl Agent for DemoNarrator {
    fn name(&self) -> &'static str {
        "demo_narrator"
    }

    async fn process(&self, ctx: AgentContext) -> Result<AgentDecision, AgentError> {
        if ctx.upstream_decisions.is_empty() {
            return Err(AgentError::InvalidInput(
                "DemoNarrator: upstream_decisions is empty".to_string(),
            ));
        }

        let system_prompt = "\
You are the Demo Narrator in THEMIS. Given a chain of agent decisions \
for an invoice, produce a 1-2 sentence plain-language summary for a \
judge at a hackathon demo. Be concise, factual, and surface the \
final outcome (approved or halted) prominently. Respond with a JSON \
object: {\"summary\": \"<text>\"}.";

        let user_prompt = format!(
            "Narrate these {} decisions for invoice {} (tenant={}):\n{}",
            ctx.upstream_decisions.len(),
            ctx.invoice_id,
            ctx.tenant_id,
            ctx.upstream_decisions
                .iter()
                .map(|d| format!("- {}: {}", d.decision_type.as_str(), d.reasoning))
                .collect::<Vec<_>>()
                .join("\n")
        );

        let req = LlmRequest {
            system_prompt: system_prompt.to_string(),
            user_prompt,
            max_tokens: 256,
            temperature: 0.3,
            seed: None,
            // DemoNarrator is prose — no JSON schema, no constrained
            // decoding. The `strip_code_fences` helper still parses
            // the optional `{ "summary": "..." }` envelope.
            response_schema: None,
            response_schema_name: None,
        };

        let resp = self.llm.complete(req).await?;
        let cleaned = strip_code_fences(&resp.text);

        // Try the JSON envelope first, then fall back to raw text.
        let summary = if let Ok(env) = serde_json::from_str::<serde_json::Value>(&cleaned) {
            env.get("summary")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or(cleaned.clone())
        } else {
            cleaned.clone()
        };

        if summary.is_empty() {
            return Err(AgentError::LlmMalformedPayload(
                "DemoNarrator: LLM returned empty summary".to_string(),
            ));
        }

        let narration = Narration {
            summary: summary.clone(),
            decisions_count: ctx.upstream_decisions.len(),
        };

        Ok(AgentDecision {
            agent_id: self.name().to_string(),
            tenant_id: ctx.tenant_id,
            invoice_id: ctx.invoice_id,
            decision_type: DecisionType::Narrated,
            confidence: 0.9,
            reasoning: summary,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            payload: serde_json::to_value(&narration).map_err(|e| {
                AgentError::Internal(format!("DemoNarrator: serialize narration: {e}"))
            })?,
        })
    }
}

fn strip_code_fences(text: &str) -> String {
    let trimmed = text.trim();
    if let Some(rest) = trimmed.strip_prefix("```json") {
        if let Some(inner) = rest.strip_suffix("```") {
            return inner.trim().to_string();
        }
    }
    if let Some(rest) = trimmed.strip_prefix("```") {
        if let Some(inner) = rest.strip_suffix("```") {
            return inner.trim().to_string();
        }
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{LlmResponse, MockLlmProvider};

    fn dec(dt: DecisionType) -> AgentDecision {
        AgentDecision {
            agent_id: "x".to_string(),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: dt,
            confidence: 0.9,
            reasoning: "x".to_string(),
            timestamp_ms: 0,
            payload: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn narrates_chain_with_json_envelope() {
        let good = serde_json::json!({"summary": "Invoice processed and approved."}).to_string();
        let mock = MockLlmProvider::new("mock").with_response(
            "Narrate these",
            LlmResponse {
                text: good,
                input_tokens: 100,
                output_tokens: 30,
                model_id: "mock".to_string(),
                finish_reason: crate::llm::FinishReason::Stop,
            }        );
        let agent = DemoNarrator::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001")
            .with_upstream(dec(DecisionType::Extracted))
            .with_upstream(dec(DecisionType::PoMatched));
        let d = agent.process(ctx).await.unwrap();
        let n: Narration = serde_json::from_value(d.payload).unwrap();
        assert_eq!(n.summary, "Invoice processed and approved.");
        assert_eq!(n.decisions_count, 2);
    }

    #[tokio::test]
    async fn narrates_chain_with_raw_text_fallback() {
        let mock = MockLlmProvider::new("mock").with_response(
            "Narrate these",
            LlmResponse {
                text: "Plain text narration, no JSON envelope.".to_string(),
                input_tokens: 100,
                output_tokens: 30,
                model_id: "mock".to_string(),
                finish_reason: crate::llm::FinishReason::Stop,
            }        );
        let agent = DemoNarrator::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001").with_upstream(dec(DecisionType::Extracted));
        let d = agent.process(ctx).await.unwrap();
        let n: Narration = serde_json::from_value(d.payload).unwrap();
        assert!(n.summary.contains("Plain text"));
    }

    #[tokio::test]
    async fn empty_summary_returns_malformed_payload() {
        let mock = MockLlmProvider::new("mock").with_response(
            "Narrate these",
            LlmResponse {
                text: "".to_string(),
                input_tokens: 0,
                output_tokens: 0,
                model_id: "mock".to_string(),
                finish_reason: crate::llm::FinishReason::Stop,
            }        );
        let agent = DemoNarrator::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001").with_upstream(dec(DecisionType::Extracted));
        let err = agent.process(ctx).await.unwrap_err();
        assert!(matches!(err, AgentError::LlmMalformedPayload(_)));
    }

    #[tokio::test]
    async fn empty_upstream_returns_invalid_input() {
        let mock = MockLlmProvider::new("mock");
        let agent = DemoNarrator::new(Arc::new(mock));
        let err = agent
            .process(AgentContext::new("stark", "inv-001"))
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::InvalidInput(_)));
    }
}
