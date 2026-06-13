//! Fraud Auditor — the gatekeeper. Calls the LLM for an assessment,
//! then runs the BAAAR gate. If the gate HALTs, the agent returns an
//! `AgentDecision::FraudAssessed` with `payload.outcome = Halt(...)`
//! — the orchestrator reads that to surface the red flash + modal.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::baaar::{BaaarGate, FraudAssessment, Outcome};
use crate::decision::{AgentDecision, AgentError, DecisionType};
use crate::llm::{LlmBackend, LlmRequest};
use crate::traits::{Agent, AgentContext};

/// The FraudAuditor's output payload. Wraps the assessment + the
/// gate's verdict so the Evidence Packet has both.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudAuditorOutput {
    /// The full LLM assessment.
    pub assessment: FraudAssessment,
    /// The BAAAR gate's verdict.
    pub outcome: Outcome,
}

/// The Fraud Auditor agent.
pub struct FraudAuditor {
    llm: Arc<dyn LlmBackend>,
    gate: BaaarGate,
}

impl FraudAuditor {
    /// New FraudAuditor with the given LLM and a default BAAAR gate.
    pub fn new(llm: Arc<dyn LlmBackend>) -> Self {
        Self {
            llm,
            gate: BaaarGate::new(),
        }
    }

    /// Custom gate (for tests with different thresholds).
    pub fn with_gate(mut self, gate: BaaarGate) -> Self {
        self.gate = gate;
        self
    }
}

#[async_trait]
impl Agent for FraudAuditor {
    fn name(&self) -> &'static str {
        "fraud_auditor"
    }

    async fn process(&self, ctx: AgentContext) -> Result<AgentDecision, AgentError> {
        let system_prompt = FRAUD_AUDITOR_SYSTEM_PROMPT.to_string();
        let user_prompt = format!(
            "Assess this invoice (tenant={}, invoice_id={}). Upstream decisions: {}",
            ctx.tenant_id,
            ctx.invoice_id,
            ctx.upstream_decisions.len()
        );

        let req = LlmRequest {
            system_prompt,
            user_prompt,
            max_tokens: 1024,
            temperature: 0.0,
            seed: Some(42),
        };

        let resp = self.llm.complete(req).await?;
        let cleaned = strip_code_fences(&resp.text);

        let assessment: FraudAssessment = serde_json::from_str(&cleaned).map_err(|e| {
            AgentError::LlmMalformedPayload(format!(
                "FraudAuditor: response is not valid FraudAssessment JSON: {e}; raw={:?}",
                &resp.text[..resp.text.len().min(200)]
            ))
        })?;

        // Run the BAAAR gate.
        let outcome = self.gate.check(&assessment);

        let output = FraudAuditorOutput {
            assessment,
            outcome,
        };

        let reasoning = match outcome {
            Outcome::Approve => format!(
                "Fraud assessment approved: risk_score={}",
                output.assessment.risk_score
            ),
            Outcome::Halt(reason) => format!("HALTED by BAAAR: {reason:?}"),
        };

        Ok(AgentDecision {
            agent_id: self.name().to_string(),
            tenant_id: ctx.tenant_id,
            invoice_id: ctx.invoice_id,
            decision_type: DecisionType::FraudAssessed,
            confidence: 0.85,
            reasoning,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            payload: serde_json::to_value(&output).map_err(|e| {
                AgentError::Internal(format!("FraudAuditor: serialize payload: {e}"))
            })?,
        })
    }
}

// Re-export FindingKind for convenience. MUST appear before any
// #[cfg(test)] mod tests; clippy's `items-after-test-module` lint
// flags it otherwise.
pub use crate::baaar::FindingKind as PublicFindingKind;

const FRAUD_AUDITOR_SYSTEM_PROMPT: &str = "\
You are the Fraud Auditor agent in THEMIS. Given the upstream \
decisions for an invoice, produce a JSON object matching this schema:

{
  \"risk_score\": number (0.0..=1.0),
  \"findings\": [{\"kind\": \"secret_leak|price_anomaly|phantom_vendor|math_fraud|duplicate|other\", \"value\": \"string\", \"description\": \"string\"}],
  \"coherence_score\": number (0.0..=1.0),
  \"debate_rounds\": integer (>= 0),
  \"explicit_halt\": boolean
}

When you set `kind` to \"other\", the `value` field carries a custom tag.

Respond with ONLY the JSON object. No commentary, no markdown fences.";

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
    use crate::baaar::BaaarReason;
    use crate::llm::{LlmResponse, MockLlmProvider};

    fn assessment_json(score: f32) -> String {
        serde_json::json!({
            "risk_score": score,
            "findings": [],
            "coherence_score": 0.7,
            "debate_rounds": 1,
            "explicit_halt": false
        })
        .to_string()
    }

    fn assessment_with_secret_leak() -> String {
        // Finding kind is a flat string ("secret_leak"), not a
        // tagged enum (no "value" field).
        serde_json::json!({
            "risk_score": 0.1,
            "findings": [
                {"kind": "secret_leak", "description": "AWS key in notes"}
            ],
            "coherence_score": 0.8,
            "debate_rounds": 1,
            "explicit_halt": false
        })
        .to_string()
    }

    #[tokio::test]
    async fn approves_when_risk_below_threshold() {
        let mock = MockLlmProvider::new("mock").with_response(
            "Assess this",
            LlmResponse {
                text: assessment_json(0.5),
                input_tokens: 100,
                output_tokens: 100,
                model_id: "mock".to_string(),
            },
        );
        let agent = FraudAuditor::new(Arc::new(mock));
        let d = agent
            .process(AgentContext::new("stark", "inv-001"))
            .await
            .unwrap();
        assert_eq!(d.decision_type, DecisionType::FraudAssessed);
        let out: FraudAuditorOutput = serde_json::from_value(d.payload).unwrap();
        assert_eq!(out.outcome, Outcome::Approve);
    }

    #[tokio::test]
    async fn halts_on_high_risk_score() {
        let mock = MockLlmProvider::new("mock").with_response(
            "Assess this",
            LlmResponse {
                text: assessment_json(0.95),
                input_tokens: 100,
                output_tokens: 100,
                model_id: "mock".to_string(),
            },
        );
        let agent = FraudAuditor::new(Arc::new(mock));
        let d = agent
            .process(AgentContext::new("stark", "inv-001"))
            .await
            .unwrap();
        let out: FraudAuditorOutput = serde_json::from_value(d.payload).unwrap();
        assert_eq!(out.outcome, Outcome::Halt(BaaarReason::RiskScoreExceeded));
    }

    #[tokio::test]
    async fn halts_on_secret_leak_finding() {
        let mock = MockLlmProvider::new("mock").with_response(
            "Assess this",
            LlmResponse {
                text: assessment_with_secret_leak(),
                input_tokens: 100,
                output_tokens: 100,
                model_id: "mock".to_string(),
            },
        );
        let agent = FraudAuditor::new(Arc::new(mock));
        let d = agent
            .process(AgentContext::new("stark", "inv-001"))
            .await
            .unwrap();
        let out: FraudAuditorOutput = serde_json::from_value(d.payload).unwrap();
        assert_eq!(out.outcome, Outcome::Halt(BaaarReason::SecretLeakDetected));
    }

    #[tokio::test]
    async fn malformed_json_returns_malformed_payload() {
        let mock = MockLlmProvider::new("mock").with_response(
            "Assess this",
            LlmResponse {
                text: "garbage".to_string(),
                input_tokens: 50,
                output_tokens: 50,
                model_id: "mock".to_string(),
            },
        );
        let agent = FraudAuditor::new(Arc::new(mock));
        let err = agent
            .process(AgentContext::new("stark", "inv-001"))
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::LlmMalformedPayload(_)));
    }

    #[tokio::test]
    async fn missing_required_field_returns_malformed_payload() {
        let bad = serde_json::json!({
            "risk_score": 0.5,
            // missing findings, coherence_score, debate_rounds, explicit_halt
        })
        .to_string();
        let mock = MockLlmProvider::new("mock").with_response(
            "Assess this",
            LlmResponse {
                text: bad,
                input_tokens: 50,
                output_tokens: 50,
                model_id: "mock".to_string(),
            },
        );
        let agent = FraudAuditor::new(Arc::new(mock));
        let err = agent
            .process(AgentContext::new("stark", "inv-001"))
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::LlmMalformedPayload(_)));
    }

    #[tokio::test]
    async fn llm_unavailable_propagates() {
        // Mock with no responses registered.
        let mock = MockLlmProvider::new("mock");
        let agent = FraudAuditor::new(Arc::new(mock));
        let err = agent
            .process(AgentContext::new("stark", "inv-001"))
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::LlmUnavailable(_)));
    }
}
