//! Audit Watchdog (shadow) — observes the chain of decisions and
//! raises a `WatchdogAlert` when any upstream decision has a
//! `confidence < 0.5` OR a `FraudAssessed` decision with a Halt.
//!
//! Read-only: never mutates the chain. The orchestrator may surface
//! the alert in the UI alongside the BAAAR HALT for transparency.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::decision::{AgentDecision, AgentError, DecisionType};
use crate::llm::LlmBackend;
use crate::traits::{Agent, AgentContext};

/// The Audit Watchdog's alert payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatchdogAlert {
    /// Coherence score across the decision chain (0.0..=1.0).
    pub coherence_score: f32,
    /// Whether any upstream decision raised a BAAAR HALT.
    pub risk_elevated: bool,
    /// Human-readable reason (goes into the Evidence Packet).
    pub reason: String,
}

/// The Audit Watchdog shadow agent.
pub struct AuditWatchdog {
    #[allow(dead_code)]
    llm: Option<Arc<dyn LlmBackend>>,
}

impl AuditWatchdog {
    /// New watchdog.
    pub fn new() -> Self {
        Self { llm: None }
    }

    /// Attach an LLM (unused for now; reserved for future LLM-based
    /// coherence estimation).
    pub fn with_llm(mut self, llm: Arc<dyn LlmBackend>) -> Self {
        self.llm = Some(llm);
        self
    }
}

impl Default for AuditWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Agent for AuditWatchdog {
    fn name(&self) -> &'static str {
        "audit_watchdog"
    }

    async fn process(&self, ctx: AgentContext) -> Result<AgentDecision, AgentError> {
        if ctx.upstream_decisions.is_empty() {
            return Err(AgentError::InvalidInput(
                "AuditWatchdog: upstream_decisions is empty".to_string(),
            ));
        }

        // Coherence = mean confidence across upstream decisions.
        let mean_confidence: f32 = ctx
            .upstream_decisions
            .iter()
            .map(|d| d.confidence)
            .sum::<f32>()
            / ctx.upstream_decisions.len() as f32;

        // Risk elevated if any FraudAssessed decision has Halt.
        // The Fraud Auditor's payload IS the FraudAuditorOutput (we
        // serialize it directly into payload), so payload["outcome"]
        // is the gate verdict (an Outcome enum serialized via its
        // own snake_case tag).
        let risk_elevated = ctx.upstream_decisions.iter().any(|d| {
            d.decision_type == DecisionType::FraudAssessed
                && d.payload
                    .get("outcome")
                    .and_then(|v| match v {
                        serde_json::Value::String(s) => Some(
                            s == "halt_risk_score_exceeded"
                                || s == "halt_secret_leak_detected"
                                || s == "halt_coherence_too_low"
                                || s == "halt_max_debate_rounds_reached"
                                || s == "halt_explicit_halt_requested",
                        ),
                        _ => None,
                    })
                    .unwrap_or(false)
        });

        let reason = if risk_elevated {
            "BAAAR HALT detected in FraudAssessed upstream decision".to_string()
        } else if mean_confidence < 0.5 {
            format!(
                "Mean confidence {:.2} below 0.5 — review chain",
                mean_confidence
            )
        } else {
            format!("Chain coherent (mean confidence {:.2})", mean_confidence)
        };

        let alert = WatchdogAlert {
            coherence_score: mean_confidence,
            risk_elevated,
            reason: reason.clone(),
        };

        Ok(AgentDecision {
            agent_id: self.name().to_string(),
            tenant_id: ctx.tenant_id,
            invoice_id: ctx.invoice_id,
            decision_type: DecisionType::WatchdogAlert,
            confidence: mean_confidence,
            reasoning: reason,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            payload: serde_json::to_value(&alert).map_err(|e| {
                AgentError::Internal(format!("AuditWatchdog: serialize alert: {e}"))
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(conf: f32, dt: DecisionType) -> AgentDecision {
        AgentDecision {
            agent_id: "x".to_string(),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: dt,
            confidence: conf,
            reasoning: "x".to_string(),
            timestamp_ms: 0,
            payload: serde_json::json!({}),
        }
    }

    fn fraud_dec_with_halt() -> AgentDecision {
        // Match the FraudAuditor's actual payload shape: a top-level
        // "outcome" field whose value is the snake_case string of
        // the Outcome enum (e.g. "halt_risk_score_exceeded").
        let mut d = dec(0.85, DecisionType::FraudAssessed);
        d.payload = serde_json::json!({
            "outcome": "halt_risk_score_exceeded",
            "assessment": {
                "risk_score": 0.95,
                "findings": [],
                "coherence_score": 0.7,
                "debate_rounds": 1,
                "explicit_halt": false
            }
        });
        d
    }

    #[tokio::test]
    async fn alerts_on_baaar_halt_in_upstream() {
        let agent = AuditWatchdog::new();
        let ctx = AgentContext::new("stark", "inv-001")
            .with_upstream(fraud_dec_with_halt())
            .with_upstream(dec(0.9, DecisionType::Extracted));
        let d = agent.process(ctx).await.unwrap();
        let a: WatchdogAlert = serde_json::from_value(d.payload).unwrap();
        assert!(a.risk_elevated);
        assert!(a.reason.contains("BAAAR HALT"));
    }

    #[tokio::test]
    async fn alerts_on_low_mean_confidence() {
        let agent = AuditWatchdog::new();
        let ctx = AgentContext::new("stark", "inv-001")
            .with_upstream(dec(0.3, DecisionType::Extracted))
            .with_upstream(dec(0.4, DecisionType::PoMatched));
        let d = agent.process(ctx).await.unwrap();
        let a: WatchdogAlert = serde_json::from_value(d.payload).unwrap();
        assert!(!a.risk_elevated);
        assert!(a.reason.contains("below 0.5"));
        assert!((a.coherence_score - 0.35).abs() < 0.01);
    }

    #[tokio::test]
    async fn coherent_chain_no_alert() {
        let agent = AuditWatchdog::new();
        let ctx = AgentContext::new("stark", "inv-001")
            .with_upstream(dec(0.9, DecisionType::Extracted))
            .with_upstream(dec(0.95, DecisionType::PoMatched));
        let d = agent.process(ctx).await.unwrap();
        let a: WatchdogAlert = serde_json::from_value(d.payload).unwrap();
        assert!(!a.risk_elevated);
        assert!(a.reason.contains("coherent"));
    }

    #[tokio::test]
    async fn empty_upstream_returns_invalid_input() {
        let agent = AuditWatchdog::new();
        let err = agent
            .process(AgentContext::new("stark", "inv-001"))
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::InvalidInput(_)));
    }
}
