//! Canonical decision types and error envelope.
//!
//! Every agent emits an `AgentDecision` regardless of its role — the
//! `decision_type` discriminant tells callers which kind it is. The
//! `AgentError` enum covers LLM-failure modes that propagate without
//! coercion (the BAAAR gate then fails closed, never invents a value).

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The 8 kinds of decisions agents in THEMIS can emit. The numeric
/// discriminants are stable across versions (a wire-format contract
/// for the Evidence Packet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionType {
    /// `Extractor` parsed a raw invoice into structured JSON.
    Extracted,
    /// `PoMatcher` matched the invoice against a purchase order.
    PoMatched,
    /// `FraudAuditor` produced a risk assessment (BAAAR may HALT).
    FraudAssessed,
    /// `GaapClassifier` mapped line items to a US-GAAP account.
    GaapClassified,
    /// `ProvenanceSigner` sealed the Evidence Packet.
    ProvenanceSigned,
    /// `AuditWatchdog` (shadow) flagged a coherence issue.
    WatchdogAlert,
    /// `RegressionTester` (shadow) re-verified the packet.
    RegressionResult,
    /// `DemoNarrator` (shadow) produced a human-readable summary.
    Narrated,
}

impl DecisionType {
    /// Stable string identifier (matches the serde rename).
    pub fn as_str(&self) -> &'static str {
        match self {
            DecisionType::Extracted => "extracted",
            DecisionType::PoMatched => "po_matched",
            DecisionType::FraudAssessed => "fraud_assessed",
            DecisionType::GaapClassified => "gaap_classified",
            DecisionType::ProvenanceSigned => "provenance_signed",
            DecisionType::WatchdogAlert => "watchdog_alert",
            DecisionType::RegressionResult => "regression_result",
            DecisionType::Narrated => "narrated",
        }
    }
}

/// Canonical decision envelope. Every agent emits one of these per
/// `process()` call. The `payload` field is a JSON `Value` because
/// each decision type carries a different shape (extracted invoice
/// vs. fraud assessment vs. signed packet) — we keep the envelope
/// uniform for telemetry and Evidence Packet assembly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentDecision {
    /// Which agent produced this decision.
    pub agent_id: String,
    /// The tenant (Stark or Wayne) this decision belongs to.
    pub tenant_id: String,
    /// The invoice being processed.
    pub invoice_id: String,
    /// What kind of decision this is.
    pub decision_type: DecisionType,
    /// Agent's confidence in the decision, 0.0..=1.0.
    pub confidence: f32,
    /// Human-readable reasoning (goes into the Evidence Packet).
    pub reasoning: String,
    /// Unix epoch milliseconds when the decision was made.
    pub timestamp_ms: i64,
    /// Type-specific payload (JSON).
    pub payload: serde_json::Value,
}

/// All failure modes an agent can return. `LlmMalformedPayload` is
/// the critical one for the BAAAR gate — it forces fail-closed
/// behavior (HALT, not "ignore and continue").
///
/// `#[non_exhaustive]` so future variants can be added without a
/// breaking semver bump; downstream crates (and tests) must add a
/// `_` arm to any exhaustive `match` on `AgentError`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AgentError {
    /// The LLM provider is unreachable or rate-limited.
    #[error("LLM unavailable: {0}")]
    LlmUnavailable(String),

    /// The LLM returned a payload that could not be parsed (e.g.
    /// not the requested JSON shape, missing required field).
    #[error("LLM returned a malformed payload: {0}")]
    LlmMalformedPayload(String),

    /// The LLM provider rate-limited us.
    #[error("rate limited: retry after {retry_after_ms}ms")]
    RateLimited {
        /// Milliseconds to wait before retrying.
        retry_after_ms: u64,
    },

    /// The LLM provider rejected our credentials (401/403). The
    /// provider's error envelope (`error.message` on OpenAI-compat
    /// gateways) is surfaced as `reason` for operator triage.
    #[error("{provider} authentication failed: {reason}")]
    AuthenticationError {
        /// Stable provider identifier (`"aimlapi"`, `"featherless"`,
        /// `"anthropic"`, ...). Used in error messages and logs.
        provider: &'static str,
        /// Human-readable reason from the provider's error envelope.
        reason: String,
    },

    /// The input to the agent was invalid (e.g. empty invoice bytes).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Internal error (e.g. crypto failure, I/O on keys dir).
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_type_as_str_is_stable() {
        // Wire format — used by Evidence Packet assembly.
        assert_eq!(DecisionType::Extracted.as_str(), "extracted");
        assert_eq!(DecisionType::PoMatched.as_str(), "po_matched");
        assert_eq!(DecisionType::FraudAssessed.as_str(), "fraud_assessed");
        assert_eq!(DecisionType::GaapClassified.as_str(), "gaap_classified");
        assert_eq!(DecisionType::ProvenanceSigned.as_str(), "provenance_signed");
        assert_eq!(DecisionType::WatchdogAlert.as_str(), "watchdog_alert");
        assert_eq!(DecisionType::RegressionResult.as_str(), "regression_result");
        assert_eq!(DecisionType::Narrated.as_str(), "narrated");
    }

    #[test]
    fn decision_type_serde_uses_snake_case() {
        // JSON serialization must match the snake_case strings.
        let json = serde_json::to_string(&DecisionType::FraudAssessed).unwrap();
        assert_eq!(json, "\"fraud_assessed\"");

        // Round-trip
        let parsed: DecisionType = serde_json::from_str("\"extracted\"").unwrap();
        assert_eq!(parsed, DecisionType::Extracted);
    }

    #[test]
    fn agent_decision_round_trips_through_json() {
        let decision = AgentDecision {
            agent_id: "extractor".to_string(),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: DecisionType::Extracted,
            confidence: 0.92,
            reasoning: "Parsed 3 line items".to_string(),
            timestamp_ms: 1_700_000_000_000,
            payload: serde_json::json!({
                "vendor": "Acme Corp",
                "amount_cents": 45000,
            }),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: AgentDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, decision);
    }

    #[test]
    fn agent_decision_serde_field_names_are_snake_case() {
        let decision = AgentDecision {
            agent_id: "x".to_string(),
            tenant_id: "y".to_string(),
            invoice_id: "z".to_string(),
            decision_type: DecisionType::Narrated,
            confidence: 0.5,
            reasoning: "ok".to_string(),
            timestamp_ms: 0,
            payload: serde_json::json!({}),
        };
        let v: serde_json::Value = serde_json::to_value(&decision).unwrap();
        assert!(v.get("agent_id").is_some());
        assert!(v.get("tenant_id").is_some());
        assert!(v.get("invoice_id").is_some());
        assert!(v.get("decision_type").is_some());
        assert!(v.get("confidence").is_some());
        assert!(v.get("reasoning").is_some());
        assert!(v.get("timestamp_ms").is_some());
        assert!(v.get("payload").is_some());
    }

    #[test]
    fn agent_error_display_messages_are_non_empty() {
        let errs = [
            AgentError::LlmUnavailable("down".to_string()),
            AgentError::LlmMalformedPayload("not json".to_string()),
            AgentError::RateLimited {
                retry_after_ms: 5000,
            },
            AgentError::AuthenticationError {
                provider: "aimlapi",
                reason: "Invalid API key".to_string(),
            },
            AgentError::InvalidInput("empty".to_string()),
            AgentError::Internal("io".to_string()),
        ];
        for e in &errs {
            assert!(
                !e.to_string().is_empty(),
                "AgentError {e:?} has empty Display"
            );
        }
    }

    #[test]
    fn agent_error_display_includes_context() {
        let e = AgentError::LlmMalformedPayload("expected field `risk_score`".to_string());
        assert!(e.to_string().contains("expected field `risk_score`"));

        let e = AgentError::RateLimited {
            retry_after_ms: 1234,
        };
        assert!(e.to_string().contains("1234"));
    }
}
