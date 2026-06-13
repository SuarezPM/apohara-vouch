//! PO Matcher — deterministic match of an ExtractedInvoice against
//! the purchase-order database.
//!
//! No LLM call. The orchestrator treats this agent the same as the
//! others (passes an `Arc<dyn LlmBackend>`), but the LLM is unused.
//! Kept as `Option<Arc<dyn LlmBackend>>` for trait uniformity; the
//! orchestrator can wire a no-op LLM in tests.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::decision::{AgentDecision, AgentError, DecisionType};
use crate::extractor::ExtractedInvoice;
use crate::llm::LlmBackend;
use crate::traits::{Agent, AgentContext};

/// A purchase order in the database.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PurchaseOrder {
    /// PO reference (e.g. "PO-12345").
    pub po_ref: String,
    /// Expected amount in cents.
    pub expected_amount_cents: i64,
    /// Expected vendor.
    pub vendor: String,
}

/// The result of a PO match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoMatchResult {
    /// Whether the PO was found in the database.
    pub matched: bool,
    /// Expected amount (if matched).
    pub expected_amount_cents: Option<i64>,
    /// Difference between invoice amount and PO expected amount, as
    /// a percentage of the expected amount. `None` when not matched.
    pub delta_pct: Option<f32>,
    /// Vendor on the PO (if matched) — for the Evidence Packet.
    pub po_vendor: Option<String>,
}

/// The PO Matcher agent.
pub struct PoMatcher {
    po_db: HashMap<String, PurchaseOrder>,
    #[allow(dead_code)]
    llm: Option<Arc<dyn LlmBackend>>,
}

impl PoMatcher {
    /// New PO Matcher with the given database.
    pub fn new(po_db: HashMap<String, PurchaseOrder>) -> Self {
        Self { po_db, llm: None }
    }

    /// Attach an LLM (unused, kept for trait uniformity).
    pub fn with_llm(mut self, llm: Arc<dyn LlmBackend>) -> Self {
        self.llm = Some(llm);
        self
    }
}

#[async_trait]
impl Agent for PoMatcher {
    fn name(&self) -> &'static str {
        "po_matcher"
    }

    async fn process(&self, ctx: AgentContext) -> Result<AgentDecision, AgentError> {
        // Find the Extractor's decision in the upstream chain.
        let extracted = ctx
            .upstream_decisions
            .iter()
            .find(|d| d.decision_type == DecisionType::Extracted)
            .ok_or_else(|| {
                AgentError::InvalidInput(
                    "PO Matcher: no Extracted decision in upstream_decisions".to_string(),
                )
            })?;

        let invoice: ExtractedInvoice =
            serde_json::from_value(extracted.payload.clone()).map_err(|e| {
                AgentError::LlmMalformedPayload(format!(
                    "PO Matcher: upstream Extracted payload is not ExtractedInvoice: {e}"
                ))
            })?;

        let result = match self.po_db.get(&invoice.po_ref) {
            Some(po) => {
                let delta_pct = if po.expected_amount_cents == 0 {
                    0.0
                } else {
                    let diff = invoice.amount_cents - po.expected_amount_cents;
                    (diff as f32 / po.expected_amount_cents as f32) * 100.0
                };
                PoMatchResult {
                    matched: true,
                    expected_amount_cents: Some(po.expected_amount_cents),
                    delta_pct: Some(delta_pct),
                    po_vendor: Some(po.vendor.clone()),
                }
            }
            None => PoMatchResult {
                matched: false,
                expected_amount_cents: None,
                delta_pct: None,
                po_vendor: None,
            },
        };

        let reasoning = if result.matched {
            format!(
                "Matched PO {} (vendor={}, expected={} cents, delta={:.1}%)",
                invoice.po_ref,
                result.po_vendor.as_deref().unwrap_or("?"),
                result.expected_amount_cents.unwrap_or(0),
                result.delta_pct.unwrap_or(0.0)
            )
        } else {
            format!("No PO found for ref {:?}", invoice.po_ref)
        };

        Ok(AgentDecision {
            agent_id: self.name().to_string(),
            tenant_id: ctx.tenant_id,
            invoice_id: ctx.invoice_id,
            decision_type: DecisionType::PoMatched,
            confidence: 1.0,
            reasoning,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            payload: serde_json::to_value(&result)
                .map_err(|e| AgentError::Internal(format!("PO Matcher: serialize payload: {e}")))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::DecisionType;

    fn db_with_po() -> HashMap<String, PurchaseOrder> {
        let mut db = HashMap::new();
        db.insert(
            "PO-12345".to_string(),
            PurchaseOrder {
                po_ref: "PO-12345".to_string(),
                expected_amount_cents: 45000,
                vendor: "Acme Corp".to_string(),
            },
        );
        db
    }

    fn make_invoice_decision(po_ref: &str, amount: i64) -> AgentDecision {
        let inv = ExtractedInvoice {
            vendor: "Acme Corp".to_string(),
            amount_cents: amount,
            line_items: vec![],
            date_iso: "2026-06-01".to_string(),
            po_ref: po_ref.to_string(),
        };
        AgentDecision {
            agent_id: "extractor".to_string(),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: DecisionType::Extracted,
            confidence: 0.9,
            reasoning: "x".to_string(),
            timestamp_ms: 0,
            payload: serde_json::to_value(&inv).unwrap(),
        }
    }

    #[tokio::test]
    async fn exact_amount_match() {
        let agent = PoMatcher::new(db_with_po());
        let ctx = AgentContext::new("stark", "inv-001")
            .with_upstream(make_invoice_decision("PO-12345", 45_000));
        let d = agent.process(ctx).await.unwrap();
        assert_eq!(d.decision_type, DecisionType::PoMatched);
        let r: PoMatchResult = serde_json::from_value(d.payload).unwrap();
        assert!(r.matched);
        assert_eq!(r.expected_amount_cents, Some(45_000));
        assert_eq!(r.delta_pct, Some(0.0));
    }

    #[tokio::test]
    async fn price_gouging_detected_as_positive_delta() {
        let agent = PoMatcher::new(db_with_po());
        let ctx = AgentContext::new("stark", "inv-001")
            .with_upstream(make_invoice_decision("PO-12345", 135_000));
        let d = agent.process(ctx).await.unwrap();
        let r: PoMatchResult = serde_json::from_value(d.payload).unwrap();
        assert!(r.matched);
        assert_eq!(r.delta_pct, Some(200.0)); // 3x → +200%
    }

    #[tokio::test]
    async fn phantom_po_returns_unmatched() {
        let agent = PoMatcher::new(db_with_po());
        let ctx = AgentContext::new("stark", "inv-001")
            .with_upstream(make_invoice_decision("PO-NONEXISTENT", 1000));
        let d = agent.process(ctx).await.unwrap();
        let r: PoMatchResult = serde_json::from_value(d.payload).unwrap();
        assert!(!r.matched);
        assert_eq!(r.expected_amount_cents, None);
    }

    #[tokio::test]
    async fn zero_amount_edge_case_does_not_divide_by_zero() {
        // PO with expected_amount_cents = 0 → delta_pct = 0 (no
        // division by zero). Defensive against pathological DB
        // entries.
        let mut db = HashMap::new();
        db.insert(
            "PO-0".to_string(),
            PurchaseOrder {
                po_ref: "PO-0".to_string(),
                expected_amount_cents: 0,
                vendor: "Zero Inc".to_string(),
            },
        );
        let agent = PoMatcher::new(db);
        let ctx = AgentContext::new("stark", "inv-001")
            .with_upstream(make_invoice_decision("PO-0", 1000));
        let d = agent.process(ctx).await.unwrap();
        let r: PoMatchResult = serde_json::from_value(d.payload).unwrap();
        assert!(r.matched);
        assert_eq!(r.delta_pct, Some(0.0));
    }

    #[tokio::test]
    async fn missing_upstream_extractor_returns_invalid_input() {
        let agent = PoMatcher::new(db_with_po());
        let ctx = AgentContext::new("stark", "inv-001");
        let err = agent.process(ctx).await.unwrap_err();
        assert!(matches!(err, AgentError::InvalidInput(_)));
    }
}
