//! GAAP Classifier — maps invoice line items to a US-GAAP account
//! using an LLM. The taxonomy is a small subset of US-GAAP 2026
//! embedded in the system prompt so the LLM has explicit context
//! (per the FinTagging paper, accuracy drops below 40% without it).

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::decision::{AgentDecision, AgentError, DecisionType};
use crate::extractor::ExtractedInvoice;
use crate::llm::{LlmBackend, LlmRequest};
use crate::traits::{Agent, AgentContext};

/// A single US-GAAP account in the taxonomy subset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GaapAccount {
    /// Account code (e.g. "6100").
    pub code: String,
    /// Account name (e.g. "Operating Expenses").
    pub name: String,
    /// One-line description (goes into the system prompt).
    pub description: String,
    /// Optional parent account code (for hierarchy).
    pub parent_code: Option<String>,
}

/// A small subset of US-GAAP 2026 accounts. Real production loads
/// the full taxonomy from XBRL; for THEMIS we ship a hand-curated
/// subset that covers the demo's 5 invoices.
#[derive(Debug, Clone, Default)]
pub struct UsGaapTaxonomy {
    /// All accounts in this taxonomy.
    pub accounts: Vec<GaapAccount>,
}

impl UsGaapTaxonomy {
    /// Default US-GAAP 2026 subset (operating expense accounts).
    pub fn default_subset() -> Self {
        Self {
            accounts: vec![
                GaapAccount {
                    code: "6100".to_string(),
                    name: "Operating Expenses".to_string(),
                    description: "General operating expenses (rent, utilities, supplies).".to_string(),
                    parent_code: None,
                },
                GaapAccount {
                    code: "6200".to_string(),
                    name: "Cost of Goods Sold".to_string(),
                    description: "Direct costs of producing goods sold.".to_string(),
                    parent_code: None,
                },
                GaapAccount {
                    code: "6300".to_string(),
                    name: "Professional Services".to_string(),
                    description: "Legal, accounting, consulting fees.".to_string(),
                    parent_code: Some("6100".to_string()),
                },
                GaapAccount {
                    code: "6400".to_string(),
                    name: "Travel and Entertainment".to_string(),
                    description: "Travel, meals, client entertainment.".to_string(),
                    parent_code: Some("6100".to_string()),
                },
                GaapAccount {
                    code: "6500".to_string(),
                    name: "Marketing and Advertising".to_string(),
                    description: "Marketing campaigns, advertising spend.".to_string(),
                    parent_code: Some("6100".to_string()),
                },
                GaapAccount {
                    code: "6600".to_string(),
                    name: "Office Supplies".to_string(),
                    description: "Stationery, software licenses, small equipment.".to_string(),
                    parent_code: Some("6100".to_string()),
                },
            ],
        }
    }

    /// Render the taxonomy as a string suitable for the system prompt.
    pub fn to_prompt_string(&self) -> String {
        let mut out = String::from("US-GAAP 2026 Account Codes:\n");
        for a in &self.accounts {
            out.push_str(&format!(
                "- {}: {} — {}\n",
                a.code,
                a.name,
                a.description
            ));
        }
        out
    }
}

/// The classification output for one invoice's line items.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GaapClassification {
    /// GaapVsIfrs marker (always UsGaap for this agent).
    pub framework: GaapFramework,
    /// Mapped account code (must be one of the taxonomy codes).
    pub account_code: String,
    /// Account name (for the Evidence Packet).
    pub account_name: String,
    /// Confidence 0.0..=1.0.
    pub confidence: f32,
    /// Per-line-item classification (parallel to invoice.line_items).
    pub per_line_item: Vec<LineItemClassification>,
}

/// Framework discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GaapFramework {
    /// US-GAAP.
    UsGaap,
    /// (Future) IFRS — not implemented in this sprint.
    Ifrs,
}

/// Per-line-item classification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineItemClassification {
    /// Original line item description.
    pub description: String,
    /// Classified account code.
    pub account_code: String,
}

/// The GAAP Classifier agent.
pub struct GaapClassifier {
    llm: Arc<dyn LlmBackend>,
    taxonomy: UsGaapTaxonomy,
}

impl GaapClassifier {
    /// New classifier with the default US-GAAP 2026 subset.
    pub fn new(llm: Arc<dyn LlmBackend>) -> Self {
        Self {
            llm,
            taxonomy: UsGaapTaxonomy::default_subset(),
        }
    }

    /// Custom taxonomy.
    pub fn with_taxonomy(mut self, taxonomy: UsGaapTaxonomy) -> Self {
        self.taxonomy = taxonomy;
        self
    }
}

#[async_trait]
impl Agent for GaapClassifier {
    fn name(&self) -> &'static str {
        "gaap_classifier"
    }

    async fn process(&self, ctx: AgentContext) -> Result<AgentDecision, AgentError> {
        let extracted_decision = ctx
            .upstream_decisions
            .iter()
            .find(|d| d.decision_type == DecisionType::Extracted)
            .ok_or_else(|| {
                AgentError::InvalidInput(
                    "GAAP Classifier: no Extracted decision in upstream_decisions".to_string(),
                )
            })?;
        let invoice: ExtractedInvoice = serde_json::from_value(extracted_decision.payload.clone())
            .map_err(|e| {
                AgentError::LlmMalformedPayload(format!(
                    "GAAP Classifier: upstream Extracted payload is not ExtractedInvoice: {e}"
                ))
            })?;

        let system_prompt = format!(
            "{}\n{}",
            GAAP_CLASSIFIER_SYSTEM_PROMPT,
            self.taxonomy.to_prompt_string()
        );
        let user_prompt = format!(
            "Classify these line items for invoice from {} ({} items):\n{}",
            invoice.vendor,
            invoice.line_items.len(),
            serde_json::to_string_pretty(&invoice.line_items).unwrap_or_default()
        );

        let req = LlmRequest {
            system_prompt,
            user_prompt,
            max_tokens: 1024,
            temperature: 0.0, // MUST be 0 — GAAP is deterministic
            seed: Some(42),
        };

        let resp = self.llm.complete(req).await?;
        let cleaned = strip_code_fences(&resp.text);

        // The LLM may return one classification or an array. Try the
        // single-object shape first, then the array.
        let classification: GaapClassification = if let Ok(c) =
            serde_json::from_str::<GaapClassification>(&cleaned)
        {
            c
        } else if let Ok(arr) = serde_json::from_str::<Vec<LineItemClassification>>(&cleaned) {
            // Fallback: LLM returned only the per-line-item array.
            GaapClassification {
                framework: GaapFramework::UsGaap,
                account_code: arr.first().map(|l| l.account_code.clone()).unwrap_or_default(),
                account_name: arr
                    .first()
                    .and_then(|l| {
                        self.taxonomy
                            .accounts
                            .iter()
                            .find(|a| a.code == l.account_code)
                            .map(|a| a.name.clone())
                    })
                    .unwrap_or_default(),
                confidence: 0.7,
                per_line_item: arr,
            }
        } else {
            return Err(AgentError::LlmMalformedPayload(format!(
                "GAAP Classifier: response is not GaapClassification or LineItemClassification array; raw={:?}",
                &resp.text[..resp.text.len().min(200)]
            )));
        };

        let reasoning = format!(
            "Classified {} line items into US-GAAP account {} ({})",
            classification.per_line_item.len(),
            classification.account_code,
            classification.account_name
        );

        Ok(AgentDecision {
            agent_id: self.name().to_string(),
            tenant_id: ctx.tenant_id,
            invoice_id: ctx.invoice_id,
            decision_type: DecisionType::GaapClassified,
            confidence: classification.confidence,
            reasoning,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            payload: serde_json::to_value(&classification).map_err(|e| {
                AgentError::Internal(format!("GAAP Classifier: serialize payload: {e}"))
            })?,
        })
    }
}

const GAAP_CLASSIFIER_SYSTEM_PROMPT: &str = "\
You are the GAAP Classifier in THEMIS. Given invoice line items and \
the US-GAAP 2026 taxonomy subset below, classify each line item to \
the most appropriate account code. Respond with a single JSON object:

{
  \"framework\": \"us_gaap\",
  \"account_code\": \"<one of the codes in the taxonomy>\",
  \"account_name\": \"<name from the taxonomy>\",
  \"confidence\": number (0.0..=1.0),
  \"per_line_item\": [{\"description\": \"<original>\", \"account_code\": \"<code>\"}]
}

Use ONLY account codes from the taxonomy. The account_code + account_name \
in the top level should be the dominant classification. Respond with ONLY \
the JSON object, no commentary, no markdown fences.";

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
    use crate::decision::DecisionType;
    use crate::extractor::LineItem;
    use crate::llm::{LlmResponse, MockLlmProvider};

    fn make_invoice_decision() -> AgentDecision {
        let inv = ExtractedInvoice {
            vendor: "Acme Corp".to_string(),
            amount_cents: 45000,
            line_items: vec![
                LineItem {
                    description: "Office supplies".to_string(),
                    amount_cents: 25000,
                },
                LineItem {
                    description: "Consulting fee".to_string(),
                    amount_cents: 20000,
                },
            ],
            date_iso: "2026-06-01".to_string(),
            po_ref: "PO-12345".to_string(),
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
    async fn classify_returns_decision() {
        let good = serde_json::json!({
            "framework": "us_gaap",
            "account_code": "6100",
            "account_name": "Operating Expenses",
            "confidence": 0.85,
            "per_line_item": [
                {"description": "Office supplies", "account_code": "6600"},
                {"description": "Consulting fee", "account_code": "6300"}
            ]
        })
        .to_string();
        let mock = MockLlmProvider::new("mock").with_response(
            "Classify these",
            LlmResponse {
                text: good,
                input_tokens: 200,
                output_tokens: 200,
                model_id: "mock".to_string(),
            },
        );
        let agent = GaapClassifier::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001").with_upstream(make_invoice_decision());
        let d = agent.process(ctx).await.unwrap();
        assert_eq!(d.decision_type, DecisionType::GaapClassified);
        let c: GaapClassification = serde_json::from_value(d.payload).unwrap();
        assert_eq!(c.framework, GaapFramework::UsGaap);
        assert_eq!(c.account_code, "6100");
        assert_eq!(c.per_line_item.len(), 2);
    }

    #[tokio::test]
    async fn missing_upstream_extractor_returns_invalid_input() {
        let mock = MockLlmProvider::new("mock");
        let agent = GaapClassifier::new(Arc::new(mock));
        let err = agent.process(AgentContext::new("stark", "inv-001")).await.unwrap_err();
        assert!(matches!(err, AgentError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn malformed_json_returns_malformed_payload() {
        let mock = MockLlmProvider::new("mock").with_response(
            "Classify these",
            LlmResponse {
                text: "garbage".to_string(),
                input_tokens: 50,
                output_tokens: 50,
                model_id: "mock".to_string(),
            },
        );
        let agent = GaapClassifier::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001").with_upstream(make_invoice_decision());
        let err = agent.process(ctx).await.unwrap_err();
        assert!(matches!(err, AgentError::LlmMalformedPayload(_)));
    }

    #[tokio::test]
    async fn accepts_array_fallback_shape() {
        // LLM returned only the per_line_item array (no envelope).
        let arr = serde_json::json!([
            {"description": "Office supplies", "account_code": "6600"}
        ])
        .to_string();
        let mock = MockLlmProvider::new("mock").with_response(
            "Classify these",
            LlmResponse {
                text: arr,
                input_tokens: 50,
                output_tokens: 50,
                model_id: "mock".to_string(),
            },
        );
        let agent = GaapClassifier::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001").with_upstream(make_invoice_decision());
        let d = agent.process(ctx).await.unwrap();
        let c: GaapClassification = serde_json::from_value(d.payload).unwrap();
        assert_eq!(c.account_code, "6600");
        assert_eq!(c.per_line_item.len(), 1);
    }

    #[test]
    fn default_taxonomy_includes_operating_expense() {
        let t = UsGaapTaxonomy::default_subset();
        assert!(t.accounts.iter().any(|a| a.code == "6100"));
        let prompt = t.to_prompt_string();
        assert!(prompt.contains("6100"));
        assert!(prompt.contains("Operating Expenses"));
    }
}
