//! Extractor agent — parses raw invoice bytes into a structured JSON
//! representation via the LLM.
//!
//! The agent is deliberately small: the prompt is the contract. The
//! LLM is told to respond with a JSON object matching the
//! `ExtractedInvoice` shape; if the response is not valid JSON or
//! is missing a required field, we return `LlmMalformedPayload` and
//! the BAAAR gate fails closed (HALT).

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::decision::{AgentDecision, AgentError, DecisionType};
use crate::llm::{LlmBackend, LlmRequest};
use crate::traits::{Agent, AgentContext};

/// Structured invoice extracted from raw bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractedInvoice {
    /// Vendor name as it appears on the invoice.
    pub vendor: String,
    /// Total amount in cents (integer — avoid float rounding).
    pub amount_cents: i64,
    /// Line items (each with description + amount).
    pub line_items: Vec<LineItem>,
    /// ISO 8601 invoice date.
    pub date_iso: String,
    /// PO reference (e.g. "PO-12345"); empty if no PO.
    pub po_ref: String,
}

/// A single line item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineItem {
    /// Item description.
    pub description: String,
    /// Item amount in cents.
    pub amount_cents: i64,
}

/// The Extractor agent.
pub struct ExtractorAgent {
    llm: Arc<dyn LlmBackend>,
}

impl ExtractorAgent {
    /// New Extractor backed by the given LLM.
    pub fn new(llm: Arc<dyn LlmBackend>) -> Self {
        Self { llm }
    }
}

#[async_trait]
impl Agent for ExtractorAgent {
    fn name(&self) -> &'static str {
        "extractor"
    }

    async fn process(&self, ctx: AgentContext) -> Result<AgentDecision, AgentError> {
        if ctx.raw_invoice.is_empty() {
            return Err(AgentError::InvalidInput(
                "Extractor: raw_invoice is empty".to_string(),
            ));
        }

        let system_prompt = EXTRACTOR_SYSTEM_PROMPT.to_string();
        let user_prompt = format!(
            "Parse this {} invoice ({} bytes) and respond with the JSON object:\n\n{:?}",
            ctx.content_type,
            ctx.raw_invoice.len(),
            String::from_utf8_lossy(&ctx.raw_invoice[..ctx.raw_invoice.len().min(2048)])
        );

        let req = LlmRequest {
            system_prompt,
            user_prompt,
            max_tokens: 2048,
            temperature: 0.0, // deterministic for the JSON contract
            seed: Some(42),
            response_schema: Some(extracted_invoice_schema()),
            response_schema_name: Some("ExtractedInvoice"),
        };

        let resp = self.llm.complete(req).await?;

        // The LLM may wrap the JSON in ```json ... ``` fences. Strip
        // them so serde_json can parse.
        let cleaned = strip_code_fences(&resp.text);

        let parsed: ExtractedInvoice = serde_json::from_str(&cleaned).map_err(|e| {
            AgentError::LlmMalformedPayload(format!(
                "Extractor: response is not valid ExtractedInvoice JSON: {e}; raw={:?}",
                &resp.text[..resp.text.len().min(200)]
            ))
        })?;

        // Validate required fields are non-empty (LLM may return
        // empty strings for fields it doesn't recognize).
        if parsed.vendor.is_empty() {
            return Err(AgentError::LlmMalformedPayload(
                "Extractor: 'vendor' is empty".to_string(),
            ));
        }
        if parsed.amount_cents <= 0 {
            return Err(AgentError::LlmMalformedPayload(format!(
                "Extractor: 'amount_cents' must be positive, got {}",
                parsed.amount_cents
            )));
        }

        Ok(AgentDecision {
            agent_id: self.name().to_string(),
            tenant_id: ctx.tenant_id,
            invoice_id: ctx.invoice_id,
            decision_type: DecisionType::Extracted,
            confidence: 0.9,
            reasoning: format!(
                "Extracted invoice from {} (vendor={}, amount_cents={}, {} line items)",
                ctx.content_type,
                parsed.vendor,
                parsed.amount_cents,
                parsed.line_items.len()
            ),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            payload: serde_json::to_value(&parsed)
                .map_err(|e| AgentError::Internal(format!("Extractor: serialize payload: {e}")))?,
        })
    }
}

const EXTRACTOR_SYSTEM_PROMPT: &str = "\
You are the Extractor agent in THEMIS, a multi-agent AP invoice fraud \
detection system. Given a raw invoice (PDF text, image OCR, or JSON), \
respond with a single JSON object matching this schema exactly:

{
  \"vendor\": \"string (non-empty)\",
  \"amount_cents\": integer (positive, total in cents),
  \"line_items\": [{\"description\": \"string\", \"amount_cents\": integer}],
  \"date_iso\": \"string (ISO 8601)\",
  \"po_ref\": \"string (PO reference; empty if none)\"
}

Respond with ONLY the JSON object. No commentary, no markdown fences.";

/// JSON schema for `ExtractedInvoice`, sent to the LLM via OpenAI's
/// `response_format.json_schema` (constrained decoding). Mirrors the
/// Rust `ExtractedInvoice` struct.
pub fn extracted_invoice_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "vendor": {"type": "string", "minLength": 1},
            "amount_cents": {"type": "integer", "minimum": 0},
            "line_items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "description": {"type": "string"},
                        "amount_cents": {"type": "integer", "minimum": 0}
                    },
                    "required": ["description", "amount_cents"]
                }
            },
            "date_iso": {"type": "string"},
            "po_ref": {"type": "string"}
        },
        "required": ["vendor", "amount_cents", "line_items", "date_iso", "po_ref"]
    })
}

/// Strip ```json ... ``` fences (and stray ``` blocks) from LLM
/// output. Tolerant of whitespace.
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

    fn good_invoice_json() -> String {
        serde_json::json!({
            "vendor": "Acme Corp",
            "amount_cents": 45000,
            "line_items": [
                {"description": "Widget", "amount_cents": 25000},
                {"description": "Service", "amount_cents": 20000}
            ],
            "date_iso": "2026-06-01",
            "po_ref": "PO-12345"
        })
        .to_string()
    }

    #[tokio::test]
    async fn happy_path_returns_extracted_decision() {
        let mock = MockLlmProvider::new("mock").with_response(
            "Parse this",
            LlmResponse {
                text: good_invoice_json(),
                input_tokens: 100,
                output_tokens: 200,
                model_id: "mock".to_string(),
                finish_reason: crate::llm::FinishReason::Stop,
            }        );
        let agent = ExtractorAgent::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001")
            .with_raw_invoice(b"raw invoice bytes".to_vec(), "application/pdf");
        let decision = agent.process(ctx).await.unwrap();
        assert_eq!(decision.decision_type, DecisionType::Extracted);
        assert_eq!(decision.agent_id, "extractor");
        assert_eq!(decision.tenant_id, "stark");
        assert_eq!(decision.invoice_id, "inv-001");
        assert_eq!(decision.payload["vendor"], "Acme Corp");
        assert_eq!(decision.payload["amount_cents"], 45_000);
    }

    #[tokio::test]
    async fn empty_invoice_returns_invalid_input() {
        let mock = MockLlmProvider::new("mock");
        let agent = ExtractorAgent::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001");
        let err = agent.process(ctx).await.unwrap_err();
        assert!(matches!(err, AgentError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn malformed_json_returns_malformed_payload() {
        let mock = MockLlmProvider::new("mock").with_response(
            "Parse this",
            LlmResponse {
                text: "this is not json".to_string(),
                input_tokens: 100,
                output_tokens: 50,
                model_id: "mock".to_string(),
                finish_reason: crate::llm::FinishReason::Stop,
            }        );
        let agent = ExtractorAgent::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001")
            .with_raw_invoice(b"bytes".to_vec(), "application/pdf");
        let err = agent.process(ctx).await.unwrap_err();
        assert!(matches!(err, AgentError::LlmMalformedPayload(_)));
    }

    #[tokio::test]
    async fn empty_vendor_returns_malformed_payload() {
        let bad = serde_json::json!({
            "vendor": "",
            "amount_cents": 1000,
            "line_items": [],
            "date_iso": "2026-06-01",
            "po_ref": ""
        })
        .to_string();
        let mock = MockLlmProvider::new("mock").with_response(
            "Parse this",
            LlmResponse {
                text: bad,
                input_tokens: 50,
                output_tokens: 50,
                model_id: "mock".to_string(),
                finish_reason: crate::llm::FinishReason::Stop,
            }        );
        let agent = ExtractorAgent::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001")
            .with_raw_invoice(b"bytes".to_vec(), "application/pdf");
        let err = agent.process(ctx).await.unwrap_err();
        assert!(matches!(err, AgentError::LlmMalformedPayload(_)));
    }

    #[tokio::test]
    async fn zero_amount_returns_malformed_payload() {
        let bad = serde_json::json!({
            "vendor": "Acme",
            "amount_cents": 0,
            "line_items": [],
            "date_iso": "2026-06-01",
            "po_ref": "PO-1"
        })
        .to_string();
        let mock = MockLlmProvider::new("mock").with_response(
            "Parse this",
            LlmResponse {
                text: bad,
                input_tokens: 50,
                output_tokens: 50,
                model_id: "mock".to_string(),
                finish_reason: crate::llm::FinishReason::Stop,
            }        );
        let agent = ExtractorAgent::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001")
            .with_raw_invoice(b"bytes".to_vec(), "application/pdf");
        let err = agent.process(ctx).await.unwrap_err();
        assert!(matches!(err, AgentError::LlmMalformedPayload(_)));
    }

    #[tokio::test]
    async fn rate_limit_propagates_without_coercion() {
        // with_rate_limit_after(0) means rate-limit the FIRST call.
        let mock = MockLlmProvider::new("mock")
            .with_response(
                "Parse this",
                LlmResponse {
                    text: good_invoice_json(),
                    input_tokens: 100,
                    output_tokens: 200,
                    model_id: "mock".to_string(),
                finish_reason: crate::llm::FinishReason::Stop,
            }            )
            .with_rate_limit_after(0);
        let agent = ExtractorAgent::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001")
            .with_raw_invoice(b"bytes".to_vec(), "application/pdf");
        let err = agent.process(ctx).await.unwrap_err();
        assert!(matches!(err, AgentError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn json_fences_are_stripped_before_parsing() {
        let fenced = format!("```json\n{}\n```", good_invoice_json());
        let mock = MockLlmProvider::new("mock").with_response(
            "Parse this",
            LlmResponse {
                text: fenced,
                input_tokens: 100,
                output_tokens: 200,
                model_id: "mock".to_string(),
                finish_reason: crate::llm::FinishReason::Stop,
            }        );
        let agent = ExtractorAgent::new(Arc::new(mock));
        let ctx = AgentContext::new("stark", "inv-001")
            .with_raw_invoice(b"bytes".to_vec(), "application/pdf");
        let decision = agent.process(ctx).await.unwrap();
        assert_eq!(decision.payload["vendor"], "Acme Corp");
    }
}
