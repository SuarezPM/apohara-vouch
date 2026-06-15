//! Test support utilities shared by the demo_data_loads integration
//! test and the themis-bench binary.
//!
//! Centralizes:
//! - `expected_outcome_string(fixture) → "halt_*" | "approve"`
//! - `fraud_auditor_payload(...) → JSON string for the mock LLM`
//! - `LlmStubAgent` (LLM-mediated Agent impl that decodes the mock
//!   response and re-emits it as an AgentDecision)
//! - `DemoInvoice` / `ExtractedInvoice` / `LineItem` /
//!   `FraudAssessmentShape` (the deserializable fixture shapes)
//!
//! Not part of the public API; only used by `#[cfg(test)]` modules
//! and the bench binary. The `orchestrator.rs` test module uses a
//! different (non-LLM) `StubAgent` and is not consolidated here.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::orchestrator::Orchestrator;
use crate::room::MockBandRoom;
use crate::tenants::TenantRegistry;
use serde::{Deserialize, Serialize};
use themis_agents::decision::{AgentDecision, AgentError, DecisionType};
use themis_agents::llm::{LlmBackend, LlmRequest, LlmResponse, MockLlmProvider};
use themis_agents::traits::{Agent, AgentContext};
use themis_evidence::rekor::RekorClient;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DemoInvoice {
    pub invoice_id: String,
    pub tenant_id: String,
    pub expected_verdict: String,
    #[serde(default)]
    pub expected_halt_reason: String,
    #[serde(default)]
    pub halt_reason_human: Option<String>,
    pub extracted: ExtractedInvoice,
    pub fraud_assessment: FraudAssessmentShape,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtractedInvoice {
    pub vendor: String,
    pub vendor_tax_id: String,
    pub amount_cents: i64,
    pub line_items: Vec<LineItem>,
    pub date_iso: String,
    pub po_ref: String,
    #[serde(default = "default_currency")]
    pub currency: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LineItem {
    pub description: String,
    pub amount_cents: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FraudAssessmentShape {
    pub risk_score: f32,
    pub coherence_score: f32,
    pub debate_rounds: u32,
    #[serde(default)]
    pub explicit_halt: bool,
    #[serde(default)]
    pub secret_leak: bool,
}

fn default_currency() -> String {
    "USD".to_string()
}

/// Map a fixture's expected verdict + halt reason to the orchestrator's
/// outcome string (see `orchestrator.rs` halt_* arms).
pub fn expected_outcome_string(f: &DemoInvoice) -> &'static str {
    match f.expected_verdict.as_str() {
        "APPROVED" => "approve",
        "HALT" => match f.expected_halt_reason.as_str() {
            "risk_score_exceeded" => "halt_risk_score_exceeded",
            "secret_leak_detected" => "halt_secret_leak_detected",
            "coherence_too_low" => "halt_coherence_too_low",
            "max_debate_rounds_reached" => "halt_max_debate_rounds_reached",
            "explicit_halt_requested" => "halt_explicit_halt_requested",
            other => panic!("unknown halt_reason in fixture: {other}"),
        },
        other => panic!("unknown expected_verdict: {other}"),
    }
}

/// Build the `FraudAuditorOutput` JSON the mock LLM should return.
/// This is the typed contract the orchestrator parses (see
/// `orchestrator.rs` lines 218-240). The `kind` of the finding
/// is derived from `expected_halt_reason` (the canonical "what
/// should the gate halt on" signal), not from a fragile bool,
/// because the `BaaarGate::check` reads the findings array
/// directly — a wrong kind here means the gate never halts.
pub fn fraud_auditor_payload(f: &DemoInvoice) -> String {
    let finding_kind = match f.expected_halt_reason.as_str() {
        "secret_leak_detected" => "secret_leak",
        "risk_score_exceeded" => "price_anomaly",
        "coherence_too_low" => "duplicate",
        "max_debate_rounds_reached" => "math_fraud",
        "explicit_halt_requested" => "phantom_vendor",
        _ => "other",
    };
    serde_json::json!({
        "assessment": {
            "risk_score": f.fraud_assessment.risk_score,
            "findings": [{
                "kind": finding_kind,
                "value": "fixture",
                "description": f.halt_reason_human.clone().unwrap_or_default(),
            }],
            "coherence_score": f.fraud_assessment.coherence_score,
            "debate_rounds": f.fraud_assessment.debate_rounds,
            "explicit_halt": f.fraud_assessment.explicit_halt,
        },
        "outcome": expected_outcome_string(f),
    })
    .to_string()
}

/// Default response for non-extractor/non-fraud_auditor agents
/// (po_matcher, gaap_classifier, etc.) — minimal valid JSON the
/// StubAgent can parse.
pub fn stub_default_response(model_id: &str) -> LlmResponse {
    LlmResponse {
        text: serde_json::json!({"stub": "ok"}).to_string(),
        input_tokens: 64,
        output_tokens: 32,
        model_id: model_id.to_string(),
    }
}

/// Path to the 5 demo invoice fixtures at the repo root.
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .join("fixtures")
        .join("demo-invoices")
}

/// LLM-mediated StubAgent. Delegates every `process()` call to the
/// mock LLM and re-emits the response as an `AgentDecision`. The
/// optional `input_token_counter` is bumped on each LLM call (used
/// by the bench to measure token economy).
pub struct LlmStubAgent {
    pub name: &'static str,
    pub llm: Arc<dyn LlmBackend>,
    pub input_token_counter: Option<Arc<AtomicU32>>,
}

#[async_trait::async_trait]
impl Agent for LlmStubAgent {
    fn name(&self) -> &'static str {
        self.name
    }
    async fn process(&self, ctx: AgentContext) -> Result<AgentDecision, AgentError> {
        let (system_prompt, user_prompt) = if self.name == "fraud_auditor" {
            (
                "fraud_auditor_agent".to_string(),
                format!(
                    "assess_fraud_risk:upstream_decisions={}",
                    ctx.upstream_decisions.len()
                ),
            )
        } else if self.name == "extractor" {
            (
                "extractor_agent".to_string(),
                format!("parse_invoice:{}:{}", ctx.tenant_id, ctx.invoice_id),
            )
        } else {
            (
                format!("{}_agent", self.name),
                format!("upstream_decisions={}", ctx.upstream_decisions.len()),
            )
        };

        let req = LlmRequest {
            system_prompt,
            user_prompt,
            max_tokens: 1024,
            temperature: 0.0,
            seed: Some(42),
        };
        let resp = self.llm.complete(req).await?;
        if let Some(counter) = &self.input_token_counter {
            counter.fetch_add(resp.input_tokens, Ordering::SeqCst);
        }
        let parsed: serde_json::Value = serde_json::from_str(&resp.text)
            .map_err(|e| AgentError::LlmMalformedPayload(e.to_string()))?;
        let decision_type = match self.name {
            "extractor" => DecisionType::Extracted,
            "po_matcher" => DecisionType::PoMatched,
            "fraud_auditor" => DecisionType::FraudAssessed,
            "gaap_classifier" => DecisionType::GaapClassified,
            "provenance_signer" => DecisionType::ProvenanceSigned,
            "demo_narrator" => DecisionType::Narrated,
            "regression_tester" => DecisionType::RegressionResult,
            "audit_watchdog" => DecisionType::WatchdogAlert,
            _ => unreachable!(),
        };
        Ok(AgentDecision {
            agent_id: self.name.to_string(),
            tenant_id: ctx.tenant_id,
            invoice_id: ctx.invoice_id,
            decision_type,
            confidence: 0.9,
            reasoning: format!("{} stub: ok", self.name),
            timestamp_ms: 0,
            payload: parsed,
        })
    }
}

/// Build the standard 8-agent HashMap wired to a mock LLM. Used by
/// both the integration test and the bench binary. If `counter` is
/// `Some`, all 8 agents bump it on every LLM call.
#[allow(unused_variables)]
pub fn build_stub_agents(
    mock_llm: Arc<dyn LlmBackend>,
    counter: Option<Arc<AtomicU32>>,
) -> HashMap<String, Arc<dyn Agent>> {
    let names = [
        "extractor",
        "po_matcher",
        "fraud_auditor",
        "gaap_classifier",
        "provenance_signer",
        "demo_narrator",
        "regression_tester",
        "audit_watchdog",
    ];
    let mut agents: HashMap<String, Arc<dyn Agent>> = HashMap::new();
    for name in names {
        agents.insert(
            name.to_string(),
            Arc::new(LlmStubAgent {
                name,
                llm: mock_llm.clone(),
                input_token_counter: counter.clone(),
            }),
        );
    }
    agents
}

/// Build a fully-wired orchestrator with the 5-fixture mock LLM
/// and an optional Rekor client. Centralized for the integration
/// test (`tests/demo_data_loads.rs`) and the bench binary.
pub fn build_orchestrator(
    f: &DemoInvoice,
    counter: Option<Arc<AtomicU32>>,
    rekor: Option<Arc<dyn RekorClient>>,
) -> Orchestrator {
    let mock_llm: Arc<dyn LlmBackend> = Arc::new(
        MockLlmProvider::new("mock-test")
            .with_response(
                &f.invoice_id,
                LlmResponse {
                    text: serde_json::to_string(&f.extracted).unwrap(),
                    input_tokens: 256,
                    output_tokens: 128,
                    model_id: "mock-test".to_string(),
                },
            )
            .with_response(
                "assess_fraud_risk",
                LlmResponse {
                    text: fraud_auditor_payload(f),
                    input_tokens: 256,
                    output_tokens: 64,
                    model_id: "mock-test".to_string(),
                },
            )
            .with_default(stub_default_response("mock-test")),
    );
    let agents = build_stub_agents(mock_llm, counter);
    let rooms: Arc<dyn crate::room::BandRoom> = MockBandRoom::new().into_arc();
    let tenants = Arc::new(TenantRegistry::with_default_tenants());
    let router = crate::router::LlmBackendRouter::with_default_routing(HashMap::new());
    Orchestrator::new_with_rekor(rooms, agents, router, tenants, rekor)
}
