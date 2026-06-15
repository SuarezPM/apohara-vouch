//! `themis-orchestrator` — the production HTTP binary.
//!
//! Wires:
//! - The HTTP layer (axum 0.7, on port 8080 by default, or $PORT)
//! - A `MockRekorClient` for transparency-log anchoring (US-R02)
//! - The 8 demo agents (MockLlmProvider + StubAgents) so the demo
//!   runs end-to-end without real LLM/TSA calls
//! - A `MockBandRoom` (real Band integration is a follow-up
//!   requiring the Python subprocess bridge on a machine with
//!   `band-sdk[langgraph]==0.2.11` installed)
//!
//! Run: `cargo run --release --bin themis-orchestrator`
//!      or deploy via `fly deploy` (uses ./Dockerfile + fly.toml).

use std::collections::HashMap;
use std::sync::Arc;

use themis_agents::llm::MockLlmProvider;
use themis_evidence::rekor::MockRekorClient;
use themis_evidence::timestamp::MockTimestampAuthority;
use themis_orchestrator::http::{build_router, AppState};
use themis_orchestrator::orchestrator::Orchestrator;
use themis_orchestrator::room::MockBandRoom;
use themis_orchestrator::tenants::TenantRegistry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read the listen port from $PORT (Fly sets this; default 8080).
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let bind = format!("0.0.0.0:{port}");

    // Log effective config (no secrets).
    eprintln!("[themis-orchestrator] starting on {bind}");
    eprintln!(
        "[themis-orchestrator] build = {}",
        env!("CARGO_PKG_VERSION")
    );

    // Tenant registry: 2 baked-in tenants (stark, wayne) from
    // TenantRegistry::with_default_tenants(). The Ed25519 pubkeys
    // come from the compile-time baked seeds in themis-evidence.
    let tenants = Arc::new(TenantRegistry::with_default_tenants());

    // Mock LLM (the demo path). A real deployment would wire
    // AnthropicBackend / OpenAiCompatBackend per the LlmBackend
    // router; that's a follow-up requiring the secrets to be set.
    let llm: Arc<dyn themis_agents::llm::LlmBackend> = Arc::new(MockLlmProvider::new("mock-demo"));

    // Build the 8 demo agents (extractor, po_matcher,
    // fraud_auditor, gaap_classifier, provenance_signer,
    // demo_narrator, regression_tester, audit_watchdog). Each
    // agent uses the same mock LLM and returns canned decisions.
    let mut agents: HashMap<String, Arc<dyn themis_agents::traits::Agent>> = HashMap::new();
    for name in [
        "extractor",
        "po_matcher",
        "fraud_auditor",
        "gaap_classifier",
        "provenance_signer",
        "demo_narrator",
        "regression_tester",
        "audit_watchdog",
    ] {
        agents.insert(
            name.to_string(),
            Arc::new(StubAgent {
                name,
                llm: llm.clone(),
            }),
        );
    }

    // Mock Timestamp Authority (real FreeTSA is a follow-up).
    let tsa: Arc<dyn themis_evidence::timestamp::TimestampAuthority> =
        Arc::new(MockTimestampAuthority::new("https://mock.tsa.local"));

    // Build the evidence service for each baked tenant. The
    // orchestrator sels into a per-tenant HashChain so the
    // SealedPacket served by /packets/:id/json carries a
    // monotonically-growing chain_length and themis-verify can
    // replay the chain offline.
    let mut evidence_map: HashMap<String, themis_evidence::packet::EvidenceService> =
        HashMap::new();
    for tenant in ["stark", "wayne"] {
        let svc = themis_evidence::packet::EvidenceService::for_tenant(tenant, tsa.clone())
            .expect("baked tenant must have a key");
        evidence_map.insert(tenant.to_string(), svc);
    }

    // Wire the orchestrator WITH a MockRekorClient + the evidence
    // service map, so every process_invoice run anchors its
    // BLAKE3 hash in the transparency log AND produces a
    // SealedPacket for the /json endpoint.
    let rooms: Arc<dyn themis_orchestrator::room::BandRoom> = MockBandRoom::new().into_arc();
    let router =
        themis_orchestrator::router::LlmBackendRouter::with_default_routing(HashMap::new());
    let orch = Orchestrator::with_evidence(
        rooms,
        agents,
        router,
        tenants,
        Some(Arc::new(MockRekorClient::new()) as Arc<dyn themis_evidence::rekor::RekorClient>),
        evidence_map,
    );

    let state = AppState {
        orchestrator: Arc::new(tokio::sync::Mutex::new(orch)),
        event_bus: Arc::new(themis_orchestrator::events::EventBus::new(1024)),
        compliance: Arc::new(themis_compliance::service::ComplianceService::new()),
        reports: dashmap::DashMap::new(),
        packets: dashmap::DashMap::new(),
        sealed: dashmap::DashMap::new(),
    };

    // Touch tsa so the unused-warning stays out of release builds
    // (the orchestrator currently doesn't stamp packets, but
    // the timestamp authority will be wired into EvidenceService
    // in a follow-up sprint).
    drop(tsa);

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("[themis-orchestrator] listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Minimal stub agent that returns a canned decision for every
/// request. Real agent implementations live in themis-agents and
/// are wired by the test_support::build_stub_agents helper; this
/// inline copy is for the production binary where the agents are
/// placeholders pending the real LLM wiring.
struct StubAgent {
    name: &'static str,
    #[allow(dead_code)]
    llm: Arc<dyn themis_agents::llm::LlmBackend>,
}

#[async_trait::async_trait]
impl themis_agents::traits::Agent for StubAgent {
    fn name(&self) -> &'static str {
        self.name
    }
    async fn process(
        &self,
        ctx: themis_agents::traits::AgentContext,
    ) -> Result<themis_agents::decision::AgentDecision, themis_agents::decision::AgentError> {
        use themis_agents::decision::{AgentDecision, DecisionType};
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
            payload: serde_json::json!({"outcome": "approve"}),
        })
    }
}
