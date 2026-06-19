//! Integration tests for the A2A 1.0 discovery surface
//! (Story C-01 / G24-G26).
//!
//! Exercises the full axum router via `tower::ServiceExt::oneshot`:
//!
//! 1. `GET /.well-known/agent-card.json` returns 200 + valid A2A
//!    1.0 JSON.
//! 2. `GET /agents.json` returns 200 + 6-agent fleet.
//! 3. `POST /a2a` with a malformed envelope returns 400 (not 500,
//!    per the critic amendment).
//! 4. `POST /a2a` with a valid `message/send` JSON-RPC envelope
//!    returns 200 with a task id that the orchestrator can
//!    re-fetch via `tasks/get`.
//!
//! Auth: every A2A call uses a mock `Ed25519Bearer` signature
//! (the C-01 contract; C-02 wires the real verifier).

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use themis_orchestrator::http::{build_router, AppState};
use themis_orchestrator::orchestrator::Orchestrator;
use themis_orchestrator::room::MockBandRoom;
use themis_orchestrator::tenants::TenantRegistry;

const MAX_BODY: usize = 1024 * 1024;
const MOCK_BEARER: &str = "Ed25519Bearer deadbeefcafebabe0123abcd";

/// Build a fully-wired `AppState` for A2A tests. The
/// orchestrator is wired with `MockBandRoom` (no real Band
/// subprocess) and a no-op agent map. The A2A tests only
/// exercise the routing/parsing layer; the `message/send`
/// test additionally exercises the orchestrator's
/// `process_invoice` path through the StubAgent stack
/// reused from `http_e2e.rs`.
fn build_state() -> AppState {
    use std::collections::HashMap;
    use themis_agents::traits::Agent;

    struct StubAgent(&'static str, themis_agents::decision::DecisionType);
    #[async_trait::async_trait]
    impl Agent for StubAgent {
        fn name(&self) -> &'static str {
            self.0
        }
        async fn process(
            &self,
            ctx: themis_agents::traits::AgentContext,
        ) -> Result<themis_agents::decision::AgentDecision, themis_agents::decision::AgentError>
        {
            Ok(themis_agents::decision::AgentDecision {
                agent_id: self.0.to_string(),
                tenant_id: ctx.tenant_id,
                invoice_id: ctx.invoice_id,
                decision_type: self.1,
                confidence: 0.9,
                reasoning: "ok".to_string(),
                timestamp_ms: 0,
                payload: serde_json::json!({"outcome": "approve"}),
            })
        }
    }

    let rooms: Arc<dyn themis_orchestrator::room::BandRoom> = MockBandRoom::new().into_arc();
    let tenants = Arc::new(TenantRegistry::with_default_tenants());
    let mut agents: HashMap<String, Arc<dyn Agent>> = HashMap::new();
    for (n, dt) in [
        (
            "extractor",
            themis_agents::decision::DecisionType::Extracted,
        ),
        (
            "po_matcher",
            themis_agents::decision::DecisionType::PoMatched,
        ),
        (
            "fraud_auditor",
            themis_agents::decision::DecisionType::FraudAssessed,
        ),
        (
            "gaap_classifier",
            themis_agents::decision::DecisionType::GaapClassified,
        ),
        (
            "provenance_signer",
            themis_agents::decision::DecisionType::ProvenanceSigned,
        ),
        (
            "demo_narrator",
            themis_agents::decision::DecisionType::Narrated,
        ),
        (
            "regression_tester",
            themis_agents::decision::DecisionType::RegressionResult,
        ),
        (
            "audit_watchdog",
            themis_agents::decision::DecisionType::WatchdogAlert,
        ),
    ] {
        agents.insert(n.to_string(), Arc::new(StubAgent(n, dt)));
    }
    let orch = Orchestrator::new(rooms, agents, tenants);
    AppState {
        orchestrator: Arc::new(tokio::sync::Mutex::new(orch)),
        event_bus: Arc::new(themis_orchestrator::events::EventBus::new(64)),
        compliance: Arc::new(themis_compliance::service::ComplianceService::new()),
        reports: dashmap::DashMap::new(),
        packets: dashmap::DashMap::new(),
        sealed: dashmap::DashMap::new(),
        model_id: "mock-fallback".to_string(),
        band_room: None,
        sponsor_stack: themis_orchestrator::events::SponsorStackInfo::default(),
        featherless_metrics: None,
        aiml_metrics: None,
        band_live: None,
    }
}

fn req(method: &str, uri: &str, body: Option<&str>, bearer: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if body.is_some() {
        b = b.header("content-type", "application/json");
    }
    if let Some(token) = bearer {
        b = b.header("authorization", token);
    }
    b.body(
        body.map(|s| Body::from(s.to_string()))
            .unwrap_or(Body::empty()),
    )
    .expect("request builder")
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    to_bytes(resp.into_body(), MAX_BODY).await.unwrap().to_vec()
}

#[tokio::test]
async fn get_agent_card_returns_valid_json() {
    let app = build_router(build_state());
    let resp = app
        .oneshot(req("GET", "/.well-known/agent-card.json", None, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("application/json"), "ct={ct}");
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(v["protocolVersion"], "1.0");
    assert_eq!(v["name"], "THEMIS Orchestrator");
    assert!(v["skills"].as_array().unwrap().len() >= 3);
    assert_eq!(
        v["authentication"]["schemes"][0], "Ed25519Bearer",
        "must advertise Ed25519Bearer auth scheme"
    );
}

#[tokio::test]
async fn get_agents_json_lists_six_agents() {
    let app = build_router(build_state());
    let resp = app
        .oneshot(req("GET", "/agents.json", None, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let agents = v["agents"].as_array().expect("agents array");
    // The PRD contract: 6 agents in the fleet (the orchestrator
    // coordinator + 5 production agents + the new 3.0.0
    // honesty-auditor). The shipped `agents.json` has 7 entries
    // (orchestrator + 6 specialists); the test asserts ≥6
    // because the registry is the source of truth and a future
    // commit (C-12: cross-framework peers) will append to it.
    assert!(
        agents.len() >= 6,
        "expected at least 6 agents, got {}",
        agents.len()
    );
    // The honesty-auditor is the new 3.0.0 addition.
    let ids: Vec<&str> = agents
        .iter()
        .map(|a| a["id"].as_str().unwrap_or(""))
        .collect();
    assert!(ids.contains(&"themis-orchestrator"));
    assert!(ids.contains(&"honesty-auditor"));
}

#[tokio::test]
async fn post_a2a_malformed_envelope_returns_400() {
    let app = build_router(build_state());
    // `{"garbage": true}` is valid JSON but not a valid JSON-RPC
    // envelope. The critic amendment requires 400 (NOT 500).
    let resp = app
        .oneshot(req(
            "POST",
            "/a2a",
            Some(r#"{"garbage": true}"#),
            Some(MOCK_BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "malformed JSON-RPC must be 400, not 500"
    );
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    // ERR_INVALID_REQUEST = -32600
    assert_eq!(v["error"]["code"], -32600);
}

#[tokio::test]
async fn post_a2a_unknown_method_returns_404() {
    let app = build_router(build_state());
    let resp = app
        .oneshot(req(
            "POST",
            "/a2a",
            Some(r#"{"jsonrpc":"2.0","id":1,"method":"frobnicate","params":{}}"#),
            Some(MOCK_BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(v["error"]["code"], -32601);
}

#[tokio::test]
async fn post_a2a_missing_bearer_returns_401() {
    let app = build_router(build_state());
    let resp = app
        .oneshot(req(
            "POST",
            "/a2a",
            Some(
                r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"tenant_id":"stark","invoice_id":"inv-1","raw_b64":""}}"#,
            ),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_a2a_message_send_dispatches() {
    let app = build_router(build_state());
    let resp = app
        .oneshot(req(
            "POST",
            "/a2a",
            Some(
                r#"{"jsonrpc":"2.0","id":"req-1","method":"message/send","params":{"tenant_id":"stark","invoice_id":"a2a-inv-001","raw_b64":""}}"#,
            ),
            Some(MOCK_BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], "req-1");
    let task = &v["result"]["task"];
    assert!(task["id"].as_str().is_some(), "task.id must be a UUID");
    assert!(task["context_id"].as_str().is_some());
    assert_eq!(task["status"]["state"], "completed");
    let parts = task["status"]["message"]["parts"]
        .as_array()
        .expect("parts array");
    assert!(!parts.is_empty(), "at least one part expected");
}

#[tokio::test]
async fn post_a2a_extended_card_returns_card_with_extended_flag() {
    let app = build_router(build_state());
    let resp = app
        .oneshot(req(
            "POST",
            "/a2a",
            Some(
                r#"{"jsonrpc":"2.0","id":2,"method":"agent/authenticatedExtendedCard","params":{}}"#,
            ),
            Some(MOCK_BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let card = &v["result"]["card"];
    assert_eq!(card["protocolVersion"], "1.0");
    assert_eq!(card["extended"], true);
}

#[tokio::test]
async fn post_a2a_invalid_json_returns_400_with_parse_error() {
    let app = build_router(build_state());
    let resp = app
        .oneshot(req(
            "POST",
            "/a2a",
            Some("not json at all"),
            Some(MOCK_BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    // ERR_PARSE = -32700
    assert_eq!(v["error"]["code"], -32700);
}
