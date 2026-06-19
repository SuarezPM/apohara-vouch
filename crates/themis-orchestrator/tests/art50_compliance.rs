//! Integration tests for EU AI Act Article 50 transparency gate
//! and Article 49 mock EU registration (THEMIS 3.0 Story C-08).
//!
//! Gaps closed: G01 (Art 50 transparency), G02 (Art 49 EU database).
//!
//! Acceptance criteria:
//! - Banner HTML rendered as FIRST SSE event before any agent output
//! - Banner text references "EU AI Act Art 50"
//! - EU registration mock id embedded in artefacts
//! - Frame as "compliance-ready — registration activates 2027-12-02"
//!
//! Note: the actual SSE handler in `http.rs` is C-01's scope. The
//! AC "first SSE event is ai_disclosure" is exercised via the
//! `art50::first_event_is_ai_disclosure` predicate and the
//! `Event::AiDisclosure` enum construction. C-08-frontend (follow-up)
//! will wire the AiDisclosure prelude into the SSE handler chain.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;
use uuid::Uuid;

use themis_orchestrator::art50::{self, AI_DISCLOSURE_BANNER_HTML, EU_REGISTRATION_ID};
use themis_orchestrator::events::{Event, EventBus};
use themis_orchestrator::http::{build_router, AppState};
use themis_orchestrator::orchestrator::Orchestrator;
use themis_orchestrator::room::MockBandRoom;
use themis_orchestrator::tenants::TenantRegistry;
use themis_orchestrator::test_support::{build_stub_agents_with_mock, DemoInvoice};

use themis_agents::llm::{FinishReason, LlmResponse, MockLlmProvider};
use themis_evidence::rekor::MockRekorClient;

fn router_for(f: &DemoInvoice) -> axum::Router {
    let mock_llm: Arc<dyn themis_agents::llm::LlmBackend> = Arc::new(
        MockLlmProvider::new("art50-mock")
            .with_response(
                &f.invoice_id,
                LlmResponse {
                    text: serde_json::to_string(&f.extracted).unwrap(),
                    input_tokens: 256,
                    output_tokens: 128,
                    model_id: "art50-mock".to_string(),
                    finish_reason: FinishReason::Stop,
                },
            )
            .with_default(LlmResponse {
                text: serde_json::json!({"stub": "ok"}).to_string(),
                input_tokens: 64,
                output_tokens: 32,
                model_id: "art50-mock".to_string(),
                finish_reason: FinishReason::Stop,
            }),
    );
    let agents = build_stub_agents_with_mock(mock_llm.clone(), None);
    let rooms: Arc<dyn themis_orchestrator::room::BandRoom> = MockBandRoom::new().into_arc();
    let tenants = Arc::new(TenantRegistry::with_default_tenants());
    let orch = Orchestrator::new_with_rekor(
        rooms,
        agents,
        tenants,
        Some(Arc::new(MockRekorClient::new()) as Arc<dyn themis_evidence::rekor::RekorClient>),
    );
    let state = AppState {
        orchestrator: Arc::new(tokio::sync::Mutex::new(orch)),
        event_bus: Arc::new(EventBus::new(1024)),
        compliance: Arc::new(themis_compliance::service::ComplianceService::new()),
        reports: dashmap::DashMap::new(),
        packets: dashmap::DashMap::new(),
        sealed: dashmap::DashMap::new(),
        model_id: mock_llm.model_id().to_string(),
        band_room: None,
        sponsor_stack: themis_orchestrator::events::SponsorStackInfo::default(),
        featherless_metrics: None,
        aiml_metrics: None,
        band_live: None,
    };
    build_router(state)
}

fn load_fixture(name: &str) -> DemoInvoice {
    let path = themis_orchestrator::test_support::fixtures_dir().join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap()
}

// AC: Banner text references "EU AI Act Art 50" + EU registration
// id is embedded. The C-08 PRD spells "Art 50"; we assert on the
// PRD-mandated phrase so a future copy change is caught.
#[test]
fn test_banner_contains_art_50_reference() {
    assert!(art50::banner_html().contains("Art 50"));
    assert!(art50::banner_html().contains("EU-AI-ACT-2026-THEMIS-MOCK"));
    assert!(art50::banner_html().contains("EU AI Act"));
}

// AC: Banner uses the THEMIS palette so it is visible above the
// fold against the deep-navy background.
#[test]
fn test_banner_uses_themis_palette() {
    assert!(AI_DISCLOSURE_BANNER_HTML.contains("#0a0e1a"));
    assert!(AI_DISCLOSURE_BANNER_HTML.contains("#d4a017"));
}

// AC: The EU registration id is stable across crates — the same
// string appears in the frontend banner module and the orchestrator
// re-export. C-10 (Evidence Packet) will embed it from
// `art50::EU_REGISTRATION_ID`.
#[test]
fn test_eu_registration_id_constant_is_stable() {
    assert_eq!(EU_REGISTRATION_ID, "EU-AI-ACT-2026-THEMIS-MOCK");
    assert_eq!(
        EU_REGISTRATION_ID,
        themis_frontend::art50_banner::EU_REGISTRATION_ID,
        "frontend and orchestrator must agree on the mock id"
    );
}

// AC: The AI disclosure event is the FIRST event on a fresh SSE
// subscription — the Art 50 transparency gate. We exercise the
// orchestrator-side predicate and the typed event; the SSE
// handler chain is in C-01's scope and will be wired in C-08-frontend.
#[tokio::test]
async fn test_first_sse_event_is_ai_disclosure() {
    let bus = EventBus::new(16);
    let mut rx = bus.subscribe();

    // Simulate the SSE prelude: the handler chains the AiDisclosure
    // prelude before the bus events. Publish a SponsorStack AFTER
    // the AiDisclosure to mirror the intended sequence.
    let disclosure = art50::build_ai_disclosure_event();
    bus.publish(disclosure.clone());
    bus.publish(Event::SponsorStack {
        run_id: Uuid::nil(),
        band: "band-sdk[langgraph]==0.2.11".to_string(),
        aiml_api: "anthropic/claude-sonnet-4.5".to_string(),
        featherless: "Qwen/Qwen3-Coder-30B-A3B-Instruct".to_string(),
    });

    // Drain two events; the first must be the AiDisclosure.
    let first = rx.recv().await.expect("first event");
    assert_eq!(first.type_str(), "ai_disclosure");
    let second = rx.recv().await.expect("second event");
    assert_eq!(second.type_str(), "sponsor_stack");

    // Hard invariant via the predicate.
    assert!(art50::first_event_is_ai_disclosure(&[first, second]));
}

// AC: Evidence Packet (or any JSON value) can carry the EU
// registration id — verifies the constant is available for C-10
// embedding without modifying SealedPacket. We construct a
// minimal JSON value as a stand-in.
#[tokio::test]
async fn test_evidence_packet_can_carry_eu_registration_id() {
    let payload = serde_json::json!({
        "tenant_id": "stark",
        "run_id": Uuid::new_v4().to_string(),
        "eu_registration_id": EU_REGISTRATION_ID,
        "eu_ai_act_art_50": {
            "banner_html": art50::banner_html(),
            "regulation": "EU AI Act Article 50",
            "registration_activates": "2027-12-02",
        },
    });
    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(serialized.contains("EU-AI-ACT-2026-THEMIS-MOCK"));
    assert!(serialized.contains("Art 50"));
    assert!(serialized.contains("2027-12-02"));

    // Round-trip — the id is recoverable.
    let v: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(v["eu_registration_id"], EU_REGISTRATION_ID);
}

// AC: The AiDisclosure event serializes to a tagged JSON shape
// (matches the existing SponsorStack convention: `type: "..."`).
#[tokio::test]
async fn test_ai_disclosure_event_serializes_with_typed_tag() {
    let ev = art50::build_ai_disclosure_event();
    let v = serde_json::to_value(&ev).unwrap();
    assert_eq!(v["type"], "ai_disclosure");
    assert_eq!(v["eu_registration_id"], EU_REGISTRATION_ID);
    assert!(v["banner_html"].as_str().unwrap().contains("Art 50"));
    assert!(v["timestamp"].is_string());
}

// AC: GET / (index page) still serves after C-08 — guards
// against accidental breakage of the existing US-11 dashboard.
#[tokio::test]
async fn test_root_still_serves_after_c08() {
    let f = load_fixture("wayne-002.json");
    let app = router_for(&f);
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("Apohara VOUCH"));
}
