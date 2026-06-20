//! Snapshot test for the compliance report JSON shape.
//!
//! This is a **shape** test (not value test) — it locks down the
//! JSON structure returned by `POST /invoices` so a future refactor
//! of the orchestrator (or the 4 mappers in themis-compliance)
//! can't accidentally change the wire format that the Vercel
//! proxy serves to the frontend.
//!
//! If the shape needs to change, regenerate with:
//!   INSTA_UPDATE=auto cargo test -p themis-orchestrator --test snapshot_compliance
//! (or use the `insta` crate's `--review` workflow).
//!
//! PDF rendering used to be tested here too
//! (`pdf_has_six_pages_with_4_buyer_framing`,
//! `pdf_page2_contains_all_26_compliance_field_names`,
//! `pdf_page2_contains_agent_decision_trace`) — those tests plus
//! the `pdf_sample_packet` / `decode_pdf_text` helpers were removed
//! in the audit-remediation pass because they specified a 6-page
//! editorial PDF (US-10 v1) that was deliberately simplified to a
//! single-page evidence receipt in commit `9f4d473`
//! ("feat(pdf): 1-page evidence receipt in Synthex dark style").
//! PDF coverage now lives in `tests/pdf_halt_visual.rs`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

use themis_agents::llm::{LlmResponse, MockLlmProvider};
use themis_evidence::rekor::MockRekorClient;
use themis_orchestrator::http::{build_router, AppState};
use themis_orchestrator::orchestrator::Orchestrator;
use themis_orchestrator::room::MockBandRoom;
use themis_orchestrator::tenants::TenantRegistry;
use themis_orchestrator::test_support::DemoInvoice;

fn router_for(f: &DemoInvoice) -> axum::Router {
    let mock_llm: Arc<dyn themis_agents::llm::LlmBackend> = Arc::new(
        MockLlmProvider::new("snapshot-mock")
            .with_response(
                &f.invoice_id,
                LlmResponse {
                    text: serde_json::to_string(&f.extracted).unwrap(),
                    input_tokens: 256,
                    output_tokens: 128,
                    model_id: "snapshot-mock".to_string(),
                    finish_reason: themis_agents::llm::FinishReason::Stop,
                },
            )
            .with_response(
                "assess_fraud_risk",
                LlmResponse {
                    text: serde_json::json!({
                        "assessment": {
                            "risk_score": f.fraud_assessment.risk_score,
                            "findings": [],
                            "coherence_score": f.fraud_assessment.coherence_score,
                            "debate_rounds": f.fraud_assessment.debate_rounds,
                            "explicit_halt": f.fraud_assessment.explicit_halt,
                        },
                        "outcome": themis_orchestrator::test_support::expected_outcome_string(f),
                    })
                    .to_string(),
                    input_tokens: 256,
                    output_tokens: 64,
                    model_id: "snapshot-mock".to_string(),
                    finish_reason: themis_agents::llm::FinishReason::Stop,
                },
            )
            .with_default(LlmResponse {
                text: serde_json::json!({"stub":"ok"}).to_string(),
                input_tokens: 64,
                output_tokens: 32,
                model_id: "snapshot-mock".to_string(),
                finish_reason: themis_agents::llm::FinishReason::Stop,
            }),
    );
    let agents =
        themis_orchestrator::test_support::build_stub_agents_with_mock(mock_llm.clone(), None);
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
        event_bus: Arc::new(themis_orchestrator::events::EventBus::new(1024)),
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

#[tokio::test]
async fn approved_compliance_report_shape() {
    let app = router_for(&load_fixture("wayne-002.json"));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/invoices")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"tenant_id":"wayne","invoice_id":"snap-approve","raw_b64":""}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Top-level keys (lock the wire format the frontend depends on)
    let top = json.as_object().expect("response is object");
    let expected_top_keys = ["run_id", "packet_id", "compliance"];
    for k in expected_top_keys {
        assert!(top.contains_key(k), "missing top-level key: {k}");
    }
    assert!(top["run_id"].is_string());
    assert!(top["packet_id"].is_string());
    assert!(top["compliance"].is_object());

    // compliance.frameworks: 5 frameworks, each with a 'framework'
    // name + 'fields' Vec<[name, value]>.
    let frameworks = top["compliance"]["frameworks"]
        .as_array()
        .expect("frameworks is array");
    assert_eq!(frameworks.len(), 5, "5 framework mappers");
    let framework_names: Vec<String> = frameworks
        .iter()
        .map(|f| f["framework"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        framework_names,
        vec![
            "dora",
            "eu_ai_act",
            "nist_ai_rmf",
            "owasp_agentic",
            "iso_42001"
        ],
        "framework order locked: {framework_names:?}"
    );

    // coverage_pct + ac15_pass + ac8_pass: dashboard signals.
    let compliance = &top["compliance"];
    assert!(compliance["coverage_pct"].is_number());
    assert!(compliance["ac15_pass"].is_boolean());
    assert!(compliance["ac8_pass"].is_boolean());
    assert!(compliance["total_fields"].is_u64());
    assert!(compliance["total_populated"].is_u64());
    assert!(
        compliance["total_populated"].as_u64().unwrap()
            <= compliance["total_fields"].as_u64().unwrap()
    );

    // Each framework: at least 3 fields populated, all are
    // [name, value] pairs.
    for fw in frameworks {
        let fields = fw["fields"].as_array().expect("framework.fields is array");
        assert!(
            fields.len() >= 3,
            "framework {} has < 3 fields",
            fw["framework"]
        );
        for entry in fields {
            let arr = entry.as_array().expect("field is [name, value]");
            assert_eq!(arr.len(), 2, "field must be a 2-tuple");
            assert!(arr[0].is_string());
        }
    }
}

#[tokio::test]
async fn halted_compliance_report_has_art17_with_halt_outcome() {
    let app = router_for(&load_fixture("stark-001.json"));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/invoices")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"tenant_id":"stark","invoice_id":"snap-halt","raw_b64":""}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // dora.art_17_incident_reporting must be a halt with the
    // R7 sub-fields (incident_classification, reporting_window_hours,
    // mock_recipient). This is the dashboard's "the regulator
    // would care about this" signal.
    let dora = json["compliance"]["frameworks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["framework"] == "dora")
        .expect("dora framework");
    let fields = dora["fields"].as_array().unwrap();
    let art17 = fields
        .iter()
        .find_map(|entry| {
            let arr = entry.as_array()?;
            if arr[0].as_str() == Some("art_17_incident_reporting") {
                Some(&arr[1])
            } else {
                None
            }
        })
        .expect("art 17 present");
    assert_eq!(art17["outcome"], "halt");
    assert_eq!(art17["reporting_window_hours"], 72);
    assert_eq!(art17["mock_recipient"], "NCA-ES");
    // incident_classification is one of the 4 halt-derived values
    let cls = art17["incident_classification"].as_str().unwrap();
    assert!(
        [
            "fraud_suspected",
            "sanctions_match",
            "data_incoherence",
            "policy_violation"
        ]
        .contains(&cls),
        "unexpected incident_classification: {cls}"
    );
}
