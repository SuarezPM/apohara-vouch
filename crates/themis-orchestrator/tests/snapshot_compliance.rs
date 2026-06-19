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

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

use themis_agents::baaar::Outcome;
use themis_agents::decision::{AgentDecision, DecisionType};
use themis_agents::llm::{LlmResponse, MockLlmProvider};
use themis_evidence::rekor::MockRekorClient;
use themis_orchestrator::http::{build_router, AppState};
use themis_orchestrator::orchestrator::Orchestrator;
use themis_orchestrator::packet::{EvidencePacket, SignedPacket};
use themis_orchestrator::pdf::render_packet_pdf;
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

/// Build a representative sample packet with 8 agent decisions so
/// the page-2 trace has enough variety to exercise. The framework
/// booleans are left at their default (all true) which means all
/// 26 fields render with [x] markers.
fn pdf_sample_packet() -> SignedPacket {
    let mk = |agent: &str, dt: DecisionType, conf: f32, reason: &str| AgentDecision {
        agent_id: agent.to_string(),
        tenant_id: "stark".to_string(),
        invoice_id: "inv-pdf".to_string(),
        decision_type: dt,
        confidence: conf,
        reasoning: reason.to_string(),
        timestamp_ms: 0,
        payload: serde_json::json!({}),
    };
    let decisions = vec![
        mk(
            "extractor",
            DecisionType::Extracted,
            0.95,
            "extracted line items from invoice text",
        ),
        mk(
            "po_matcher",
            DecisionType::PoMatched,
            0.88,
            "matched PO 4500123456",
        ),
        mk(
            "fraud_auditor",
            DecisionType::FraudAssessed,
            0.42,
            "risk_score=0.42 below threshold",
        ),
        mk(
            "audit_watchdog",
            DecisionType::WatchdogAlert,
            0.91,
            "coherence within bounds",
        ),
        mk(
            "gaap_classifier",
            DecisionType::GaapClassified,
            0.83,
            "expense / office supplies",
        ),
        mk(
            "regression_tester",
            DecisionType::RegressionResult,
            1.0,
            "signature verified ok",
        ),
        mk(
            "provenance_signer",
            DecisionType::ProvenanceSigned,
            1.0,
            "Ed25519 signature sealed",
        ),
        mk(
            "narrator",
            DecisionType::Narrated,
            0.97,
            "policy version themis@2026-06-12 matched",
        ),
    ];
    let packet = EvidencePacket::new("stark", "inv-pdf", decisions, Outcome::Approve);
    SignedPacket::wrap(packet, "00".repeat(64), "11".repeat(32))
}

#[test]
fn pdf_has_six_pages_with_4_buyer_framing() {
    // US-10 acceptance: rendered PDF must have 6 pages
    // (cover + compliance grid + CISO + CFO + General
    // Counsel + Broker). US-10 originally targeted 9
    // pages; the 6-page minimal shell ships the 4
    // buyer framings (CISO/CFO/General Counsel/Broker)
    // which is the demo-impactful part of the plan.
    // printpdf 0.7 emits the /Count object in the Pages
    // dictionary as plain text, e.g. "/Count 6". A byte
    // search for "/Count 6" verifies 6 pages were emitted.
    let sp = pdf_sample_packet();
    let bytes = render_packet_pdf(&sp).expect("render");
    assert_eq!(&bytes[..5], b"%PDF-", "PDF magic");
    let body = String::from_utf8_lossy(&bytes);
    assert!(
        body.contains("/Count 6"),
        "PDF should declare /Count 6 (6 pages with 4-buyer framing), got: {body}"
    );
}

/// Decode all hex-string literals (`<...>`) in a PDF body into a
/// single UTF-8 string. printpdf 0.7 emits text in content streams
/// as hex literals like `<5448454D4953>`; raw bytes of the field
/// names won't match without decoding. We also concatenate the
/// outer (non-stream) PDF text so any unencoded content (e.g. the
/// /Count 2 marker) is also searchable.
fn decode_pdf_text(pdf: &[u8]) -> String {
    let mut out = String::with_capacity(pdf.len());
    let mut i = 0;
    while i < pdf.len() {
        if pdf[i] == b'<' && i + 1 < pdf.len() && (pdf[i + 1].is_ascii_hexdigit()) {
            // hex string literal
            let mut j = i + 1;
            while j < pdf.len() && pdf[j] != b'>' {
                j += 1;
            }
            if j >= pdf.len() {
                break;
            }
            let hex = &pdf[i + 1..j];
            if hex.len().is_multiple_of(2) {
                let mut decoded = Vec::with_capacity(hex.len() / 2);
                let mut k = 0;
                while k + 1 < hex.len() {
                    let pair = std::str::from_utf8(&hex[k..k + 2]).unwrap_or("");
                    if let Ok(b) = u8::from_str_radix(pair, 16) {
                        decoded.push(b);
                    }
                    k += 2;
                }
                out.push_str(&String::from_utf8_lossy(&decoded));
            }
            i = j + 1;
        } else {
            // pass through printable ASCII (so /Count and other markers are found)
            let c = pdf[i];
            if (0x20..=0x7e).contains(&c) {
                out.push(c as char);
            }
            i += 1;
        }
    }
    out
}

#[test]
fn pdf_page2_contains_all_26_compliance_field_names() {
    // US-06 acceptance: page 2 must list all 26 populated fields.
    // The 26 field names are hardcoded into the page-2 grid. We
    // verify the field-name strings appear in the decoded PDF
    // content (printpdf emits text as hex-encoded `<...>` literals,
    // so the raw bytes don't match without decoding).
    let sp = pdf_sample_packet();
    let bytes = render_packet_pdf(&sp).expect("render");
    let decoded = decode_pdf_text(&bytes);
    let required_fields = [
        // DORA (3)
        "art_9_ict_risk_management",
        "art_10_incident_detection",
        "art_17_incident_reporting",
        // EU AI Act (9: 8 Art.12 + 1 Art.26)
        "art_12_1_start_time",
        "art_12_2_end_time",
        "art_12_3_reference_database",
        "art_12_4_input_data",
        "art_12_5_natural_person_id",
        "art_12_6_decision_id",
        "art_12_7_policy_version",
        "art_12_8_hash_chain_prev",
        "art_26_deployer_name",
        // NIST AI RMF (4)
        "govern",
        "map",
        "measure",
        "manage",
        // OWASP Agentic 2026 (10)
        "ASI01_prompt_injection",
        "ASI02_sensitive_data_exposure",
        "ASI03_supply_chain",
        "ASI04_data_and_model_poisoning",
        "ASI05_improper_output_handling",
        "ASI06_excessive_agency",
        "ASI07_system_prompt_leakage",
        "ASI08_vector_and_embedding_weaknesses",
        "ASI09_misinformation",
        "ASI10_rogue_agents",
    ];
    assert_eq!(
        required_fields.len(),
        26,
        "26-field grid must contain exactly 26 names"
    );
    for name in &required_fields {
        assert!(
            decoded.contains(name),
            "PDF page 2 should contain field name '{name}' (decoded content stream missing it)"
        );
    }
}

#[test]
fn pdf_page2_contains_agent_decision_trace() {
    // US-06 acceptance: page 2 must include the agent decision trace
    // with reasoning truncated to 120 chars. We assert the agent_id
    // strings appear in the decoded PDF text, plus a "Page 2"
    // header and the "8 agents" trace count.
    let sp = pdf_sample_packet();
    let bytes = render_packet_pdf(&sp).expect("render");
    let decoded = decode_pdf_text(&bytes);
    // Page 2 header
    assert!(
        decoded.contains("Page 2"),
        "PDF should declare 'Page 2' header on the auditor page"
    );
    // Agent trace count
    assert!(
        decoded.contains("8 agents"),
        "PDF should declare '8 agents' in the trace section"
    );
    // Each agent id from the sample packet
    for agent in &[
        "extractor",
        "po_matcher",
        "fraud_auditor",
        "audit_watchdog",
        "gaap_classifier",
        "regression_tester",
        "provenance_signer",
        "narrator",
    ] {
        assert!(
            decoded.contains(agent),
            "PDF should reference agent_id '{agent}' in the decision trace"
        );
    }
}
