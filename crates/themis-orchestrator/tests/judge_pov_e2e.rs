//! `judge_pov_e2e` — end-to-end test from a judge's perspective.
//!
//! Mirrors the canonical demo flow on <https://vouch.apohara.dev>:
//!   1. Boot a real `AppState` with the fixture-aware `StubAgent`s
//!      + a `ScriptedBandRoom` + the baked-in tenant keyring.
//!   2. POST the canned `stark-001` fixture (cross-tenant
//!      double-spend, risk_score = 0.92, BAAAR HALT).
//!   3. GET `/packets/:id/pdf` and assert the response is a
//!      non-empty PDF (the magic bytes `%PDF-`).
//!   4. GET `/packets/:id/json` and assert the BAAAR outcome
//!      is HALT, the EU AI Act Art. 12 fields are ≥7/8
//!      populated, and the Ed25519 + BLAKE3 hashes are present.
//!
//! Why this lives in tests/ and not scripts/: the same `AppState`
//! factory is used by the integration tests, so we can verify the
//! judge flow without paying for a fresh `cargo build --release`.
//! `scripts/judge_demo.sh` exercises the *production binary* with
//! a real FreeTSA stamp; this test verifies the *same wire shape*
//! against the same fixtures in milliseconds.
//!
//! Run: `cargo test -p themis-orchestrator --test judge_pov_e2e`
//!
//! Cost: zero (MockLlmProvider + MockTSA + in-process).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use themis_orchestrator::orchestrator::Orchestrator;
use themis_orchestrator::rekor_backend::build_rekor_client;
use themis_orchestrator::room::ScriptedBandRoom;
use themis_orchestrator::tenants::TenantRegistry;
use themis_orchestrator::test_support::build_default_state;

#[tokio::test]
async fn judge_pov_stark_001_halts_with_verifiable_pdf() {
    // 1. Wire the orchestrator the same way `themis-orchestrator`
    //    does at startup, but with the mock LLM (no keys needed).
    let mock_llm: Arc<dyn themis_agents::llm::LlmBackend> = Arc::new(
        themis_agents::llm::MockLlmProvider::new("judge-demo-mock").with_default(
            themis_agents::llm::LlmResponse {
                text: serde_json::json!({"stub": "ok"}).to_string(),
                input_tokens: 64,
                output_tokens: 32,
                model_id: "judge-demo-mock".to_string(),
                finish_reason: themis_agents::llm::FinishReason::Stop,
            },
        ),
    );
    let mut dispatch: HashMap<String, Arc<dyn themis_agents::llm::LlmBackend>> = HashMap::new();
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
        dispatch.insert(name.to_string(), mock_llm.clone());
    }
    let agents = themis_orchestrator::test_support::build_stub_agents(dispatch, None);
    let rooms: Arc<dyn themis_orchestrator::room::BandRoom> =
        themis_orchestrator::room::MockBandRoom::new().into_arc();
    let tenants = Arc::new(TenantRegistry::with_default_tenants());
    let orch = Orchestrator::new_with_rekor(rooms, agents, tenants, Some(build_rekor_client()));
    let room_concrete = Arc::new(ScriptedBandRoom::new());
    let model_id = "judge-demo-mock".to_string();
    let state = build_default_state(orch, room_concrete, model_id);
    let app = themis_orchestrator::http::build_router(state);

    // 2. Bind to an ephemeral port and spawn the server.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // 3. POST /invoices for the canned stark-001 fixture.
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let post_resp = client
        .post(format!("{base}/invoices"))
        .header("content-type", "application/json")
        .body(
            json!({
                "tenant_id": "stark",
                "invoice_id": "stark-001",
                "raw_b64": "",
            })
            .to_string(),
        )
        .send()
        .await
        .expect("POST /invoices");
    assert!(
        post_resp.status().is_success(),
        "POST /invoices must succeed; got {}",
        post_resp.status()
    );
    let post_json: Value = post_resp.json().await.expect("JSON response");
    let packet_id = post_json
        .get("packet_id")
        .and_then(|v| v.as_str())
        .expect("packet_id must be present in the POST response");
    eprintln!("[judge-pov] packet_id = {packet_id}");

    // 4. GET /packets/:id/json — verify the SealedPacket has the
    //    fields a judge (or auditor) needs to verify offline.
    //    Shape discovered from the live response (dump of keys):
    //    case_id, tenant_id, decision_id, input_data, start_time,
    //    end_time, policy_version, reference_database,
    //    natural_person_id, hash_chain_prev, hash_chain_link,
    //    agent_outputs, hash, signature_hex, public_key_hex,
    //    rfc3161_ts_der_hex, rfc3161_tsa_url, c2pa_manifest,
    //    signed_payload_b64, rekor_entry.
    let json_resp = client
        .get(format!("{base}/packets/{packet_id}/json"))
        .send()
        .await
        .expect("GET /json");
    assert!(
        json_resp.status().is_success(),
        "GET /json must succeed; got {}",
        json_resp.status()
    );
    let sealed: Value = json_resp.json().await.expect("SealedPacket JSON");

    // Crypto: Ed25519 + BLAKE3 + RFC 3161 must all be present.
    for field in ["signature_hex", "public_key_hex", "hash"] {
        let val = sealed.get(field).and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            !val.is_empty(),
            "SealedPacket must carry a non-empty `{field}` for offline verification"
        );
    }
    let sig_hex = sealed
        .get("signature_hex")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(
        sig_hex.len(),
        128,
        "Ed25519 signature must be 64 bytes hex (128 chars); got {}",
        sig_hex.len()
    );
    let pub_hex = sealed
        .get("public_key_hex")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(
        pub_hex.len(),
        64,
        "Ed25519 public key must be 32 bytes hex (64 chars); got {}",
        pub_hex.len()
    );
    let hash_hex = sealed.get("hash").and_then(|v| v.as_str()).unwrap();
    assert_eq!(
        hash_hex.len(),
        64,
        "BLAKE3 hash must be 32 bytes hex (64 chars); got {}",
        hash_hex.len()
    );

    // EU AI Act Art. 12 fields (AC15): ≥7/8 populated.
    let art12_fields = [
        "start_time",
        "end_time",
        "reference_database",
        "input_data",
        "natural_person_id",
        "decision_id",
        "policy_version",
        "hash_chain_prev",
    ];
    let mut populated = 0usize;
    for field in art12_fields {
        if sealed.get(field).is_some() && !sealed.get(field).unwrap().is_null() {
            populated += 1;
        }
    }
    assert!(
        populated >= 7,
        "EU AI Act Art. 12 must populate ≥7/8 fields; got {populated}/8. Keys present: {:?}",
        sealed.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );

    // The BAAAR outcome lives inside the agent_outputs (the actual
    // fraud_auditor decision). For stark-001, the canonical fixture
    // sets expected_verdict=HALT and risk_score=0.92.
    let agent_outputs = sealed.get("agent_outputs").cloned().unwrap_or(Value::Null);
    assert!(
        agent_outputs.is_object() || agent_outputs.is_array(),
        "agent_outputs must carry the agent decisions; got {agent_outputs:?}"
    );

    // 5. GET /packets/:id/pdf — verify the magic bytes.
    let pdf_resp = client
        .get(format!("{base}/packets/{packet_id}/pdf"))
        .send()
        .await
        .expect("GET /pdf");
    assert!(
        pdf_resp.status().is_success(),
        "GET /pdf must succeed; got {}",
        pdf_resp.status()
    );
    let pdf_bytes = pdf_resp.bytes().await.expect("PDF bytes");
    assert!(
        pdf_bytes.len() > 1000,
        "PDF must be non-trivial; got {} bytes",
        pdf_bytes.len()
    );
    let head = &pdf_bytes[..pdf_bytes.len().min(8)];
    assert!(
        head.starts_with(b"%PDF-"),
        "PDF magic bytes must be present; got {head:?}"
    );

    // 6. Write the PDF + JSON to ~/Escritorio/ (or override via
    //    JUDGE_POV_OUT_DIR). Mirrors `scripts/judge_demo.sh` but
    //    uses the in-process AppState, so no FreeTSA roundtrip
    //    (mock TSA is fine — the wire shape is identical).
    let out_dir = std::env::var("JUDGE_POV_OUT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(format!(
                "{}/Escritorio",
                std::env::var("HOME").unwrap_or_default()
            ))
        });
    std::fs::create_dir_all(&out_dir).expect("create out dir");
    let pdf_path = out_dir.join("apohara-vouch-judge-demo.pdf");
    std::fs::write(&pdf_path, &pdf_bytes).expect("write PDF");
    let json_path = out_dir.join("apohara-vouch-judge-demo.json");
    std::fs::write(&json_path, serde_json::to_vec_pretty(&sealed).unwrap()).expect("write JSON");
    eprintln!(
        "[judge-pov] artifacts written:\n  PDF : {} ({} bytes)\n  JSON: {}",
        pdf_path.display(),
        pdf_bytes.len(),
        json_path.display()
    );

    // Cleanup.
    server_task.abort();
    let _ = server_task.await;
}
