//! Integration test: load the 5 Stanford InvoiceNet-shaped demo
//! invoices from `fixtures/demo-invoices/`, run each one through
//! the orchestrator's `process_invoice` (fully mocked), and verify
//! the outcome matches the fixture's `expected_verdict`.
//!
//! This is the contract test for US-D01: 4 HALT + 1 APPROVED,
//! spread across Stark (#1-3) and Wayne (#1-2) trust domains.
//!
//! Run with: `cargo test -p themis-orchestrator --test demo_data_loads`

use std::sync::Arc;

use themis_evidence::rekor::MockRekorClient;
use themis_orchestrator::orchestrator::Orchestrator;
use themis_orchestrator::test_support::{build_orchestrator, expected_outcome_string, DemoInvoice};

/// Build an orchestrator WITHOUT a Rekor client. Used by the
/// original 7 fixture contract tests (US-D01) — these don't care
/// about anchoring, only the verdict distribution.
fn orchestrator_for(fixture: &DemoInvoice) -> Orchestrator {
    build_orchestrator(fixture, None, None)
}

/// Build an orchestrator WITH a `MockRekorClient` for the Rekor
/// wire-up tests (US-R02). The mock is deterministic (UUID derived
/// from BLAKE3 hash) so the assertions are stable.
fn orchestrator_with_rekor(fixture: &DemoInvoice) -> (Orchestrator, Arc<MockRekorClient>) {
    let rekor: Arc<dyn themis_evidence::rekor::RekorClient> = Arc::new(MockRekorClient::new());
    // Recover the inner Arc to expose the log_index counter in
    // tests; the dyn-trait API doesn't give us back the concrete
    // type, so we re-create one for the counter.
    let orch = build_orchestrator(fixture, None, Some(rekor));
    (orch, Arc::new(MockRekorClient::new()))
}

fn load_fixture(name: &str) -> DemoInvoice {
    let path = themis_orchestrator::test_support::fixtures_dir().join(name);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("failed to parse fixture {}: {e}", path.display()))
}

#[tokio::test]
async fn all_5_fixtures_load() {
    let names = [
        "stark-001.json",
        "stark-002.json",
        "stark-003.json",
        "wayne-001.json",
        "wayne-002.json",
    ];
    for name in names {
        let f = load_fixture(name);
        assert!(!f.invoice_id.is_empty());
        assert!(!f.tenant_id.is_empty());
        assert!(
            f.expected_verdict == "HALT" || f.expected_verdict == "APPROVED",
            "fixture {} has invalid expected_verdict: {}",
            name,
            f.expected_verdict
        );
    }
}

#[tokio::test]
async fn stark_001_halts_on_risk_score_exceeded() {
    let f = load_fixture("stark-001.json");
    let orch = orchestrator_for(&f);
    let sp = orch
        .process_invoice(&f.tenant_id, &f.invoice_id, b"raw".to_vec())
        .await
        .unwrap();
    assert_eq!(
        sp.packet.bbaaar_outcome,
        themis_agents::baaar::Outcome::Halt(themis_agents::baaar::BaaarReason::RiskScoreExceeded),
        "stark-001 should HALT on risk_score (vendor duplicate)"
    );
}

#[tokio::test]
async fn stark_002_halts_on_risk_score_exceeded() {
    let f = load_fixture("stark-002.json");
    let orch = orchestrator_for(&f);
    let sp = orch
        .process_invoice(&f.tenant_id, &f.invoice_id, b"raw".to_vec())
        .await
        .unwrap();
    assert_eq!(
        sp.packet.bbaaar_outcome,
        themis_agents::baaar::Outcome::Halt(themis_agents::baaar::BaaarReason::RiskScoreExceeded),
        "stark-002 should HALT on risk_score (no PO)"
    );
}

#[tokio::test]
async fn stark_003_halts_on_secret_leak() {
    let f = load_fixture("stark-003.json");
    let orch = orchestrator_for(&f);
    let sp = orch
        .process_invoice(&f.tenant_id, &f.invoice_id, b"raw".to_vec())
        .await
        .unwrap();
    assert_eq!(
        sp.packet.bbaaar_outcome,
        themis_agents::baaar::Outcome::Halt(themis_agents::baaar::BaaarReason::SecretLeakDetected),
        "stark-003 should HALT on SecretLeak (OFAC sanctioned vendor)"
    );
}

#[tokio::test]
async fn wayne_001_halts_on_coherence_too_low() {
    let f = load_fixture("wayne-001.json");
    let orch = orchestrator_for(&f);
    let sp = orch
        .process_invoice(&f.tenant_id, &f.invoice_id, b"raw".to_vec())
        .await
        .unwrap();
    assert_eq!(
        sp.packet.bbaaar_outcome,
        themis_agents::baaar::Outcome::Halt(themis_agents::baaar::BaaarReason::CoherenceTooLow),
        "wayne-001 should HALT on CoherenceTooLow (future invoice_date)"
    );
}

#[tokio::test]
async fn wayne_002_approves() {
    let f = load_fixture("wayne-002.json");
    let orch = orchestrator_for(&f);
    let sp = orch
        .process_invoice(&f.tenant_id, &f.invoice_id, b"raw".to_vec())
        .await
        .unwrap();
    assert_eq!(
        sp.packet.bbaaar_outcome,
        themis_agents::baaar::Outcome::Approve,
        "wayne-002 should APPROVE (clean invoice)"
    );
}

#[tokio::test]
async fn distribution_4_halt_1_approved() {
    let mut halts = 0;
    let mut approves = 0;
    for name in [
        "stark-001.json",
        "stark-002.json",
        "stark-003.json",
        "wayne-001.json",
        "wayne-002.json",
    ] {
        let f = load_fixture(name);
        let orch = orchestrator_for(&f);
        let sp = orch
            .process_invoice(&f.tenant_id, &f.invoice_id, b"raw".to_vec())
            .await
            .unwrap();
        match sp.packet.bbaaar_outcome {
            themis_agents::baaar::Outcome::Halt(_) => halts += 1,
            themis_agents::baaar::Outcome::Approve => approves += 1,
        }
    }
    assert_eq!(halts, 4, "expected 4 HALT verdicts across the 5 fixtures");
    assert_eq!(
        approves, 1,
        "expected 1 APPROVED verdict across the 5 fixtures"
    );
}

// Reference the helper to keep it from being dead-code in case the
// only call site ever changes.
#[allow(dead_code)]
fn _exercise_expected_outcome_string() -> &'static str {
    let f = load_fixture("stark-001.json");
    expected_outcome_string(&f)
}

// --- US-R02: Rekor anchoring wired into process_invoice ---

#[tokio::test]
async fn rekor_entry_populated_when_orchestrator_has_rekor_client() {
    let f = load_fixture("wayne-002.json");
    let (orch, _) = orchestrator_with_rekor(&f);
    let sp = orch
        .process_invoice(&f.tenant_id, &f.invoice_id, b"raw".to_vec())
        .await
        .unwrap();
    let entry = sp
        .rekor_entry
        .as_ref()
        .expect("rekor_entry should be Some when orchestrator has a Rekor client");
    // The mock derives the UUID from the BLAKE3 hash and embeds
    // the tenant in the bundle_url.
    assert!(entry.uuid.starts_with("mock-uuid-"));
    assert!(
        entry.bundle_url.contains("tenant=wayne"),
        "bundle_url should embed tenant: got {}",
        entry.bundle_url
    );
    assert_eq!(entry.log_index, 0, "first anchor in a fresh mock → 0");
}

#[tokio::test]
async fn rekor_entry_absent_when_orchestrator_has_no_rekor_client() {
    let f = load_fixture("wayne-002.json");
    // orchestrator_for() builds without a Rekor client — back-compat.
    let orch = orchestrator_for(&f);
    let sp = orch
        .process_invoice(&f.tenant_id, &f.invoice_id, b"raw".to_vec())
        .await
        .unwrap();
    assert!(
        sp.rekor_entry.is_none(),
        "rekor_entry should be None when no Rekor client is configured"
    );
}

#[tokio::test]
async fn rekor_anchor_uses_packets_blake3_hash() {
    let f = load_fixture("stark-001.json");
    let (orch, _) = orchestrator_with_rekor(&f);
    let sp = orch
        .process_invoice(&f.tenant_id, &f.invoice_id, b"raw".to_vec())
        .await
        .unwrap();
    let entry = sp.rekor_entry.as_ref().unwrap();
    // The mock stores base64(blake3_hash_hex) in body_b64. Decode
    // it and verify it matches the packet's blake3_hash_hex.
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD
        .decode(&entry.body_b64)
        .expect("body_b64 is valid base64");
    let body_str = String::from_utf8(body).expect("body is utf-8");
    assert_eq!(body_str, sp.blake3_hash_hex);
}

#[tokio::test]
async fn rekor_anchors_all_5_fixtures_end_to_end() {
    for name in [
        "stark-001.json",
        "stark-002.json",
        "stark-003.json",
        "wayne-001.json",
        "wayne-002.json",
    ] {
        let f = load_fixture(name);
        let (orch, _) = orchestrator_with_rekor(&f);
        let sp = orch
            .process_invoice(&f.tenant_id, &f.invoice_id, b"raw".to_vec())
            .await
            .unwrap();
        assert!(
            sp.rekor_entry.is_some(),
            "fixture {name} should produce a SignedPacket with rekor_entry populated"
        );
        let entry = sp.rekor_entry.as_ref().unwrap();
        assert!(
            entry
                .bundle_url
                .contains(&format!("tenant={}", f.tenant_id)),
            "fixture {name}: bundle_url should embed tenant={}",
            f.tenant_id
        );
    }
}

// --- US-P01: PDF generation via /packets/:id/pdf (AC12) ---

#[tokio::test]
async fn pdf_render_under_2s_for_each_fixture() {
    // AC12: PRC PDF download <2s. We measure the in-process PDF
    // render (which is the bulk of the latency; HTTP transport
    // adds <10ms on localhost). The full HTTP roundtrip is
    // covered by the http::tests module.
    use std::time::Instant;
    for name in [
        "stark-001.json",
        "stark-002.json",
        "stark-003.json",
        "wayne-001.json",
        "wayne-002.json",
    ] {
        let f = load_fixture(name);
        let (orch, _) = orchestrator_with_rekor(&f);
        let sp = orch
            .process_invoice(&f.tenant_id, &f.invoice_id, b"raw".to_vec())
            .await
            .unwrap();
        let start = Instant::now();
        let bytes =
            themis_orchestrator::pdf::render_packet_pdf(&sp).expect("PDF render should succeed");
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs_f64() < 2.0,
            "PDF render for {name} took {elapsed:?} (>2s)"
        );
        assert!(
            bytes.len() > 1024,
            "PDF for {name} is too small: {} bytes",
            bytes.len()
        );
        assert_eq!(
            &bytes[..5],
            b"%PDF-",
            "PDF for {name} has wrong magic bytes"
        );
    }
}
