//! Integration tests for the HALT/Approve visual differentiation in
//! the Evidence Packet PDF.
//!
//! These tests build a `SignedPacket`, render it via
//! `render_packet_pdf`, and verify the output is a structurally
//! well-formed PDF (`%PDF-` magic, size > 1 KB).
//!
//! Limitation: we do NOT parse the rendered PDF text. The
//! `printpdf` 0.7 byte stream is not easy to extract text from
//! without a dedicated parser crate, and the test contract from the
//! story is "the function does not panic and produces a valid PDF
//! for both Halt and Approve fixtures". A future story can add a
//! `lopdf`-based content check if needed.

use themis_agents::baaar::{BaaarReason, Outcome};
use themis_agents::decision::{AgentDecision, DecisionType};
use themis_orchestrator::packet::{EvidencePacket, SignedPacket};
use themis_orchestrator::pdf::render_packet_pdf;

fn build_halt_packet() -> SignedPacket {
    // FraudAuditor decision with `assessment.risk_score = 0.95`,
    // which exceeds the 0.85 threshold and should fire the
    // `RiskScoreExceeded` BAAAR condition.
    let decisions = vec![AgentDecision {
        agent_id: "fraud_auditor".to_string(),
        tenant_id: "stark".to_string(),
        invoice_id: "inv-halt-001".to_string(),
        decision_type: DecisionType::FraudAssessed,
        confidence: 0.9,
        reasoning: "HALTED: risk score above threshold".to_string(),
        timestamp_ms: 1_700_000_000_000,
        payload: serde_json::json!({
            "assessment": {
                "risk_score": 0.95,
                "coherence_score": 0.7,
                "debate_rounds": 1,
                "explicit_halt": false,
                "findings": [],
            }
        }),
    }];
    let packet = EvidencePacket::new(
        "stark",
        "inv-halt-001",
        decisions,
        Outcome::Halt(BaaarReason::RiskScoreExceeded),
    );
    SignedPacket::wrap(packet, "00".repeat(64), "11".repeat(32))
}

fn build_approve_packet() -> SignedPacket {
    // Approve case: risk_score 0.1, no secret findings, healthy
    // coherence, low debate rounds. All 5 BAAAR conditions should
    // show as pass.
    let decisions = vec![AgentDecision {
        agent_id: "fraud_auditor".to_string(),
        tenant_id: "wayne".to_string(),
        invoice_id: "inv-ok-001".to_string(),
        decision_type: DecisionType::FraudAssessed,
        confidence: 0.95,
        reasoning: "OK".to_string(),
        timestamp_ms: 1_700_000_001_000,
        payload: serde_json::json!({
            "assessment": {
                "risk_score": 0.10,
                "coherence_score": 0.85,
                "debate_rounds": 1,
                "explicit_halt": false,
                "findings": [],
            }
        }),
    }];
    let packet = EvidencePacket::new(
        "wayne",
        "inv-ok-001",
        decisions,
        Outcome::Approve,
    );
    SignedPacket::wrap(packet, "00".repeat(64), "11".repeat(32))
}

#[test]
fn renders_halt_with_stamp_and_matrix() {
    let sp = build_halt_packet();
    let bytes = render_packet_pdf(&sp).expect("render halt PDF");
    assert!(
        bytes.len() > 1024,
        "HALT PDF should be >1KB, got {}",
        bytes.len()
    );
    assert_eq!(&bytes[..5], b"%PDF-", "PDF magic bytes missing");
}

#[test]
fn renders_approve_with_green_indicator() {
    let sp = build_approve_packet();
    let bytes = render_packet_pdf(&sp).expect("render approve PDF");
    assert!(
        bytes.len() > 1024,
        "Approve PDF should be >1KB, got {}",
        bytes.len()
    );
    assert_eq!(&bytes[..5], b"%PDF-", "PDF magic bytes missing");
}
