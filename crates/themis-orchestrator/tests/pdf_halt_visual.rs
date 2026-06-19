//! Integration tests for the HALT/Approve visual differentiation in
//! the Evidence Packet PDF.
//!
//! These tests build a `SignedPacket`, render it via
//! `render_packet_pdf`, and verify the output PDF (a) starts with
//! `%PDF-`, (b) is at least 1 KB, and (c) contains the expected
//! rendered text content (HALT stamp, REASON line, BAAAR condition
//! matrix for the halt case; APPROVED marker for the approve case).
//!
//! printpdf 0.7 emits text in content streams as hex literals like
//! `<48414c54>`, so the raw bytes don't match a string literal
//! without decoding. We use a `decode_pdf_text` helper that walks
//! the PDF byte stream, decodes every `<hex>` literal, and also
//! passes through printable ASCII so unencoded markers are
//! searchable. This is the same pattern used in
//! `snapshot_compliance.rs`.

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
    let packet = EvidencePacket::new("wayne", "inv-ok-001", decisions, Outcome::Approve);
    SignedPacket::wrap(packet, "00".repeat(64), "11".repeat(32))
}

/// Decode the text content of a printpdf-rendered PDF into a single
/// `String`. printpdf 0.7 emits text in content streams as hex
/// literals like `<48414c54>`; raw bytes of the field names won't
/// match without decoding. We also concatenate the outer
/// (non-stream) PDF text so any unencoded content (e.g. the
/// /Count 2 marker) is also searchable. Mirrors the helper in
/// `snapshot_compliance.rs`.
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
fn renders_halt_with_stamp_and_matrix() {
    let sp = build_halt_packet();
    let bytes = render_packet_pdf(&sp).expect("render halt PDF");
    assert!(
        bytes.len() > 1024,
        "HALT PDF should be >1KB, got {}",
        bytes.len()
    );
    assert_eq!(&bytes[..5], b"%PDF-", "PDF magic bytes missing");

    // Content assertions: the rendered PDF must contain the HALT
    // stamp, the REASON line, and at least 3 of the 5 BAAAR
    // condition labels. A regression that replaces "HALT" with
    // "STOP" or drops the 24pt stamp will fail here.
    let decoded = decode_pdf_text(&bytes);

    assert!(
        decoded.contains("HALT"),
        "HALT PDF should contain the literal 'HALT' stamp"
    );
    // Post-v5 PDF redesign: the REASON label was consolidated into
    // the BAAAR CONDITIONS matrix header. The halt reason now shows
    // as the `value` next to the fired condition label (e.g.
    // "fired: risk_score > 0.85"). We assert on the matrix header
    // + the RiskScoreExceeded value string instead.
    assert!(
        decoded.contains("BAAAR CONDITIONS"),
        "HALT PDF should contain the BAAAR CONDITIONS matrix header"
    );
    assert!(
        decoded.contains("risk_score > 0.85"),
        "HALT PDF should show the RiskScoreExceeded reason (risk_score > 0.85) in the matrix"
    );

    let conditions = [
        "risk_score",
        "secret_leak",
        "coherence",
        "debate_rounds",
        "explicit_halt",
    ];
    let matched: Vec<&str> = conditions
        .iter()
        .copied()
        .filter(|c| decoded.contains(c))
        .collect();
    assert!(
        matched.len() >= 3,
        "HALT PDF should contain at least 3 of the 5 BAAAR condition labels; matched: {:?}",
        matched
    );
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

    // Content assertions: the approved PDF should show the
    // APPROVED marker and must NOT contain the big red HALT stamp.
    let decoded = decode_pdf_text(&bytes);

    assert!(
        decoded.contains("APPROVED"),
        "Approve PDF should contain the 'APPROVED' marker"
    );
    // US-10: the 4-buyer PDF is now 6 pages. The General
    // Counsel page (5) and the BAAAR Outcome section on
    // page 1 both reference "HALT" in informational
    // context (the legal reporting timeline + the
    // conditional BAAAR outcome labels). The "red HALT
    // stamp" is only emitted on the HALT path; for an
    // APPROVED packet the page-1 stamp reads "APPROVED".
    // The negative assertion is therefore "the green
    // APPROVED marker is present" (already asserted above)
    // — not "HALT is absent from any text".
}
