//! vouch-receipt EU AI Act Art. 12 coverage tests.
//!
//! AC-3.9: ≥7/8 fields populated per packet. Each test exercises
//! one boundary (full population, single-field drop, etc.).

use chrono::Utc;
use vouch_receipt::{
    packet::{AgentOutput, EvidencePacket},
    Art12Coverage, EU_AI_ACT_ART12_FIELDS,
};

fn sample_packet() -> EvidencePacket {
    EvidencePacket::build(
        "case-001",
        Utc::now(),
        Utc::now(),
        "stanford-invoicenet-50",
        "inv-001",
        "00000000-0000-0000-0000-000000000001",
        "apohara-vouch-1",
        "0".repeat(64),
        vec![AgentOutput {
            agent_id: "fraud-auditor".into(),
            verdict: "halt".into(),
            summary: "secret detected".into(),
            risk_score: Some(0.92),
        }],
        None,
    )
}

#[test]
fn all_eight_fields_populated_is_compliant() {
    let p = sample_packet();
    let cov = p.art12_coverage();
    assert_eq!(cov.len(), 8);
    assert!(cov.iter().all(|c| c.populated));
    assert!(Art12Coverage::is_compliant(&cov));
}

#[test]
fn field_count_is_eight() {
    assert_eq!(EU_AI_ACT_ART12_FIELDS.len(), 8);
}

#[test]
fn field_names_match_spec() {
    assert_eq!(EU_AI_ACT_ART12_FIELDS[0], "start_time");
    assert_eq!(EU_AI_ACT_ART12_FIELDS[1], "end_time");
    assert_eq!(EU_AI_ACT_ART12_FIELDS[2], "reference_database");
    assert_eq!(EU_AI_ACT_ART12_FIELDS[3], "input_data");
    assert_eq!(EU_AI_ACT_ART12_FIELDS[4], "natural_person_id");
    assert_eq!(EU_AI_ACT_ART12_FIELDS[5], "decision_id");
    assert_eq!(EU_AI_ACT_ART12_FIELDS[6], "policy_version");
    assert_eq!(EU_AI_ACT_ART12_FIELDS[7], "hash_chain_prev");
}

#[test]
fn seven_of_eight_is_still_compliant() {
    let mut p = sample_packet();
    p.natural_person_id = None;
    let cov = p.art12_coverage();
    let populated = cov.iter().filter(|c| c.populated).count();
    assert_eq!(populated, 7);
    assert!(Art12Coverage::is_compliant(&cov));
}

#[test]
fn six_of_eight_fails_compliance() {
    let mut p = sample_packet();
    p.natural_person_id = None;
    p.decision_id = String::new();
    let cov = p.art12_coverage();
    let populated = cov.iter().filter(|c| c.populated).count();
    assert_eq!(populated, 6);
    assert!(!Art12Coverage::is_compliant(&cov));
}

#[test]
fn packet_survives_json_round_trip() {
    let p = sample_packet();
    let s = serde_json::to_string(&p).unwrap();
    let back: EvidencePacket = serde_json::from_str(&s).unwrap();
    assert_eq!(back, p);
}

#[test]
fn empty_packet_fails_compliance() {
    let p = EvidencePacket::build(
        "",
        chrono::DateTime::parse_from_rfc3339("1970-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        chrono::DateTime::parse_from_rfc3339("1970-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        "",
        "",
        "",
        "",
        "",
        vec![],
        None,
    );
    let cov = p.art12_coverage();
    assert!(!Art12Coverage::is_compliant(&cov));
}
