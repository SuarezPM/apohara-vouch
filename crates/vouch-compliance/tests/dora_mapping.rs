//! vouch-compliance DORA mapper test.

use themis_agents::baaar::Outcome;
use themis_agents::decision::{AgentDecision, DecisionType};
use themis_compliance::dora::DoraMapper;
use themis_compliance::framework::{ComplianceMapper, EvidencePacket, Framework};

fn decision(decision_type: DecisionType) -> AgentDecision {
    AgentDecision {
        agent_id: "test".to_string(),
        tenant_id: "stark".to_string(),
        invoice_id: "inv-001".to_string(),
        timestamp_ms: 0,
        decision_type,
        confidence: 0.95,
        reasoning: "test reasoning".to_string(),
        payload: serde_json::Value::Null,
    }
}

#[test]
fn dora_mapper_returns_dora_framework() {
    let m = DoraMapper;
    assert_eq!(m.framework(), Framework::Dora);
}

#[test]
fn dora_mapper_populates_art17_on_approve() {
    let m = DoraMapper;
    let ep = EvidencePacket::new("stark", "inv-001", vec![], Outcome::Approve);
    let map = m.map(&ep);
    // Art 17 is always populated (either as incident or "no_incident").
    let names: Vec<&str> = map.fields.iter().map(|(n, _)| *n).collect();
    assert!(
        names.iter().any(|n| n.contains("art_17")),
        "Art 17 must always be populated"
    );
}

#[test]
fn dora_mapper_populates_art9_with_fraud_assessed_decision() {
    let m = DoraMapper;
    let decisions = vec![decision(DecisionType::FraudAssessed)];
    let ep = EvidencePacket::new("stark", "inv-001", decisions, Outcome::Approve);
    let map = m.map(&ep);
    let names: Vec<&str> = map.fields.iter().map(|(n, _)| *n).collect();
    assert!(names.iter().any(|n| n.contains("art_9")));
}

#[test]
fn dora_mapper_populates_art10_with_watchdog_alert() {
    let m = DoraMapper;
    let decisions = vec![decision(DecisionType::WatchdogAlert)];
    let ep = EvidencePacket::new("stark", "inv-001", decisions, Outcome::Approve);
    let map = m.map(&ep);
    let names: Vec<&str> = map.fields.iter().map(|(n, _)| *n).collect();
    assert!(names.iter().any(|n| n.contains("art_10")));
}

#[test]
fn dora_mapper_handles_halt_outcome() {
    let m = DoraMapper;
    let ep = EvidencePacket::new(
        "stark",
        "inv-001",
        vec![],
        Outcome::Halt(themis_agents::baaar::BaaarReason::RiskScoreExceeded),
    );
    let map = m.map(&ep);
    assert!(map.populated >= 1, "Art 17 must populate on HALT");
}
