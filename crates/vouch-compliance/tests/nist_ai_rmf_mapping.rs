//! vouch-compliance NIST AI RMF mapper test.

use themis_agents::baaar::Outcome;
use themis_agents::decision::{AgentDecision, DecisionType};
use themis_compliance::framework::{ComplianceMapper, EvidencePacket, Framework};
use themis_compliance::nist_ai_rmf::NistAiRmfMapper;

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
fn nist_ai_rmf_returns_nist_framework() {
    let m = NistAiRmfMapper;
    assert_eq!(m.framework(), Framework::NistAiRmf);
}

#[test]
fn nist_ai_rmf_populates_at_least_three_core_fields() {
    let m = NistAiRmfMapper;
    // Provide at least one decision so "govern" populates.
    let decisions = vec![decision(DecisionType::FraudAssessed)];
    let ep = EvidencePacket::new("stark", "inv-001", decisions, Outcome::Approve);
    let map = m.map(&ep);
    let names: Vec<&str> = map.fields.iter().map(|(n, _)| *n).collect();
    // map + measure + govern (with non-empty decisions) = 3 of 4.
    assert!(names.iter().any(|n| *n == "govern"));
    assert!(names.iter().any(|n| *n == "map"));
    assert!(names.iter().any(|n| *n == "measure"));
}

#[test]
fn nist_ai_rmf_populates_manage_with_provenance_signed() {
    let m = NistAiRmfMapper;
    let decisions = vec![decision(DecisionType::ProvenanceSigned)];
    let ep = EvidencePacket::new("stark", "inv-001", decisions, Outcome::Approve);
    let map = m.map(&ep);
    let names: Vec<&str> = map.fields.iter().map(|(n, _)| *n).collect();
    assert!(names.iter().any(|n| *n == "manage"));
}
