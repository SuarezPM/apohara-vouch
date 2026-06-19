//! vouch-compliance EU AI Act mapper test.

use themis_agents::baaar::Outcome;
use themis_compliance::eu_ai_act::EuAiActMapper;
use themis_compliance::framework::{ComplianceMapper, EvidencePacket, Framework};

#[test]
fn eu_ai_act_returns_eu_ai_act_framework() {
    let m = EuAiActMapper;
    assert_eq!(m.framework(), Framework::EuAiAct);
}

#[test]
fn eu_ai_act_populates_at_least_seven_art12_fields() {
    let m = EuAiActMapper;
    let ep = EvidencePacket::new("stark", "inv-001", vec![], Outcome::Approve);
    let map = m.map(&ep);
    assert!(
        map.populated >= 7,
        "EU AI Act Art. 12 requires ≥7/8 fields, got {}",
        map.populated
    );
}

#[test]
fn eu_ai_act_handles_halt_outcome() {
    let m = EuAiActMapper;
    let ep = EvidencePacket::new(
        "wayne",
        "inv-002",
        vec![],
        Outcome::Halt(themis_agents::baaar::BaaarReason::SecretLeakDetected),
    );
    let map = m.map(&ep);
    assert!(map.populated >= 7);
}
