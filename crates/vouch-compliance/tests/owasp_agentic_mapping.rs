//! vouch-compliance OWASP Agentic 2026 mapper test.

use themis_agents::baaar::Outcome;
use themis_compliance::framework::{ComplianceMapper, EvidencePacket, Framework};
use themis_compliance::owasp_agentic::OwaspAgenticMapper;

#[test]
fn owasp_returns_owasp_framework() {
    let m = OwaspAgenticMapper;
    assert_eq!(m.framework(), Framework::OwaspAgentic);
}

#[test]
fn owasp_maps_secret_leak_to_asi02() {
    let m = OwaspAgenticMapper;
    let ep = EvidencePacket::new(
        "stark",
        "inv-001",
        vec![],
        Outcome::Halt(themis_agents::baaar::BaaarReason::SecretLeakDetected),
    );
    let map = m.map(&ep);
    let asi02 = map
        .fields
        .iter()
        .find(|(n, _)| *n == "ASI02_sensitive_data_exposure");
    assert!(asi02.is_some(), "ASI02 field must exist");
    let (name, value) = asi02.unwrap();
    assert_eq!(value, &serde_json::json!("triggered"));
    assert!(name.contains("ASI02"));
}
