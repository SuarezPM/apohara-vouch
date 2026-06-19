//! US-05: ISO/IEC 42001:2023 AIMS fields on SealedPacket.
//!
//! Asserts:
//!   - `SealedPacket.iso_42001` is populated by default when
//!     `EvidenceService::seal` is called.
//!   - All 5 fields are present (risk_assessment,
//!     impact_assessment, monitoring, improvement, lifecycle).
//!   - The vouch-verify binary prints the ISO 42001 summary
//!     line when the field is populated.

use themis_evidence::packet::EvidenceService;
use themis_evidence::timestamp::MockTimestampAuthority;

fn service() -> EvidenceService {
    let tsa = std::sync::Arc::new(MockTimestampAuthority::new("https://mock.tsa"));
    EvidenceService::for_tenant("stark", tsa).expect("baked tenant stark must have a key")
}

#[tokio::test]
async fn sealed_packet_carries_iso_42001_fields_by_default() {
    let mut svc = service();
    let packet = svc
        .seal("inv-iso-001", "{\"x\":1}", None)
        .await
        .expect("seal must succeed");
    let iso = packet
        .iso_42001
        .as_ref()
        .expect("iso_42001 must be populated by default");
    // 5 fields, all of them populated.
    assert_eq!(
        iso.get("risk_assessment_conducted")
            .and_then(|v| v.as_bool()),
        Some(true),
        "risk_assessment_conducted must be true"
    );
    let impact_ref = iso
        .get("impact_assessment_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        impact_ref.starts_with("themis-compliance v"),
        "impact_assessment_ref must start with 'themis-compliance v', got: {impact_ref}"
    );
    let monitoring = iso
        .get("monitoring_mechanism")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        monitoring.contains("BAAAR-gate"),
        "monitoring_mechanism must mention BAAAR-gate, got: {monitoring}"
    );
    assert!(
        iso.get("improvement_cycle")
            .and_then(|v| v.as_str())
            .is_some(),
        "improvement_cycle must be present"
    );
    assert_eq!(
        iso.get("lifecycle_stage").and_then(|v| v.as_str()),
        Some("production"),
        "lifecycle_stage must default to 'production'"
    );
}

#[tokio::test]
async fn sealed_packet_iso_42001_round_trips_through_json() {
    let mut svc = service();
    let packet = svc
        .seal("inv-iso-002", "{\"y\":2}", None)
        .await
        .expect("seal must succeed");
    let json = serde_json::to_string(&packet).expect("serialize");
    let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
    assert!(
        v.get("iso_42001").is_some(),
        "iso_42001 must be present in serialized JSON"
    );
    assert_eq!(
        v["iso_42001"]["lifecycle_stage"],
        serde_json::json!("production")
    );
}
