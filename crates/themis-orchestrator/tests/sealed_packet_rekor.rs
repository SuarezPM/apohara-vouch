//! Integration test for US-A4: a sealed packet with a Rekor entry
//! round-trips through serde_json and the `rekor_entry` field is
//! preserved on the wire.
//!
//! This test lives in the orchestrator crate (rather than the
//! evidence crate's own `tests/`) because the orchestrator's
//! `process_invoice_sealed` is the production caller. The unit
//! test for the seal method itself lives in
//! `crates/themis-evidence/src/packet.rs::tests`.

use std::sync::Arc;

use themis_evidence::packet::EvidenceService;
use themis_evidence::rekor::{MockRekorClient, RekorClient};
use themis_evidence::timestamp::{MockTimestampAuthority, TimestampAuthority};

fn tsa() -> Arc<dyn TimestampAuthority> {
    Arc::new(MockTimestampAuthority::new("https://mock.tsa.local"))
}

#[tokio::test]
async fn sealed_packet_with_rekor_entry_round_trips_through_json() {
    let mut svc = EvidenceService::from_seed("stark", [0xA1; 32], tsa());
    let rekor = MockRekorClient::new();

    let payload = r#"{"invoice_id":"inv-rekor-1","tenant":"stark","vendor":"ACME","amount_cents":4242}"#;
    let hash_hex = blake3::hash(payload.as_bytes()).to_hex().to_string();
    let entry = rekor.anchor(&hash_hex, "stark").await.unwrap();

    let sealed = svc.seal("inv-rekor-1", payload, Some(entry)).await.unwrap();

    // The field is populated.
    let carried = sealed
        .rekor_entry
        .as_ref()
        .expect("rekor_entry should be Some");
    assert!(!carried.uuid.is_empty());
    assert!(!carried.bundle_url.is_empty());

    // Round-trip through JSON — the field must survive serialization.
    let json = serde_json::to_string(&sealed).expect("serialize");
    assert!(
        json.contains("\"rekor_entry\""),
        "serialized packet must include rekor_entry key (got: {json})"
    );

    let parsed: themis_evidence::packet::SealedPacket =
        serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed.rekor_entry.as_ref().unwrap().uuid, carried.uuid);
    assert_eq!(parsed.rekor_entry.as_ref().unwrap().log_index, carried.log_index);
}
