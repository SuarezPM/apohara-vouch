//! vouch-receipt C2PA manifest tests.
//!
//! C2PA manifests are deterministic JSON envelopes. The "CI"
//! here means: the manifest survives round-trip JSON and uses
//! a stable schema. Real C2PA verification requires a C2PA
//! toolchain (out of scope; we emit a deterministic stub).

use vouch_receipt::C2paManifest;

#[test]
fn manifest_builds_with_required_fields() {
    let m = C2paManifest::build("vouch-orchestrator", "abcdef0123", None);
    assert_eq!(m.vendor, "apohara-vouch-v1");
    assert_eq!(m.claim_generator, "vouch-orchestrator");
    assert_eq!(m.claim_hex, "abcdef0123");
    assert_eq!(m.algorithm, "Ed25519+BLAKE3");
    assert!(!m.issued_at.is_empty());
    assert!(m.upstream_manifest_id.is_none());
}

#[test]
fn manifest_carries_upstream_link_when_provided() {
    let m = C2paManifest::build("vouch-orchestrator", "sig", Some("upstream-id".into()));
    assert_eq!(m.upstream_manifest_id.as_deref(), Some("upstream-id"));
}

#[test]
fn manifest_survives_json_round_trip() {
    let m = C2paManifest::build("vouch-orchestrator", "deadbeef", Some("up".into()));
    let s = serde_json::to_string(&m).unwrap();
    let back: C2paManifest = serde_json::from_str(&s).unwrap();
    assert_eq!(back, m);
}

#[test]
fn issued_at_is_rfc3339() {
    let m = C2paManifest::build("g", "s", None);
    let _: chrono::DateTime<chrono::Utc> = m.issued_at.parse().expect("RFC 3339");
}
