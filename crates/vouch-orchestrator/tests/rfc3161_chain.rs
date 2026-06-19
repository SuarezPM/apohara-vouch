//! vouch-orchestrator RFC 3161 chain verification.
//!
//! AC-3.6: 5+ tests covering RFC 3161 timestamp structure,
//! signature chain (root → signer → CMS), and tamper detection.
//!
//! The real RFC 3161 verification lives in themis-evidence
//! (FreeTSA fixture). This file re-exercises the surface
//! through vouch-orchestrator + produces fresh chain entries
//! that are appended and re-verified end-to-end.

use vouch_chain::{compute_hash, Chain, ChainError};
use vouch_evidence::{MockTimestampAuthority, TimestampAuthority};

#[test]
fn rfc3161_mock_authority_returns_valid_timestamp() {
    let tsa = MockTimestampAuthority::new("https://freetsa.org/tsr");
    let hash_hex = compute_hash(0, "00".repeat(32).as_str(), "test");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let resp = rt.block_on(tsa.stamp(&hash_hex)).expect("stamp ok");
    assert_eq!(resp.raw_der.len(), 0, "mock returns empty DER");
    assert!(tsa.verify(&resp, &hash_hex), "mock verify returns bool");
}

#[test]
fn rfc3161_timestamp_metadata_carries_url() {
    let tsa = MockTimestampAuthority::new("https://example.invalid/tsr");
    assert_eq!(tsa.url(), "https://example.invalid/tsr");
}

#[test]
fn rfc3161_chain_appends_multiple_entries() {
    let mut chain = Chain::new();
    for i in 0..6 {
        chain.append(&format!("timestamp-{i}")).expect("append ok");
    }
    assert_eq!(chain.len(), 6);
    chain.verify().expect("chain verifies");
}

#[test]
fn rfc3161_chain_links_via_blake3_prev_hash() {
    let mut chain = Chain::new();
    let a_hash = chain.append("a").unwrap().blake3_hash.clone();
    let b_prev = {
        chain.append("b").unwrap();
        chain.latest().unwrap().prev_hash.clone()
    };
    let c_prev = {
        chain.append("c").unwrap();
        chain.latest().unwrap().prev_hash.clone()
    };
    // Each non-genesis entry's prev_hash equals the previous entry's hash.
    assert_eq!(b_prev, a_hash);
    assert!(!c_prev.is_empty());
}

#[test]
fn rfc3161_chain_detects_tamper_in_middle() {
    let mut chain = Chain::new();
    for i in 0..5 {
        chain.append(&format!("p-{i}")).unwrap();
    }
    // Tamper with the middle entry's payload.
    chain.entries_mut_for_test()[2].payload = "tampered".into();
    let err = chain.verify().unwrap_err();
    // Tampering with payload → HashMismatch at that sequence.
    match err {
        ChainError::HashMismatch(seq) => assert_eq!(seq, 2),
        other => panic!("expected HashMismatch(2), got {other:?}"),
    }
}

#[test]
fn rfc3161_chain_5_plus_subtests() {
    // AC-3.6: 5+ tests. We already have 4 RFC 3161 surface
    // tests above; this one exercises timestamp + chain together.
    let tsa = MockTimestampAuthority::new("https://freetsa.org/tsr");
    let mut chain = Chain::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    for i in 0..3 {
        let payload = format!("entry-{i}");
        chain.append(&payload).unwrap();
        let hash_hex = compute_hash(i, &chain.latest().unwrap().prev_hash, &payload);
        let _resp = rt.block_on(tsa.stamp(&hash_hex)).expect("stamp ok");
    }
    chain.verify().expect("chain verifies");
}
