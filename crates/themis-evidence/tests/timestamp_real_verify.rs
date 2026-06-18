//! Integration test for `FreeTSAAuthority::verify_strict` (FIX-2).
//!
//! Uses a real FreeTSA timestamp response captured at
//! 2026-06-18 from `https://freetsa.org/tsr`. The fixture is
//! committed at `tests/fixtures/freetsa_sample.tsr`; the
//! FreeTSA root CA at `certs/freetsa-root.pem`.
//!
//! Run with: `cargo test -p themis-evidence --test timestamp_real_verify`
//!
//! The test does NOT make any network calls — everything is
//! parsed locally and verified offline against the embedded
//! root CA.

use std::fs;

use themis_evidence::timestamp::{FreeTSAAuthority, TimestampResponse};

/// SHA-256("THEMIS_TEST_FIXTURE_2026_06_18") — the hash that was
/// sent to FreeTSA when the fixture was generated. The fixture
/// is a real `TimeStampResp` from `https://freetsa.org/tsr`
/// captured 2026-06-18 (serial 0x05ADCCF5).
const FIXTURE_HASH: [u8; 32] = [
    0x69, 0x29, 0xba, 0x7c, 0xd8, 0x47, 0xe9, 0xbb, 0x0a, 0xf3, 0xbc, 0x20, 0x36, 0x9a, 0xea, 0x03,
    0x37, 0x5d, 0x5f, 0x14, 0x23, 0x5e, 0x60, 0xb4, 0x3c, 0xb5, 0x21, 0x74, 0x04, 0x9e, 0x5a, 0xe9,
];

fn load_fixture() -> TimestampResponse {
    let raw = fs::read("tests/fixtures/freetsa_sample.tsr")
        .expect("fixture missing: tests/fixtures/freetsa_sample.tsr");
    TimestampResponse {
        time: 1_751_000_000, // wall-clock at fetch; ignored by verify_strict
        accuracy_ms: 1000,
        raw_der: raw,
    }
}

#[test]
fn verify_strict_accepts_matching_hash() {
    let tsa = FreeTSAAuthority::freetsa();
    let resp = load_fixture();
    let result = tsa.verify_strict(&resp, &FIXTURE_HASH);
    assert!(
        result.is_ok(),
        "verify_strict failed on a known-good fixture: {:?}",
        result
    );
    assert!(
        result.unwrap(),
        "verify_strict returned Ok(false) on a hash-matching fixture"
    );
}

#[test]
fn verify_strict_rejects_mismatched_hash() {
    let tsa = FreeTSAAuthority::freetsa();
    let resp = load_fixture();
    // Flip one bit of the hash → must yield Ok(false), not Err.
    let mut wrong = FIXTURE_HASH;
    wrong[0] ^= 0x01;
    let result = tsa.verify_strict(&resp, &wrong);
    assert!(
        result.is_ok(),
        "hash mismatch should be Ok(false), not Err: {:?}",
        result
    );
    assert!(!result.unwrap());
}

#[test]
fn verify_strict_rejects_garbage_der() {
    let tsa = FreeTSAAuthority::freetsa();
    let resp = TimestampResponse {
        time: 0,
        accuracy_ms: 0,
        raw_der: vec![0x30, 0x82, 0xFF, 0xFF], // truncated SEQUENCE
    };
    let result = tsa.verify_strict(&resp, &FIXTURE_HASH);
    assert!(result.is_err(), "expected Asn1 error, got {:?}", result);
}

#[test]
fn verify_strict_rejects_empty_der() {
    let tsa = FreeTSAAuthority::freetsa();
    let resp = TimestampResponse {
        time: 0,
        accuracy_ms: 0,
        raw_der: Vec::new(),
    };
    let result = tsa.verify_strict(&resp, &FIXTURE_HASH);
    assert!(result.is_err(), "expected error on empty DER, got {:?}", result);
}

#[test]
fn verify_quick_still_accepts_non_empty_der() {
    // The legacy quick path is retained for the orchestrator's
    // optimistic fallback; verify_strict is the strict path.
    let tsa = FreeTSAAuthority::freetsa();
    let resp = load_fixture();
    assert!(tsa.verify_quick(&resp, "ignored"));
}