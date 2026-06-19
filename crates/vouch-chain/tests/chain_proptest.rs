//! vouch-chain BLAKE3 chain determinism — proptest.
//!
//! AC-3.8: two chains built from identical input produce identical
//! chain root. 200 proptest cases (one per `proptest!` invocation).

use proptest::prelude::*;
use vouch_chain::{Chain, GENESIS_PREV_HASH};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Identical inputs produce identical chain roots.
    #[test]
    fn identical_inputs_produce_identical_roots(inputs in proptest::collection::vec(
        proptest::string::string_regex("[a-zA-Z0-9_-]{1,64}").unwrap(),
        1..30,
    )) {
        let mut a = Chain::new();
        let mut b = Chain::new();
        for s in &inputs {
            a.append(s).unwrap();
            b.append(s).unwrap();
        }
        prop_assert_eq!(a.root(), b.root());
        prop_assert_eq!(a.entries(), b.entries());
    }

    /// Re-verifying a chain that has been mutated to be invalid
    /// at any sequence must report that sequence (first mismatch wins).
    #[test]
    fn tampering_any_entry_fails_verify(
        inputs in proptest::collection::vec(
            proptest::string::string_regex("[a-zA-Z0-9_-]{1,32}").unwrap(),
            5..20,
        ),
        tamper_idx in 0usize..20,
    ) {
        let mut chain = Chain::new();
        for s in &inputs {
            chain.append(s).unwrap();
        }
        let n = chain.entries().len();
        if n == 0 { return Ok(()); }
        let i = tamper_idx % n;
        // Mutate the payload (but not the hash); verify must fail.
        let mut bytes = chain.entries()[i].payload.as_bytes().to_vec();
        if bytes.is_empty() { bytes.push(b'x'); }
        bytes[0] = bytes[0].wrapping_add(1);
        chain.entries_mut_for_test()[i].payload = String::from_utf8(bytes).unwrap_or_else(|_| "x".into());
        let err = chain.verify().unwrap_err();
        // Tampered entry either mismatches its own hash or breaks linkage.
        let expected = format!("sequence {}", i);
        prop_assert!(err.to_string().contains(expected.as_str()));
    }

    /// Genesis prev_hash is always the all-zero 64-hex string.
    #[test]
    fn genesis_prev_hash_is_zero(_dummy in 0..1u8) {
        let mut chain = Chain::new();
        let g = chain.append("genesis").unwrap();
        prop_assert_eq!(g.sequence, 0);
        prop_assert_eq!(g.prev_hash.as_str(), GENESIS_PREV_HASH);
    }
}
