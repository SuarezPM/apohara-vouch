//! vouch-evidence signer proptest.
//!
//! AC-3.9: Ed25519 signatures verify under tenant keys; signature
//! shape is consistent across tenants. 150 proptest cases.

use proptest::prelude::*;
use vouch_evidence::{SignerService, STARK_SEED, WAYNE_SEED};

fn tenant_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("stark".to_string()),
        Just("wayne".to_string()),
        proptest::string::string_regex("[a-z][a-z0-9-]{2,16}").unwrap(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(150))]

    /// Sign/verify round-trips under the same tenant.
    #[test]
    fn sign_verify_round_trip(
        tenant in tenant_strategy(),
        msg in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let signer = SignerService::for_tenant(&tenant)
            .unwrap_or_else(|_| panic!("could not derive signer for {tenant}"));
        let sig = signer.sign(&msg);
        prop_assert!(signer.verify(&msg, &sig));
    }

    /// Different tenants produce different public keys.
    #[test]
    fn distinct_tenants_have_distinct_keys(
        a in tenant_strategy(),
        b in tenant_strategy(),
    ) {
        let sa = SignerService::for_tenant(&a).unwrap();
        let sb = SignerService::for_tenant(&b).unwrap();
        if a == b {
            prop_assert_eq!(sa.public_key_hex(), sb.public_key_hex());
        } else {
            prop_assert_ne!(sa.public_key_hex(), sb.public_key_hex());
        }
    }

    /// sign_hex always returns 128 hex chars (Ed25519 sig = 64 bytes).
    #[test]
    fn sign_hex_is_128_chars(
        tenant in tenant_strategy(),
        msg in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let signer = SignerService::for_tenant(&tenant).unwrap();
        let hex = signer.sign_hex(&msg);
        prop_assert_eq!(hex.len(), 128);
    }

    /// baked seeds are 32 bytes each (Ed25519 seed length).
    #[test]
    fn baked_seeds_are_32_bytes(_dummy in 0..1u8) {
        prop_assert_eq!(STARK_SEED.len(), 32);
        prop_assert_eq!(WAYNE_SEED.len(), 32);
        prop_assert_ne!(STARK_SEED, WAYNE_SEED);
    }
}
