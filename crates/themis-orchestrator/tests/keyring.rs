//! Integration tests for Story C-13 — BIP32-*style* Ed25519 keyring
//! (G16 / G28 / AC13).
//!
//! The keyring is the dynamic path for tenants that don't have a
//! baked key file: derivation is `HMAC-SHA512(master_seed,
//! domain_tag || tenant_id)[0..32]`, then `SigningKey::from_bytes`.
//! This is a simplified subset of BIP32 — see the module doc in
//! `keyring.rs` for the design rationale.
//!
//! These tests assert the **integration** with `TenantRegistry`,
//! not the unit-level invariants (those live in `keyring.rs`'s
//! `#[cfg(test)] mod tests`).

use ed25519_dalek::Verifier;
use themis_orchestrator::keyring::{TenantKeyring, BIP32_LIKE_DOMAIN};
use themis_orchestrator::tenants::TenantRegistry;

fn fixed_seed(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn test_tenant_key_derivation_deterministic() {
    // Same tenant_id, same seed → same key, byte-for-byte.
    let k = TenantKeyring::new(fixed_seed(0x42));
    let first = k.derive_for_tenant("tenant-a");
    let second = k.derive_for_tenant("tenant-a");
    assert_eq!(first.to_bytes(), second.to_bytes());
    assert_eq!(
        first.verifying_key().to_bytes(),
        second.verifying_key().to_bytes()
    );
    // Caching via get_or_derive must not change the derived key.
    let cached = k.get_or_derive("tenant-a").unwrap();
    assert_eq!(first.to_bytes(), cached.to_bytes());
}

#[test]
fn test_tenant_keys_distinct() {
    // Three tenants, three distinct keypairs, one master seed.
    let k = TenantKeyring::new(fixed_seed(0x11));
    let a = k.derive_for_tenant("tenant-a");
    let b = k.derive_for_tenant("tenant-b");
    let c = k.derive_for_tenant("tenant-c");
    assert_ne!(a.to_bytes(), b.to_bytes());
    assert_ne!(b.to_bytes(), c.to_bytes());
    assert_ne!(a.to_bytes(), c.to_bytes());
    // All three must be valid Ed25519 pubkeys (32 bytes).
    assert_eq!(a.verifying_key().to_bytes().len(), 32);
    assert_eq!(b.verifying_key().to_bytes().len(), 32);
    assert_eq!(c.verifying_key().to_bytes().len(), 32);
    // Round-trip: each key can sign+verify with itself.
    use ed25519_dalek::Signer;
    let msg = b"themis-c13-tenant-keyring";
    let sig = a.sign(msg);
    a.verifying_key().verify(msg, &sig).expect("self-verify");
}

#[test]
fn test_master_seed_domain_separates() {
    // Two keyrings, different master seeds → same tenant_id yields
    // different keys. This is the master-seed domain separation
    // half of the contract; the tag half is asserted in the
    // unit tests.
    let k1 = TenantKeyring::new(fixed_seed(0xAA));
    let k2 = TenantKeyring::new(fixed_seed(0xBB));
    let a1 = k1.derive_for_tenant("tenant-x");
    let a2 = k2.derive_for_tenant("tenant-x");
    assert_ne!(a1.to_bytes(), a2.to_bytes());
    // The domain tag is exposed and stable. If a refactor changes
    // the tag, every previously-derived key changes too — assert
    // the exact bytes so the change is loud.
    assert_eq!(
        BIP32_LIKE_DOMAIN,
        b"themis-3.0-tenant-keyring-v1"
    );
}

#[test]
fn test_tenant_registry_returns_keyring() {
    // The registry exposes the same keyring that a future A2A
    // handler will use to sign cross-framework peer messages.
    let r = TenantRegistry::with_default_tenants_and_seed(fixed_seed(0xCD));
    let from_registry = r.keyring().derive_for_tenant("tenant-a");
    // The derivation must match a fresh, independent keyring built
    // from the same seed (proves the registry isn't shadowing the
    // derivation in a non-obvious way).
    let independent = TenantKeyring::new(fixed_seed(0xCD)).derive_for_tenant("tenant-a");
    assert_eq!(from_registry.to_bytes(), independent.to_bytes());
    // And the registry's stark tenant must have a baked key (the
    // demo path) that's distinct from the keyring's stark key.
    let stark = r.get("stark").expect("stark must be a default tenant");
    let keyring_stark = r.keyring().derive_for_tenant("stark");
    assert_ne!(
        stark.ed25519_public_key_hex,
        hex::encode(keyring_stark.verifying_key().to_bytes())
    );
}

#[test]
fn test_evict_forces_rederivation() {
    // Eviction removes the cached entry; the next get_or_derive
    // call reproduces the same key (because derivation is
    // deterministic — no entropy is lost on evict).
    let k = TenantKeyring::new(fixed_seed(0x99));
    let before = k.get_or_derive("tenant-z").unwrap();
    assert_eq!(k.count(), 1);
    k.evict("tenant-z");
    assert_eq!(k.count(), 0);
    let after = k.get_or_derive("tenant-z").unwrap();
    assert_eq!(before.to_bytes(), after.to_bytes());
    // The freshly-derived key is functionally equivalent: it
    // signs and the signature verifies under the same pubkey.
    use ed25519_dalek::Signer;
    let sig = after.sign(b"post-evict");
    after.verifying_key().verify(b"post-evict", &sig).expect("verify");
}
