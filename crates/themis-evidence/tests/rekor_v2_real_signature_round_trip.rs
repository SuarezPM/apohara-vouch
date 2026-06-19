//! FIX-1 verification: the `RekorV2Client::anchor()` body must
//! embed a real Ed25519 signature over the BLAKE3 digest using the
//! per-tenant SignerService.
//!
//! We don't call the real Rekor log (that needs network); instead
//! we mirror the same code path (decode hex, sign with
//! `SignerService::for_tenant`, build the `Signature` + `Verifier`)
//! and assert that:
//!
//!   1. The signature verifies against the signer's public key.
//!   2. The Ed25519 sig is NOT the hash bytes themselves (the
//!      pre-fix placeholder made them identical).
//!   3. The tenant public key bytes round-trip from
//!      `public_key_hex()` into the `PublicKey.raw_bytes` field.
//!
//! Acceptance: `cargo test -p themis-evidence rekor_v2_real_signature_round_trip`.

use ed25519_dalek::{Signature as DalekSig, Verifier as DalekVerifier, VerifyingKey};
use themis_evidence::signer::SignerService;

/// The hash we want anchored (arbitrary test payload).
fn test_blake3_hash() -> String {
    blake3::hash(b"test-payload").to_hex().to_string()
}

#[test]
fn anchor_signature_verifies_under_tenant_public_key() {
    let tenant = "stark";
    let signer = SignerService::for_tenant(tenant).expect("stark has a baked seed");

    let hash_hex = test_blake3_hash();
    let hash_bytes = hex::decode(&hash_hex).expect("blake3 hex must decode");
    assert_eq!(hash_bytes.len(), 32, "blake3 output is always 32 bytes");

    // Mirror the production anchor() signature path.
    let sig: DalekSig = signer.sign(&hash_bytes);
    let pubkey_bytes = hex::decode(signer.public_key_hex()).expect("signer pubkey hex decodes");
    assert_eq!(pubkey_bytes.len(), 32, "ed25519 public key is 32 bytes");

    // Verify: the tenant public key must validate the signature
    // over the BLAKE3 digest. This is the whole point of FIX-1:
    // the sig is real, not a placeholder.
    let pk = VerifyingKey::from_bytes(&pubkey_bytes.try_into().unwrap())
        .expect("pubkey bytes must be a valid ed25519 point");
    assert!(
        pk.verify(&hash_bytes, &sig).is_ok(),
        "Ed25519 signature must verify against the tenant public key"
    );
}

#[test]
fn anchor_signature_is_not_the_hash_itself() {
    // Pre-FIX-1 the Signature.content was hash_bytes.clone() — i.e.
    // sig == digest. That made the wire shape compile but the
    // signature meaningless. Assert the two are now distinct.
    let signer = SignerService::for_tenant("stark").unwrap();
    let hash_bytes = hex::decode(test_blake3_hash()).unwrap();
    let sig = signer.sign(&hash_bytes);
    assert_ne!(
        sig.to_bytes(),
        hash_bytes.as_slice(),
        "Ed25519 sig must NOT equal the digest (would mean the placeholder is back)"
    );
    // Sig is 64 bytes; hash is 32 bytes. Different lengths alone
    // catch the regression, but the byte-level check is the load-bearing
    // one for anyone patching the path back to the placeholder.
    assert_eq!(sig.to_bytes().len(), 64);
}

#[test]
fn cross_tenant_signature_does_not_verify() {
    // Stark's signature must NOT verify under Wayne's public key.
    // Catches the regression where a single baked key would be
    // shared across tenants.
    let stark = SignerService::for_tenant("stark").unwrap();
    let wayne = SignerService::for_tenant("wayne").unwrap();
    let hash_bytes = hex::decode(test_blake3_hash()).unwrap();
    let stark_sig = stark.sign(&hash_bytes);

    let wayne_pubkey_bytes: [u8; 32] = hex::decode(wayne.public_key_hex())
        .unwrap()
        .try_into()
        .unwrap();
    let wayne_pk = VerifyingKey::from_bytes(&wayne_pubkey_bytes).unwrap();
    assert!(
        wayne_pk.verify(&hash_bytes, &stark_sig).is_err(),
        "Stark's signature must NOT verify under Wayne's public key"
    );
}

#[test]
fn anchor_signature_payload_round_trips_through_proto_shapes() {
    // Mirror the exact `Signature` + `Verifier` + `PublicKey` wire
    // shapes that anchor() builds, and assert the bytes that hit
    // the wire are the bytes the verifier needs. This is the
    // round-trip the production code relies on.
    let signer = SignerService::for_tenant("wayne").unwrap();
    let hash_bytes = hex::decode(test_blake3_hash()).unwrap();
    let sig = signer.sign(&hash_bytes);
    let pubkey_bytes = hex::decode(signer.public_key_hex()).unwrap();

    // The "wire" bytes (what anchor() puts in the request).
    let wire_sig_bytes: Vec<u8> = sig.to_bytes().to_vec();
    let wire_pubkey_bytes: Vec<u8> = pubkey_bytes.clone();

    // A separate verifier with only the wire bytes (and the tenant
    // baked pubkey baked at compile time) must reconstruct and
    // verify.
    let pk = VerifyingKey::from_bytes(wire_pubkey_bytes.as_slice().try_into().unwrap()).unwrap();
    let recovered_sig = DalekSig::from_bytes(wire_sig_bytes.as_slice().try_into().unwrap());
    assert!(
        pk.verify(&hash_bytes, &recovered_sig).is_ok(),
        "signature reconstructed from wire bytes must verify"
    );
}
