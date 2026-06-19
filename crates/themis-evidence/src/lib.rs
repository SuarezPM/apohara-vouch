//! themis-evidence — cryptographic Evidence Packet for THEMIS.
//!
//! Ed25519 signing (`ed25519-dalek`), BLAKE3 hash chain, RFC 3161
//! timestamp (mock TSA; real FreeTSA in production), Rekor v2
//! anchoring (deferred to follow-up). Multi-tenant key isolation:
//! 2 fictitious companies (Stark / Wayne) with distinct keypairs
//! in `keys/{tenant}.ed25519`, mode 600.
//!
//! The `themis-verify` binary (see `src/bin/verify.rs`) replaces
//! `openssl dgst -sha512` for Ed25519 signatures (openssl does not
//! list ed25519 in its digest registry, so the spec's original
//! verify command was incorrect).
//!
//! ## Module map
//!
//! * **`signer.rs`** — `KeyPair` + `SignerService` (Ed25519)
//! * **`chain.rs`** — `HashChain` (BLAKE3, append-only, tamper-evident)
//! * **`timestamp.rs`** — `Timestamp` + `TimestampAuthority` trait + mock
//! * **`rekor.rs`** — `RekorClient` trait + `MockRekorClient` + `CosignRekorClient` (ADR-002)
//! * **`packet.rs`** — `SealedPacket` + `EvidenceService`
//! * **`bin/verify.rs`** — the offline-verify binary

#![allow(missing_docs)]

/// Crate version + name.
pub fn version() -> &'static str {
    "themis-evidence"
}

pub mod chain;
pub mod packet;
pub mod persistence;
pub mod rekor;
pub mod rekor_v2;
pub mod signer;
pub mod timestamp;

// Generated proto module (see `build.rs`). tonic-prost-build writes
// the output to `dev.sigstore.rekor.v2.rs`; `build.rs` renames it to
// `dev_sigstore_rekor_v2.rs` so this `include!` resolves to a
// known module name. `OUT_DIR` is set by Cargo for every build.
#[allow(clippy::module_inception)]
mod dev_sigstore_rekor_v2 {
    include!(concat!(env!("OUT_DIR"), "/dev_sigstore_rekor_v2.rs"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-evidence");
    }
}
