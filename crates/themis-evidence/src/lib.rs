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
//! * **`packet.rs`** — `SealedPacket` + `EvidenceService`
//! * **`bin/verify.rs`** — the offline-verify binary

#![allow(missing_docs)]

/// Crate version + name.
pub fn version() -> &'static str {
    "themis-evidence"
}

pub mod chain;
pub mod packet;
pub mod signer;
pub mod timestamp;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-evidence");
    }
}
