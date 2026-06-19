//! vouch-evidence — Ed25519 signer + SealedPacket + RFC 3161.
//!
//! AC-3.1, AC-3.9: thin re-export shell over `themis-evidence`,
//! preserving the deep module path (`vouch_evidence::signer::*`
//! etc.). The 8 EU AI Act Art. 12 fields are populated by
//! `EvidenceService::seal` (see `themis_evidence::packet`).
//!
//! ## Tenant keys
//!
//! `SignerService::for_tenant(tenant_id)` returns a baked signer:
//! `stark`/`wayne` use compile-time seeds; any other id derives a
//! seed via HKDF-SHA256 from a baked master seed. This is the
//! deployment path (Vercel's ephemeral FS cannot persist generated
//! keys; baked keys survive that — R4 + R8 mitigation).

/// Crate version + name.
pub fn version() -> &'static str {
    "vouch-evidence"
}

pub mod packet;
pub mod signer;

pub use themis_evidence::{chain, persistence, rekor, rekor_v2, timestamp};

// Re-export the most-used public types so callers can `use
// vouch_evidence::{SignerService, SealedPacket, ...}` without
// reaching into deep modules.
pub use themis_evidence::chain::{
    ChainEntry as EvChainEntry, ChainError as EvChainError, HashChain, RetentionPolicy,
};
pub use themis_evidence::packet::{
    DsseEnvelope, DsseSignature, EvError, EvidenceService, SealedPacket,
};
pub use themis_evidence::persistence::{ChainStore, ChainStoreError};
pub use themis_evidence::rekor::{
    CosignRekorClient, MockRekorClient, RekorClient, RekorEntry, RekorError,
    SigstoreVerifyRekorClient,
};
pub use themis_evidence::rekor_v2::RekorV2Client;
pub use themis_evidence::signer::{KeyPair, SignerError, SignerService, STARK_SEED, WAYNE_SEED};
pub use themis_evidence::timestamp::{
    FreeTSAAuthority, MockTimestampAuthority, Timestamp, TimestampAuthority, TimestampError,
    TimestampResponse, TsError,
};

/// SignerService factory alias — kept as a stable surface
/// for `vouch-orchestrator` and `bin/vouch-verify`.
pub type VouchSignerService = SignerService;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "vouch-evidence");
    }

    #[test]
    fn signer_service_for_tenant_baked() {
        // Stark + Wayne are baked; we just need the constructor
        // to not panic and to return a usable signer.
        let stark = SignerService::for_tenant("stark").expect("stark is baked");
        assert_eq!(stark.tenant_id(), "stark");
        let pub_hex = stark.public_key_hex();
        assert_eq!(pub_hex.len(), 64);
    }

    #[test]
    fn signer_service_for_tenant_saas_derives_deterministically() {
        // Same tenant id → same key. HKDF-SHA256 is deterministic.
        let a = SignerService::for_tenant("acme-corp").unwrap();
        let b = SignerService::for_tenant("acme-corp").unwrap();
        assert_eq!(a.public_key_hex(), b.public_key_hex());
        let c = SignerService::for_tenant("other-corp").unwrap();
        assert_ne!(a.public_key_hex(), c.public_key_hex());
    }

    #[test]
    fn signer_signs_and_verifies_round_trip() {
        let signer = SignerService::for_tenant("stark").unwrap();
        let msg = b"hello world";
        let sig = signer.sign(msg);
        assert!(signer.verify(msg, &sig));
        let other = SignerService::for_tenant("wayne").unwrap();
        assert!(!other.verify(msg, &sig), "wayne cannot verify stark's sig");
    }
}
