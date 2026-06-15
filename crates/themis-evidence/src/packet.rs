//! Sealed Evidence Packet + EvidenceService.
//!
//! Combines the signer (Ed25519), the hash chain (BLAKE3), and
//! the TSA (RFC 3161) into one signed + timestamped packet.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::chain::{ChainError, HashChain};
use crate::signer::{SignerError, SignerService};
use crate::timestamp::{Timestamp, TimestampAuthority, TimestampResponse, TsError};

/// The sealed packet. The orchestrator hands this to the Evidence
/// Packet assembly step; downstream consumers (auditors, verifiers,
/// the themis-verify binary) consume this shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedPacket {
    /// Unique packet id.
    pub packet_id: Uuid,
    /// Tenant id (stark, wayne).
    pub tenant_id: String,
    /// Invoice id.
    pub invoice_id: String,
    /// The canonical JSON bytes of the payload (the thing signed).
    pub payload_canonical_json: Vec<u8>,
    /// BLAKE3 hash of the canonical JSON, hex (64 chars).
    pub blake3_hash_hex: String,
    /// Ed25519 signature over the BLAKE3 hash, hex (128 chars).
    pub signature_hex: String,
    /// Hex-encoded Ed25519 public key (64 chars).
    pub public_key_hex: String,
    /// RFC 3161 timestamp from the TSA.
    pub timestamp: Timestamp,
    /// Length of the hash chain at the time of sealing (proof that
    /// this packet is sequenced correctly).
    pub chain_length: u64,
}

/// Evidence-layer errors.
#[derive(Debug, Error)]
pub enum EvError {
    /// Signer failure.
    #[error("signer: {0}")]
    Signer(#[from] SignerError),
    /// Hash chain failure.
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    /// TSA failure.
    #[error("tsa: {0}")]
    Ts(#[from] TsError),
    /// Verification failure.
    #[error("verification failed: {0}")]
    VerifyFailed(String),
}

/// The Evidence Service. Holds a `SignerService`, a `HashChain`, and
/// a `TimestampAuthority`. `seal` produces a `SealedPacket`;
/// `verify` re-validates it.
pub struct EvidenceService {
    signer: SignerService,
    chain: HashChain,
    tsa: Arc<dyn TimestampAuthority>,
}

impl std::fmt::Debug for EvidenceService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceService")
            .field("tenant_id", &self.signer.tenant_id())
            .field("public_key_hex", &self.signer.public_key_hex())
            .field("chain_length", &self.chain.len())
            .finish()
    }
}

impl EvidenceService {
    /// New service. Reads / generates the tenant's key in
    /// `key_dir/keys/{tenant}.ed25519` (chmod 600).
    pub fn new(
        tenant_id: &str,
        key_dir: &Path,
        tsa: Arc<dyn TimestampAuthority>,
    ) -> Result<Self, EvError> {
        let signer = SignerService::new(tenant_id, key_dir)?;
        Ok(Self {
            signer,
            chain: HashChain::new(),
            tsa,
        })
    }

    /// In-memory service (no key file IO). For tests.
    pub fn from_seed(tenant_id: &str, seed: [u8; 32], tsa: Arc<dyn TimestampAuthority>) -> Self {
        Self {
            signer: SignerService::from_seed(tenant_id, seed),
            chain: HashChain::new(),
            tsa,
        }
    }

    /// Service using the compile-time baked key for the given
    /// tenant. The 2 fixture tenants (`stark`, `wayne`) have keys
    /// committed in `keys/{tenant}.ed25519` and embedded via
    /// `include_bytes!`. Returns `EvError::Signer(UnknownTenant)`
    /// for any other id.
    pub fn for_tenant(
        tenant_id: &str,
        tsa: Arc<dyn TimestampAuthority>,
    ) -> Result<Self, EvError> {
        let signer = SignerService::for_tenant(tenant_id)?;
        Ok(Self {
            signer,
            chain: HashChain::new(),
            tsa,
        })
    }

    /// Replace the internal chain (used at startup to restore
    /// from `ChainStore`). Caller is responsible for verifying
    /// the chain before handing it over.
    pub fn restore_chain(&mut self, chain: HashChain) {
        self.chain = chain;
    }

    /// Borrow the chain (for tests + the persistence layer).
    pub fn chain(&self) -> &HashChain {
        &self.chain
    }

    /// The current chain length.
    pub fn chain_length(&self) -> usize {
        self.chain.len()
    }

    /// The signer's public key (hex).
    pub fn public_key_hex(&self) -> String {
        self.signer.public_key_hex()
    }

    /// Seal a payload: serialize → hash → sign → append to chain →
    /// request timestamp → return SealedPacket. Async because the
    /// TSA call is async.
    pub async fn seal(&mut self, invoice_id: &str, payload: &str) -> Result<SealedPacket, EvError> {
        // 1. Serialize the payload (the "canonical JSON" for the
        //    demo is just serde_json; production would use a
        //    canonical-JSON crate for cross-platform determinism).
        let payload_canonical_json = serde_json::to_vec(payload)
            .map_err(|e| EvError::VerifyFailed(format!("serialize payload: {e}")))?;

        // 2. Hash it.
        let hash = blake3::hash(&payload_canonical_json);
        let blake3_hash_hex = hash.to_hex().to_string();

        // 3. Sign the hash.
        let signature_hex = self.signer.sign_hex(hash.as_bytes());

        // 4. Append the (payload, hash) tuple to the chain. The
        //    payload is what the auditor sees; the chain proves
        //    ordering.
        self.chain.append(payload)?;

        // 5. Request a timestamp.
        let ts_response: TimestampResponse = self
            .tsa
            .stamp(&blake3_hash_hex)
            .await
            .map_err(EvError::Ts)?;
        if !self.tsa.verify(&ts_response, &blake3_hash_hex) {
            return Err(EvError::VerifyFailed(
                "TSA rejected its own response".to_string(),
            ));
        }
        let timestamp = Timestamp {
            time: ts_response.time,
            accuracy_ms: ts_response.accuracy_ms,
            tsa_url: self.tsa.url().to_string(),
        };

        Ok(SealedPacket {
            packet_id: Uuid::new_v4(),
            tenant_id: self.signer.tenant_id().to_string(),
            invoice_id: invoice_id.to_string(),
            payload_canonical_json,
            blake3_hash_hex,
            signature_hex,
            public_key_hex: self.signer.public_key_hex(),
            timestamp,
            chain_length: self.chain.len() as u64,
        })
    }

    /// Verify a sealed packet. Re-hashes the payload, verifies the
    /// signature, and verifies the chain. The packet's `tenant_id`
    /// must match this service's tenant — cross-tenant verify
    /// returns an error (defense against AC9 cross-tenant leaks).
    pub fn verify(&self, packet: &SealedPacket) -> Result<(), EvError> {
        // 0. Tenant match.
        if packet.tenant_id != self.signer.tenant_id() {
            return Err(EvError::VerifyFailed(format!(
                "cross-tenant verify denied: this service is for tenant {:?}, packet is for {:?}",
                self.signer.tenant_id(),
                packet.tenant_id
            )));
        }
        // 1. Re-hash the payload and compare.
        let recomputed = blake3::hash(&packet.payload_canonical_json);
        if recomputed.to_hex().to_string() != packet.blake3_hash_hex {
            return Err(EvError::VerifyFailed("BLAKE3 hash mismatch".to_string()));
        }

        // 2. Re-verify the signature. The signer is a fresh
        //    VerifyingKey reconstructed from the packet's
        //    `public_key_hex` — this lets us verify packets from
        //    past runs without holding the in-memory key.
        let pk_bytes = hex::decode(&packet.public_key_hex)
            .map_err(|e| EvError::VerifyFailed(format!("decode pubkey: {e}")))?;
        let pk_array: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| EvError::VerifyFailed("pubkey not 32 bytes".to_string()))?;
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk_array)
            .map_err(|e| EvError::VerifyFailed(format!("parse pubkey: {e}")))?;

        let sig_bytes = hex::decode(&packet.signature_hex)
            .map_err(|e| EvError::VerifyFailed(format!("decode sig: {e}")))?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| EvError::VerifyFailed("sig not 64 bytes".to_string()))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_array);

        use ed25519_dalek::Verifier;
        // The signer signed the RAW 32 bytes of the BLAKE3 hash;
        // reconstruct from the hex string before verifying.
        let raw_hash = hex::decode(&packet.blake3_hash_hex)
            .map_err(|e| EvError::VerifyFailed(format!("decode blake3 hash: {e}")))?;
        pk.verify(&raw_hash, &sig)
            .map_err(|e| EvError::VerifyFailed(format!("signature: {e}")))?;

        // 3. Verify the chain (tamper-evident).
        self.chain.verify()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timestamp::MockTimestampAuthority;

    fn tsa() -> Arc<dyn TimestampAuthority> {
        Arc::new(MockTimestampAuthority::new("https://mock.tsa.local"))
    }

    #[tokio::test]
    async fn round_trip_seal_and_verify() {
        let mut svc = EvidenceService::from_seed("stark", [1u8; 32], tsa());
        let packet = svc.seal("inv-001", "hello world").await.unwrap();
        assert_eq!(packet.tenant_id, "stark");
        assert_eq!(packet.invoice_id, "inv-001");
        let res = svc.verify(&packet);
        if res.is_err() {
            eprintln!("verify error: {:?}", res.as_ref().err());
        }
        assert!(res.is_ok(), "verify failed: {:?}", res.err());
    }

    #[tokio::test]
    async fn two_tenants_seal_independently() {
        let mut stark = EvidenceService::from_seed("stark", [1u8; 32], tsa());
        let mut wayne = EvidenceService::from_seed("wayne", [2u8; 32], tsa());
        let sp = stark.seal("inv-001", "from stark").await.unwrap();
        let wp = wayne.seal("inv-001", "from wayne").await.unwrap();
        assert_ne!(sp.public_key_hex, wp.public_key_hex);
        assert!(stark.verify(&sp).is_ok());
        assert!(wayne.verify(&wp).is_ok());
        // wayne cannot verify stark's packet.
        assert!(wayne.verify(&sp).is_err());
        // stark cannot verify wayne's packet.
        assert!(stark.verify(&wp).is_err());
    }

    #[tokio::test]
    async fn tampered_payload_fails_verify() {
        let mut svc = EvidenceService::from_seed("stark", [1u8; 32], tsa());
        let mut packet = svc.seal("inv-001", "hello").await.unwrap();
        // Mutate the canonical JSON (the payload itself).
        packet.payload_canonical_json = b"\"TAMPERED\"".to_vec();
        let err = svc.verify(&packet).unwrap_err();
        assert!(matches!(err, EvError::VerifyFailed(_)));
    }

    #[tokio::test]
    async fn tampered_signature_fails_verify() {
        let mut svc = EvidenceService::from_seed("stark", [1u8; 32], tsa());
        let mut packet = svc.seal("inv-001", "hello").await.unwrap();
        // Flip a hex char in the signature.
        let mut sig = packet.signature_hex;
        // safe char flip
        let first = sig.remove(0);
        sig.insert(0, if first == '0' { '1' } else { '0' });
        packet.signature_hex = sig;
        let err = svc.verify(&packet).unwrap_err();
        assert!(matches!(err, EvError::VerifyFailed(_)));
    }

    #[tokio::test]
    async fn chain_length_grows_with_each_seal() {
        let mut svc = EvidenceService::from_seed("stark", [1u8; 32], tsa());
        let p1 = svc.seal("inv-001", "a").await.unwrap();
        let p2 = svc.seal("inv-002", "b").await.unwrap();
        let p3 = svc.seal("inv-003", "c").await.unwrap();
        assert_eq!(p1.chain_length, 1);
        assert_eq!(p2.chain_length, 2);
        assert_eq!(p3.chain_length, 3);
        assert_eq!(svc.chain_length(), 3);
    }

    #[tokio::test]
    async fn blank_payload_works() {
        let mut svc = EvidenceService::from_seed("stark", [1u8; 32], tsa());
        let packet = svc.seal("inv-001", "").await.unwrap();
        assert!(svc.verify(&packet).is_ok());
    }
}
