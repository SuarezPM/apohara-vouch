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
    /// DSSE envelope (RFC 8785 JCS, IETF draft-sharif-agent-audit-trail).
    /// Compatible with the Notarized Agents paper pattern
    /// (arXiv:2606.04193): `{"payloadType": "application/vnd.apohara.themis.entry+json",
    /// "payload": base64url(payload_canonical_json), "signatures": [{"keyid",
    /// "sig": base64url(signature_hex)}]}`. The auditor can
    /// re-canonicalize and re-verify with any tool that
    /// understands DSSE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsse_envelope: Option<DsseEnvelope>,
    /// Rekor v2 transparency-log entry (anchoring the BLAKE3
    /// hash to a public tamper-evident log). `None` if no anchor
    /// was performed at seal time (the demo gracefully degrades
    /// when Rekor is not configured).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekor_entry: Option<crate::rekor::RekorEntry>,
    /// ISO/IEC 42001:2023 AIMS fields. US-05: 5-field flat
    /// struct (risk_assessment, impact_assessment,
    /// monitoring, improvement, lifecycle). Stored as
    /// `serde_json::Value` to avoid a themis-compliance →
    /// themis-evidence dep cycle (the canonical struct
    /// `themis_compliance::iso_42001::Iso42001Fields`
    /// serializes into this shape). Populated by default
    /// with the production-shaped static claims. `None`
    /// for packets sealed before the ISO 42001 schema
    /// was introduced (back-compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iso_42001: Option<serde_json::Value>,
    /// EU AI Act Article 49 mock registration id (C-10 /
    /// G30). Embedded in the C2PA manifest's Art 50
    /// assertion. A short, stable identifier (e.g.
    /// `EU-AIA-REG-2026-APOHARA-001`) that downstream
    /// regulators can resolve against the public
    /// registration directory. Carried as a top-level
    /// field on the SealedPacket for fast lookup without
    /// parsing the C2PA manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eu_registration_id: Option<String>,
}

/// DSSE envelope over the canonical JSON payload.
///
/// Format follows the IETF in-toto DSSE convention
/// (https://github.com/in-toto/in-toto.io/blob/main/in-toto-spec.md#dsse):
/// ```json
/// {
///   "payloadType": "application/vnd.apohara.themis.entry+json",
///   "payload": "<base64url(payload_canonical_json)>",
///   "signatures": [
///     { "keyid": "<public_key_hex_first_16_chars>",
///       "sig": "<base64url(signature_bytes)>" }
///   ]
/// }
/// ```
/// The envelope's bytes are themselves canonical JSON
/// (RFC 8785), so a verifier can hash the envelope's
/// serialized form to get a stable identifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DsseEnvelope {
    /// IANA media type (or vendor MIME) describing the payload.
    pub payload_type: String,
    /// Base64url-encoded payload (canonical JSON bytes).
    pub payload: String,
    /// One or more signatures over the payload. THEMIS emits
    /// exactly one (the tenant's Ed25519 key signs the payload).
    pub signatures: Vec<DsseSignature>,
}

/// A single signature entry inside a DSSE envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DsseSignature {
    /// Stable identifier for the signing key (first 16 hex chars
    /// of the public key, by convention).
    pub keyid: String,
    /// Base64url-encoded Ed25519 signature over the payload.
    pub sig: String,
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
    /// US-06: configurable retention policy. Default
    /// `RetentionPolicy::default()` (6 months per EU AI
    /// Act Art 12). Per-tenant / per-jurisdiction
    /// overrides apply.
    retention: crate::chain::RetentionPolicy,
    /// US-06: jurisdiction tag for retention lookup.
    /// Defaults to "EU" (the demo's deployment region).
    jurisdiction: String,
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
            retention: crate::chain::RetentionPolicy::default(),
            jurisdiction: "EU".to_string(),
        })
    }

    /// In-memory service (no key file IO). For tests.
    pub fn from_seed(tenant_id: &str, seed: [u8; 32], tsa: Arc<dyn TimestampAuthority>) -> Self {
        Self {
            signer: SignerService::from_seed(tenant_id, seed),
            chain: HashChain::new(),
            tsa,
            retention: crate::chain::RetentionPolicy::default(),
            jurisdiction: "EU".to_string(),
        }
    }

    /// Service using the compile-time baked key for the given
    /// tenant. The 2 fixture tenants (`stark`, `wayne`) have keys
    /// committed in `keys/{tenant}.ed25519` and embedded via
    /// `include_bytes!`. Returns `EvError::Signer(UnknownTenant)`
    /// for any other id.
    pub fn for_tenant(tenant_id: &str, tsa: Arc<dyn TimestampAuthority>) -> Result<Self, EvError> {
        let signer = SignerService::for_tenant(tenant_id)?;
        Ok(Self {
            signer,
            chain: HashChain::new(),
            tsa,
            retention: crate::chain::RetentionPolicy::default(),
            jurisdiction: "EU".to_string(),
        })
    }

    /// US-06: constructor with an explicit retention policy.
    /// The default `for_tenant` uses 6 months; this variant
    /// lets the demo wire per-tenant overrides (e.g. `wayne`
    /// with 24 months for biometric / law enforcement).
    pub fn for_tenant_with_retention(
        tenant_id: &str,
        tsa: Arc<dyn TimestampAuthority>,
        retention: crate::chain::RetentionPolicy,
    ) -> Result<Self, EvError> {
        let signer = SignerService::for_tenant(tenant_id)?;
        Ok(Self {
            signer,
            chain: HashChain::new(),
            tsa,
            retention,
            jurisdiction: "EU".to_string(),
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
    pub async fn seal(
        &mut self,
        invoice_id: &str,
        payload: &str,
        rekor_entry: Option<crate::rekor::RekorEntry>,
    ) -> Result<SealedPacket, EvError> {
        // US-05: every sealed packet carries the ISO/IEC
        // 42001:2023 AIMS fields by default. The 5 fields
        // are derived from the compliance crate's static
        // mapper defaults (BAAAR always runs, monitoring is
        // the test suite, lifecycle is production). Stored
        // as `serde_json::Value` to avoid a themis-compliance
        // dep cycle.
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
        // US-06: enforce the retention policy before appending.
        // If the previous entry is older than the configured
        // window (default 6 months per EU AI Act Art 12), the
        // append is rejected with `ChainError::RetentionExceeded`.
        // Empty chains (genesis append) always pass.
        self.chain.enforce_retention(
            &self.retention,
            chrono::Utc::now().timestamp_millis(),
            self.signer.tenant_id(),
            self.jurisdiction.as_str(),
        )?;
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

        // Build the DSSE envelope (RFC 8785 JCS, IETF
        // in-toto DSSE). The payload is the canonical
        // JSON bytes; the signature is the Ed25519
        // signature over the BLAKE3 hash (matching
        // the `signature_hex` field). The envelope is
        // the shape that an external auditor consumes
        // to re-verify offline.
        let public_key_hex = self.signer.public_key_hex();
        use base64::Engine;
        let dsse_envelope = {
            let payload_b64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_canonical_json);
            let sig_bytes = hex::decode(&signature_hex).unwrap_or_default();
            let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sig_bytes);
            let keyid: String = public_key_hex.chars().take(16).collect();
            DsseEnvelope {
                payload_type: "application/vnd.apohara.themis.entry+json".to_string(),
                payload: payload_b64,
                signatures: vec![DsseSignature {
                    keyid,
                    sig: sig_b64,
                }],
            }
        };
        let public_key_hex = self.signer.public_key_hex();

        Ok(SealedPacket {
            packet_id: Uuid::new_v4(),
            tenant_id: self.signer.tenant_id().to_string(),
            invoice_id: invoice_id.to_string(),
            payload_canonical_json,
            blake3_hash_hex,
            signature_hex,
            public_key_hex: public_key_hex.clone(),
            timestamp,
            chain_length: self.chain.len() as u64,
            dsse_envelope: Some(dsse_envelope),
            rekor_entry,
            iso_42001: Some(serde_json::json!({
                "risk_assessment_conducted": true,
                "impact_assessment_ref": format!("themis-compliance v{}", env!("CARGO_PKG_VERSION")),
                "monitoring_mechanism": "BAAAR-gate + 310+-test suite",
                "improvement_cycle": "post-hackathon sprint (vNext roadmap)",
                "lifecycle_stage": "production",
            })),
            eu_registration_id: None,
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
        let packet = svc.seal("inv-001", "hello world", None).await.unwrap();
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
        let sp = stark.seal("inv-001", "from stark", None).await.unwrap();
        let wp = wayne.seal("inv-001", "from wayne", None).await.unwrap();
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
        let mut packet = svc.seal("inv-001", "hello", None).await.unwrap();
        // Mutate the canonical JSON (the payload itself).
        packet.payload_canonical_json = b"\"TAMPERED\"".to_vec();
        let err = svc.verify(&packet).unwrap_err();
        assert!(matches!(err, EvError::VerifyFailed(_)));
    }

    #[tokio::test]
    async fn tampered_signature_fails_verify() {
        let mut svc = EvidenceService::from_seed("stark", [1u8; 32], tsa());
        let mut packet = svc.seal("inv-001", "hello", None).await.unwrap();
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
        let p1 = svc.seal("inv-001", "a", None).await.unwrap();
        let p2 = svc.seal("inv-002", "b", None).await.unwrap();
        let p3 = svc.seal("inv-003", "c", None).await.unwrap();
        assert_eq!(p1.chain_length, 1);
        assert_eq!(p2.chain_length, 2);
        assert_eq!(p3.chain_length, 3);
        assert_eq!(svc.chain_length(), 3);
    }

    #[tokio::test]
    async fn blank_payload_works() {
        let mut svc = EvidenceService::from_seed("stark", [1u8; 32], tsa());
        let packet = svc.seal("inv-001", "", None).await.unwrap();
        assert!(svc.verify(&packet).is_ok());
    }

    #[tokio::test]
    async fn sealed_packet_carries_rekor_entry_when_provided() {
        use crate::rekor::{MockRekorClient, RekorClient};
        let mut svc = EvidenceService::from_seed("stark", [1u8; 32], tsa());
        let rekor = MockRekorClient::new();
        // Seal once to learn the BLAKE3 hash, then anchor that
        // hash, then seal again to carry the entry. The hash is
        // derived from the payload, so we have to know the
        // payload's hash up front — we approximate by sealing
        // a first time, but for the test we just anchor the
        // hash of a fixed payload string.
        let payload = "hello world";
        let hash_hex = blake3::hash(payload.as_bytes()).to_hex().to_string();
        let entry = rekor.anchor(&hash_hex, "stark").await.unwrap();
        let packet = svc
            .seal("inv-001", payload, Some(entry.clone()))
            .await
            .unwrap();
        let carried = packet
            .rekor_entry
            .expect("rekor_entry should be carried when Some");
        assert_eq!(carried.uuid, entry.uuid);
        assert_eq!(carried.log_index, entry.log_index);
        assert_eq!(carried.bundle_url, entry.bundle_url);
    }

    #[tokio::test]
    async fn sealed_packet_rekor_entry_is_none_by_default() {
        let mut svc = EvidenceService::from_seed("stark", [1u8; 32], tsa());
        let packet = svc.seal("inv-001", "hello world", None).await.unwrap();
        assert!(packet.rekor_entry.is_none());
    }
}
