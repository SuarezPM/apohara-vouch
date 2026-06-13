//! Provenance Signer — the last core agent. Takes all upstream
//! decisions, serializes to canonical JSON, computes BLAKE3 hash,
//! signs with Ed25519, and emits the signed Evidence Packet stub.
//!
//! Multi-tenant: each tenant has its own keypair (Stark / Wayne).
//! In production the keys live in `keys/{tenant}.ed25519` (chmod 600)
//! or are baked at compile time via `include_bytes!` for the demo.

use async_trait::async_trait;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::decision::{AgentDecision, AgentError, DecisionType};
use crate::traits::{Agent, AgentContext};

/// A tenant's signing keypair. In production this is loaded from
/// `keys/{tenant}.ed25519`; in tests we construct directly.
#[derive(Debug, Clone)]
pub struct Ed25519Keypair {
    /// Tenant identifier (e.g. "stark", "wayne").
    pub tenant_id: String,
    /// Stable key identifier (for rotation logs).
    pub key_id: String,
    /// The signing key (private).
    signing_key: SigningKey,
}

impl Ed25519Keypair {
    /// Generate a fresh random keypair for a tenant.
    pub fn generate(tenant_id: impl Into<String>) -> Self {
        use rand::RngCore;
        let mut csprng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let key_id = format!("{}-{}", tenant_id.into(), hex::encode(&bytes[..4]));
        Self {
            tenant_id: key_id.split('-').next().unwrap_or("unknown").to_string(),
            key_id,
            signing_key,
        }
    }

    /// Construct from raw 32-byte private key seed. For loading from
    /// `keys/{tenant}.ed25519` in production.
    pub fn from_bytes(
        tenant_id: impl Into<String>,
        key_id: impl Into<String>,
        seed: [u8; 32],
    ) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        Self {
            tenant_id: tenant_id.into(),
            key_id: key_id.into(),
            signing_key,
        }
    }

    /// Hex-encoded public key (32 bytes = 64 hex chars).
    pub fn public_key_hex(&self) -> String {
        let pk: VerifyingKey = self.signing_key.verifying_key();
        hex::encode(pk.to_bytes())
    }

    /// Sign a message, returning the signature as 64-byte hex.
    pub fn sign(&self, message: &[u8]) -> String {
        let sig: Signature = self.signing_key.sign(message);
        hex::encode(sig.to_bytes())
    }

    /// Verify a signature. Helper for tests + the Regression Tester
    /// shadow agent.
    pub fn verify(&self, message: &[u8], signature_hex: &str) -> bool {
        let Ok(sig_bytes) = hex::decode(signature_hex) else {
            return false;
        };
        let Ok(sig_array) = sig_bytes.as_slice().try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(sig_array);
        let pk: VerifyingKey = self.signing_key.verifying_key();
        pk.verify_strict(message, &sig).is_ok()
    }
}

/// Output of the Provenance Signer: a signed Evidence Packet stub
/// (full Evidence Packet is in `themis-evidence`; this is the
/// agent-side envelope).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceOutput {
    /// BLAKE3 hash of the canonical-JSON-serialized upstream chain.
    pub blake3_hash_hex: String,
    /// Ed25519 signature over the BLAKE3 hash.
    pub signature_hex: String,
    /// Hex-encoded public key for verification.
    pub public_key_hex: String,
    /// Key identifier (for rotation logs).
    pub key_id: String,
    /// Tenant identifier.
    pub tenant_id: String,
    /// The canonical-JSON-serialized upstream chain (for replay).
    pub canonical_payload_hex: String,
}

/// The Provenance Signer agent.
pub struct ProvenanceSigner {
    keypair: Ed25519Keypair,
}

impl ProvenanceSigner {
    /// New signer for a tenant.
    pub fn new(keypair: Ed25519Keypair) -> Self {
        Self { keypair }
    }
}

#[async_trait]
impl Agent for ProvenanceSigner {
    fn name(&self) -> &'static str {
        "provenance_signer"
    }

    async fn process(&self, ctx: AgentContext) -> Result<AgentDecision, AgentError> {
        if ctx.upstream_decisions.is_empty() {
            return Err(AgentError::InvalidInput(
                "ProvenanceSigner: upstream_decisions is empty".to_string(),
            ));
        }

        // Canonical JSON: serde_json's default is stable enough for
        // the demo (no HashMap nondeterminism — we sort maps
        // elsewhere). For production: use a canonical-JSON crate.
        let canonical = serde_json::to_vec(&ctx.upstream_decisions).map_err(|e| {
            AgentError::Internal(format!("ProvenanceSigner: serialize upstream: {e}"))
        })?;

        let blake3_hash = blake3::hash(&canonical);
        let blake3_hash_hex = blake3_hash.to_hex().to_string();

        // Sign the BLAKE3 hash (not the raw payload — hash-then-sign
        // is the standard pattern).
        let signature_hex = self.keypair.sign(blake3_hash.as_bytes());

        let output = ProvenanceOutput {
            blake3_hash_hex: blake3_hash_hex.clone(),
            signature_hex: signature_hex.clone(),
            public_key_hex: self.keypair.public_key_hex(),
            key_id: self.keypair.key_id.clone(),
            tenant_id: self.keypair.tenant_id.clone(),
            canonical_payload_hex: hex::encode(&canonical),
        };

        let reasoning = format!(
            "Signed {} upstream decisions (BLAKE3={}…{}, sig={}…)",
            ctx.upstream_decisions.len(),
            &blake3_hash_hex[..16],
            blake3_hash_hex.len(),
            &signature_hex[..16]
        );

        Ok(AgentDecision {
            agent_id: self.name().to_string(),
            tenant_id: ctx.tenant_id,
            invoice_id: ctx.invoice_id,
            decision_type: DecisionType::ProvenanceSigned,
            confidence: 1.0,
            reasoning,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            payload: serde_json::to_value(&output).map_err(|e| {
                AgentError::Internal(format!("ProvenanceSigner: serialize output: {e}"))
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::DecisionType;

    fn make_decision(i: usize) -> AgentDecision {
        AgentDecision {
            agent_id: format!("agent-{i}"),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: DecisionType::Extracted,
            confidence: 0.9,
            reasoning: format!("decision {i}"),
            timestamp_ms: 1_700_000_000_000 + i as i64,
            payload: serde_json::json!({"i": i}),
        }
    }

    #[tokio::test]
    async fn sign_then_verify_roundtrip() {
        let kp = Ed25519Keypair::generate("stark");
        // The signer holds a CLONE of kp; the test holds kp. Same
        // underlying key bytes (Ed25519Keypair is Clone). Verify
        // works because both clones share the same secret.
        let agent = ProvenanceSigner::new(kp.clone());
        let ctx = AgentContext::new("stark", "inv-001")
            .with_upstream(make_decision(0))
            .with_upstream(make_decision(1));
        let d = agent.process(ctx).await.unwrap();
        let out: ProvenanceOutput = serde_json::from_value(d.payload).unwrap();
        // The signer signs the RAW 32 bytes of the BLAKE3 hash, not
        // the hex string. Reconstruct the raw bytes from the hex to
        // verify with the same key.
        let raw_hash = hex::decode(&out.blake3_hash_hex).unwrap();
        assert!(kp.verify(&raw_hash, &out.signature_hex));
    }

    #[tokio::test]
    async fn signature_is_128_hex_chars() {
        let kp = Ed25519Keypair::generate("stark");
        let agent = ProvenanceSigner::new(kp);
        let ctx = AgentContext::new("stark", "inv-001").with_upstream(make_decision(0));
        let d = agent.process(ctx).await.unwrap();
        let out: ProvenanceOutput = serde_json::from_value(d.payload).unwrap();
        assert_eq!(out.signature_hex.len(), 128); // 64 bytes
        assert_eq!(out.public_key_hex.len(), 64); // 32 bytes
        assert_eq!(out.blake3_hash_hex.len(), 64); // 32 bytes
    }

    #[tokio::test]
    async fn multi_tenant_distinct_signatures() {
        let stark_kp = Ed25519Keypair::generate("stark");
        let wayne_kp = Ed25519Keypair::generate("wayne");
        let stark_agent = ProvenanceSigner::new(stark_kp.clone());
        let wayne_agent = ProvenanceSigner::new(wayne_kp.clone());

        let ctx_stark = AgentContext::new("stark", "inv-001").with_upstream(make_decision(0));
        let ctx_wayne = AgentContext::new("wayne", "inv-001").with_upstream(make_decision(0));

        let d_stark = stark_agent.process(ctx_stark).await.unwrap();
        let d_wayne = wayne_agent.process(ctx_wayne).await.unwrap();

        let out_stark: ProvenanceOutput = serde_json::from_value(d_stark.payload).unwrap();
        let out_wayne: ProvenanceOutput = serde_json::from_value(d_wayne.payload).unwrap();

        // Same upstream decisions but different keys → different sigs.
        assert_ne!(out_stark.signature_hex, out_wayne.signature_hex);
        assert_ne!(out_stark.public_key_hex, out_wayne.public_key_hex);
        // The BLAKE3 hash should be the same (same canonical payload,
        // same timestamp).
        assert_eq!(out_stark.blake3_hash_hex, out_wayne.blake3_hash_hex);
    }

    #[tokio::test]
    async fn empty_upstream_returns_invalid_input() {
        let kp = Ed25519Keypair::generate("stark");
        let agent = ProvenanceSigner::new(kp);
        let ctx = AgentContext::new("stark", "inv-001");
        let err = agent.process(ctx).await.unwrap_err();
        assert!(matches!(err, AgentError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn different_payload_produces_different_signature() {
        let kp = Ed25519Keypair::generate("stark");
        let agent = ProvenanceSigner::new(kp.clone());
        let ctx_a = AgentContext::new("stark", "inv-001").with_upstream(make_decision(0));
        let ctx_b = AgentContext::new("stark", "inv-002").with_upstream(make_decision(1));
        let d_a = agent.process(ctx_a).await.unwrap();
        let d_b = agent.process(ctx_b).await.unwrap();
        let out_a: ProvenanceOutput = serde_json::from_value(d_a.payload).unwrap();
        let out_b: ProvenanceOutput = serde_json::from_value(d_b.payload).unwrap();
        assert_ne!(out_a.blake3_hash_hex, out_b.blake3_hash_hex);
        assert_ne!(out_a.signature_hex, out_b.signature_hex);
    }

    #[test]
    fn from_bytes_round_trip() {
        let kp1 = Ed25519Keypair::from_bytes("stark", "k1", [1u8; 32]);
        let kp2 = Ed25519Keypair::from_bytes("stark", "k1", [1u8; 32]);
        assert_eq!(kp1.public_key_hex(), kp2.public_key_hex());
        let sig1 = kp1.sign(b"hello");
        let sig2 = kp2.sign(b"hello");
        assert_eq!(sig1, sig2);
    }
}
