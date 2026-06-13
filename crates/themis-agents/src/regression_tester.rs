//! Regression Tester (shadow) — re-verifies a signed Evidence Packet.
//!
//! Read-only. Re-runs the Ed25519 signature verification + BLAKE3
//! hash check on the Provenance Signer's output. Used as the second
//! line of defense: if the BAAAR HALT didn't catch tampering, the
//! Regression Tester will.

use async_trait::async_trait;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::decision::{AgentDecision, AgentError, DecisionType};
use crate::provenance_signer::ProvenanceOutput;
use crate::traits::{Agent, AgentContext};

/// The Regression Tester's output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegressionResult {
    /// True iff signature AND hash check both pass.
    pub verified: bool,
    /// True iff the Ed25519 signature is valid.
    pub signature_valid: bool,
    /// True iff the BLAKE3 hash matches the canonical payload.
    pub hash_chain_valid: bool,
    /// Reason for failure (empty on success).
    pub reason: String,
}

/// The Regression Tester shadow agent.
pub struct RegressionTester;

impl RegressionTester {
    /// New tester.
    pub fn new() -> Self {
        Self
    }
}

impl Default for RegressionTester {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Agent for RegressionTester {
    fn name(&self) -> &'static str {
        "regression_tester"
    }

    async fn process(&self, ctx: AgentContext) -> Result<AgentDecision, AgentError> {
        // Find the Provenance Signer's output in the chain.
        let signed = ctx
            .upstream_decisions
            .iter()
            .find(|d| d.decision_type == DecisionType::ProvenanceSigned)
            .ok_or_else(|| {
                AgentError::InvalidInput(
                    "RegressionTester: no ProvenanceSigned in upstream_decisions".to_string(),
                )
            })?;

        let prov: ProvenanceOutput =
            serde_json::from_value(signed.payload.clone()).map_err(|e| {
                AgentError::LlmMalformedPayload(format!(
                "RegressionTester: upstream ProvenanceSigned payload is not ProvenanceOutput: {e}"
            ))
            })?;

        // 1. Hash check: recompute BLAKE3 over the canonical payload.
        let canonical = hex::decode(&prov.canonical_payload_hex).map_err(|e| {
            AgentError::Internal(format!("RegressionTester: hex decode canonical: {e}"))
        })?;
        let recomputed = blake3::hash(&canonical);
        let hash_chain_valid = recomputed.to_hex().to_string() == prov.blake3_hash_hex;

        // 2. Signature check: verify Ed25519(public_key, raw_hash, sig).
        // The signer signs the RAW 32 bytes of the BLAKE3 hash, not
        // the hex string. Decode the hex to get the raw bytes.
        let signature_valid = if let Ok(raw_hash) = hex::decode(&prov.blake3_hash_hex) {
            verify_ed25519(&prov.public_key_hex, &raw_hash, &prov.signature_hex)
        } else {
            false
        };

        let verified = hash_chain_valid && signature_valid;
        let reason = if verified {
            "Signature + hash chain both valid".to_string()
        } else {
            format!(
                "verification failed: hash_chain={}, signature={}",
                hash_chain_valid, signature_valid
            )
        };

        let result = RegressionResult {
            verified,
            signature_valid,
            hash_chain_valid,
            reason: reason.clone(),
        };

        Ok(AgentDecision {
            agent_id: self.name().to_string(),
            tenant_id: ctx.tenant_id,
            invoice_id: ctx.invoice_id,
            decision_type: DecisionType::RegressionResult,
            confidence: 1.0,
            reasoning: reason,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            payload: serde_json::to_value(&result).map_err(|e| {
                AgentError::Internal(format!("RegressionTester: serialize result: {e}"))
            })?,
        })
    }
}

fn verify_ed25519(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let pk_bytes = match hex::decode(public_key_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk_array: [u8; 32] = match pk_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pk = match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_array: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_array);

    pk.verify_strict(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance_signer::{Ed25519Keypair, ProvenanceSigner};

    #[tokio::test]
    async fn verifies_a_valid_signature() {
        let kp = Ed25519Keypair::generate("stark");
        let signer = ProvenanceSigner::new(kp.clone());
        let upstream = AgentContext::new("stark", "inv-001").with_upstream(AgentDecision {
            agent_id: "extractor".to_string(),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: DecisionType::Extracted,
            confidence: 0.9,
            reasoning: "x".to_string(),
            timestamp_ms: 0,
            payload: serde_json::json!({"v": 1}),
        });
        let signed = signer.process(upstream).await.unwrap();

        let tester = RegressionTester::new();
        let ctx = AgentContext::new("stark", "inv-001").with_upstream(signed);
        let d = tester.process(ctx).await.unwrap();
        let r: RegressionResult = serde_json::from_value(d.payload).unwrap();
        assert!(r.verified, "reason: {}", r.reason);
        assert!(r.signature_valid);
        assert!(r.hash_chain_valid);
    }

    #[tokio::test]
    async fn rejects_tampered_hash() {
        // Build a packet, then mutate the canonical payload hex to
        // simulate tampering.
        let kp = Ed25519Keypair::generate("stark");
        let signer = ProvenanceSigner::new(kp.clone());
        let upstream = AgentContext::new("stark", "inv-001").with_upstream(AgentDecision {
            agent_id: "extractor".to_string(),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: DecisionType::Extracted,
            confidence: 0.9,
            reasoning: "x".to_string(),
            timestamp_ms: 0,
            payload: serde_json::json!({"v": 1}),
        });
        let signed = signer.process(upstream).await.unwrap();

        // Mutate the payload: flip a byte in canonical_payload_hex.
        let mut signed_payload = signed.payload.clone();
        let mut prov: ProvenanceOutput = serde_json::from_value(signed_payload.clone()).unwrap();
        let mut bytes = hex::decode(&prov.canonical_payload_hex).unwrap();
        bytes[0] ^= 0x01;
        prov.canonical_payload_hex = hex::encode(&bytes);
        signed_payload = serde_json::to_value(&prov).unwrap();
        let tampered = AgentDecision {
            payload: signed_payload,
            ..signed
        };

        let tester = RegressionTester::new();
        let ctx = AgentContext::new("stark", "inv-001").with_upstream(tampered);
        let d = tester.process(ctx).await.unwrap();
        let r: RegressionResult = serde_json::from_value(d.payload).unwrap();
        assert!(!r.verified);
        assert!(!r.hash_chain_valid);
    }

    #[tokio::test]
    async fn rejects_bad_signature() {
        let kp = Ed25519Keypair::generate("stark");
        let signer = ProvenanceSigner::new(kp);
        let upstream = AgentContext::new("stark", "inv-001").with_upstream(AgentDecision {
            agent_id: "extractor".to_string(),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: DecisionType::Extracted,
            confidence: 0.9,
            reasoning: "x".to_string(),
            timestamp_ms: 0,
            payload: serde_json::json!({"v": 1}),
        });
        let mut signed = signer.process(upstream).await.unwrap();
        // Mutate the signature to invalid bytes.
        let mut prov: ProvenanceOutput = serde_json::from_value(signed.payload.clone()).unwrap();
        prov.signature_hex = "00".repeat(64);
        signed.payload = serde_json::to_value(&prov).unwrap();

        let tester = RegressionTester::new();
        let ctx = AgentContext::new("stark", "inv-001").with_upstream(signed);
        let d = tester.process(ctx).await.unwrap();
        let r: RegressionResult = serde_json::from_value(d.payload).unwrap();
        assert!(!r.verified);
        assert!(!r.signature_valid);
    }

    #[tokio::test]
    async fn missing_upstream_signer_returns_invalid_input() {
        let tester = RegressionTester::new();
        let err = tester
            .process(AgentContext::new("stark", "inv-001"))
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::InvalidInput(_)));
    }
}
