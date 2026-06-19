//! EvidencePacket — the canonical signed output of a run.
//!
//! 7 framework booleans (DORA Art 9/10/17, EU AI Act Art 12/26, NIST
//! AI RMF, OWASP Agentic) all default to `true` for a fully-mapped
//! packet. The `bbaaar_outcome` field carries the gate verdict.
//!
//! The `SignedPacket` envelope wraps the packet with an Ed25519
//! signature + BLAKE3 hash. Real signing is in `themis-evidence`;
//! this module just defines the shape.

use serde::{Deserialize, Serialize};
use themis_agents::baaar::Outcome;
use themis_agents::decision::AgentDecision;
use uuid::Uuid;

fn new_packet_id() -> Uuid {
    Uuid::new_v4()
}

/// Compliance framework mappings. All 7 fields default to `true` —
/// the framework coverage is the whole point of the Evidence Packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameworkMappings {
    /// DORA Art 9 (ICT risk management).
    pub dora_art_9: bool,
    /// DORA Art 10 (incident detection).
    pub dora_art_10: bool,
    /// DORA Art 17 (incident reporting).
    pub dora_art_17: bool,
    /// EU AI Act Art 12 (record-keeping for high-risk AI).
    pub eu_ai_act_art_12: bool,
    /// EU AI Act Art 26 (deployer obligations).
    pub eu_ai_act_art_26: bool,
    /// NIST AI RMF (Govern/Map/Measure/Manage).
    pub nist_ai_rmf: bool,
    /// OWASP Agentic 2026 (ASI01-ASI10).
    pub owasp_agentic: bool,
}

impl Default for FrameworkMappings {
    fn default() -> Self {
        Self {
            dora_art_9: true,
            dora_art_10: true,
            dora_art_17: true,
            eu_ai_act_art_12: true,
            eu_ai_act_art_26: true,
            nist_ai_rmf: true,
            owasp_agentic: true,
        }
    }
}

impl FrameworkMappings {
    /// Number of frameworks mapped (for AC15: ≥7 of 8 EU AI Act
    /// Art 12 fields populated — note this is the framework
    /// coverage, not the field count).
    pub fn coverage_count(&self) -> usize {
        [
            self.dora_art_9,
            self.dora_art_10,
            self.dora_art_17,
            self.eu_ai_act_art_12,
            self.eu_ai_act_art_26,
            self.nist_ai_rmf,
            self.owasp_agentic,
        ]
        .iter()
        .filter(|&&x| x)
        .count()
    }
}

/// Independent fraud-auditor verdict from a peer agent
/// (PydanticAI, LangGraph, CrewAI) that joined the Band room
/// and emitted a structured opinion. Stored alongside the
/// orchestrator's own agent decisions so the Evidence Packet
/// can attest to multi-framework agreement (Story C-12 / G27).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerVerdict {
    /// Agent name (e.g. ``"peer_pydantic_ai"``).
    pub agent: String,
    /// Risk score 0.0 (safe) to 1.0 (definite fraud).
    pub risk_score: f64,
    /// Free-form findings.
    pub findings: Vec<String>,
    /// ``"approve"`` or ``"halt"``.
    pub recommendation: String,
    /// Unix epoch ms when the peer emitted the verdict.
    pub timestamp_ms: i64,
}

/// The canonical Evidence Packet. One per invoice run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidencePacket {
    /// Unique packet id (UUID v4).
    pub packet_id: Uuid,
    /// Tenant identifier (Stark or Wayne).
    pub tenant_id: String,
    /// Invoice being processed.
    pub invoice_id: String,
    /// Chain of agent decisions, in order.
    pub agent_decisions: Vec<AgentDecision>,
    /// Schema version (bump when the wire format changes).
    pub evidence_packet_v: u32,
    /// Unix epoch ms when the packet was sealed.
    pub generated_at_ms: i64,
    /// BAAAR gate verdict (Approve or Halt(reason)).
    pub bbaaar_outcome: Outcome,
    /// Framework coverage. All 7 default to `true`.
    pub framework_mappings: FrameworkMappings,
    /// Independent verdicts from peer agents (PydanticAI,
    /// LangGraph, CrewAI). Empty when no peer responded
    /// before the BAAAR gate sealed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_verdicts: Vec<PeerVerdict>,
}

impl EvidencePacket {
    /// New packet for a (tenant, invoice) pair with the given
    /// decisions. `evidence_packet_v` defaults to 1; the caller can
    /// bump it when the schema changes.
    pub fn new(
        tenant_id: impl Into<String>,
        invoice_id: impl Into<String>,
        decisions: Vec<AgentDecision>,
        outcome: Outcome,
    ) -> Self {
        Self {
            packet_id: new_packet_id(),
            tenant_id: tenant_id.into(),
            invoice_id: invoice_id.into(),
            agent_decisions: decisions,
            evidence_packet_v: 1,
            generated_at_ms: chrono::Utc::now().timestamp_millis(),
            bbaaar_outcome: outcome,
            framework_mappings: FrameworkMappings::default(),
            peer_verdicts: Vec::new(),
        }
    }

    /// Append a peer verdict. Used by the A2A bridge when a
    /// ``peer_verdict`` envelope arrives from the Band room.
    pub fn attach_peer_verdict(&mut self, verdict: PeerVerdict) {
        self.peer_verdicts.push(verdict);
    }

    /// Serialize the packet to canonical JSON bytes. The current
    /// implementation uses serde_json's default ordering; for
    /// cross-platform determinism a canonical-JSON crate is a
    /// follow-up (see honest gaps in the plan).
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// BLAKE3 hash of the canonical JSON (hex, 32 bytes = 64 chars).
    pub fn blake3_hash(&self) -> String {
        let bytes = self
            .to_canonical_json()
            .expect("EvidencePacket serialization is infallible for valid structs");
        blake3::hash(&bytes).to_hex().to_string()
    }
}

/// The signed envelope. Real Ed25519 signing is in `themis-evidence`;
/// this struct is the shape the orchestrator hands back to callers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedPacket {
    /// The canonical packet.
    pub packet: EvidencePacket,
    /// Hex-encoded Ed25519 signature over the BLAKE3 hash.
    pub signature_hex: String,
    /// Hex-encoded public key (for verification).
    pub public_key_hex: String,
    /// Hex-encoded BLAKE3 hash of the packet.
    pub blake3_hash_hex: String,
    /// Rekor transparency-log entry for this packet (if anchoring
    /// was enabled at orchestrator construction time). `None` if
    /// the orchestrator was built without a Rekor client (back-compat
    /// for the demo / mock-only path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekor_entry: Option<themis_evidence::rekor::RekorEntry>,
}

impl SignedPacket {
    /// Wrap an `EvidencePacket` with a signature + hash.
    pub fn wrap(packet: EvidencePacket, signature_hex: String, public_key_hex: String) -> Self {
        let blake3_hash_hex = packet.blake3_hash();
        Self {
            packet,
            signature_hex,
            public_key_hex,
            blake3_hash_hex,
            rekor_entry: None,
        }
    }

    /// Wrap an `EvidencePacket` with a signature + hash + Rekor entry.
    /// Used by the orchestrator when a Rekor client is configured.
    pub fn wrap_with_rekor(
        packet: EvidencePacket,
        signature_hex: String,
        public_key_hex: String,
        rekor_entry: themis_evidence::rekor::RekorEntry,
    ) -> Self {
        let blake3_hash_hex = packet.blake3_hash();
        Self {
            packet,
            signature_hex,
            public_key_hex,
            blake3_hash_hex,
            rekor_entry: Some(rekor_entry),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use themis_agents::decision::{AgentDecision, DecisionType};

    fn dec(tenant: &str) -> AgentDecision {
        AgentDecision {
            agent_id: "extractor".to_string(),
            tenant_id: tenant.to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: DecisionType::Extracted,
            confidence: 0.9,
            reasoning: "ok".to_string(),
            timestamp_ms: 0,
            payload: serde_json::json!({}),
        }
    }

    #[test]
    fn framework_mappings_default_all_true() {
        let m = FrameworkMappings::default();
        assert_eq!(m.coverage_count(), 7);
        assert!(m.dora_art_9);
        assert!(m.eu_ai_act_art_12);
        assert!(m.owasp_agentic);
    }

    #[test]
    fn framework_mappings_serde_roundtrip() {
        let m = FrameworkMappings::default();
        let json = serde_json::to_string(&m).unwrap();
        let parsed: FrameworkMappings = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn packet_serializes_to_non_empty_canonical_json() {
        let p = EvidencePacket::new("stark", "inv-001", vec![dec("stark")], Outcome::Approve);
        let bytes = p.to_canonical_json().unwrap();
        assert!(!bytes.is_empty());
        // Must contain the tenant_id in the JSON.
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("stark"));
        assert!(s.contains("inv-001"));
    }

    #[test]
    fn blake3_hash_is_64_hex_chars() {
        let p = EvidencePacket::new("stark", "inv-001", vec![], Outcome::Approve);
        let h = p.blake3_hash();
        assert_eq!(h.len(), 64);
        for c in h.chars() {
            assert!(c.is_ascii_hexdigit());
        }
    }

    #[test]
    fn signed_packet_carries_hash_and_signature() {
        let p = EvidencePacket::new("stark", "inv-001", vec![], Outcome::Approve);
        let sp = SignedPacket::wrap(p.clone(), "00".repeat(64), "11".repeat(32));
        assert_eq!(sp.packet, p);
        assert_eq!(sp.signature_hex, "00".repeat(64));
        assert_eq!(sp.public_key_hex, "11".repeat(32));
        assert_eq!(sp.blake3_hash_hex.len(), 64);
    }

    #[test]
    fn packet_round_trips_through_json() {
        let p = EvidencePacket::new(
            "wayne",
            "inv-002",
            vec![dec("wayne"), dec("wayne")],
            Outcome::Approve,
        );
        let json = serde_json::to_string(&p).unwrap();
        let parsed: EvidencePacket = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, p);
    }

    fn fake_peer_verdict(agent: &str, risk: f64, rec: &str) -> PeerVerdict {
        PeerVerdict {
            agent: agent.to_string(),
            risk_score: risk,
            findings: vec![format!("{agent} saw something")],
            recommendation: rec.to_string(),
            timestamp_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn peer_verdict_attaches_and_round_trips() {
        let mut p = EvidencePacket::new("stark", "inv-001", vec![dec("stark")], Outcome::Approve);
        assert!(p.peer_verdicts.is_empty());
        p.attach_peer_verdict(fake_peer_verdict("peer_pydantic_ai", 0.42, "approve"));
        p.attach_peer_verdict(fake_peer_verdict("peer_langgraph", 0.88, "halt"));
        assert_eq!(p.peer_verdicts.len(), 2);
        assert_eq!(p.peer_verdicts[0].agent, "peer_pydantic_ai");
        assert!((p.peer_verdicts[1].risk_score - 0.88).abs() < 1e-9);
        let json = serde_json::to_string(&p).unwrap();
        let parsed: EvidencePacket = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.peer_verdicts, p.peer_verdicts);
    }

    #[test]
    fn peer_verdict_json_contains_expected_keys() {
        // The JSON must carry the field under the documented name so
        // downstream consumers (compliance dashboard, EU AI Act
        // Art. 12 mapper) can find it without schema guessing.
        let mut p = EvidencePacket::new("stark", "inv-007", vec![], Outcome::Approve);
        p.attach_peer_verdict(fake_peer_verdict("peer_pydantic_ai", 0.73, "halt"));
        let s = serde_json::to_string(&p).unwrap();
        assert!(
            s.contains("\"peer_verdicts\""),
            "wire format missing peer_verdicts: {s}"
        );
        assert!(s.contains("\"peer_pydantic_ai\""));
        assert!(s.contains("\"risk_score\":0.73"));
        assert!(s.contains("\"recommendation\":\"halt\""));
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let arr = v["peer_verdicts"].as_array().expect("peer_verdicts array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["agent"], "peer_pydantic_ai");
    }

    #[test]
    fn empty_peer_verdicts_skip_in_wire_format() {
        let p = EvidencePacket::new("stark", "inv-empty", vec![], Outcome::Approve);
        let s = serde_json::to_string(&p).unwrap();
        assert!(
            !s.contains("peer_verdicts"),
            "empty peer_verdicts should be elided: {s}"
        );
    }

    #[test]
    fn legacy_packet_json_without_peer_verdicts_deserializes() {
        // Back-compat: packets sealed before C-12 / FIX-4 must still
        // load. The field has ``#[serde(default)]``; verify that.
        let legacy = serde_json::json!({
            "packet_id": "00000000-0000-0000-0000-000000000001",
            "tenant_id": "stark",
            "invoice_id": "inv-legacy",
            "agent_decisions": [],
            "evidence_packet_v": 1,
            "generated_at_ms": 1_700_000_000_000_i64,
            "bbaaar_outcome": "approve",
            "framework_mappings": {
                "dora_art_9": true,
                "dora_art_10": true,
                "dora_art_17": true,
                "eu_ai_act_art_12": true,
                "eu_ai_act_art_26": true,
                "nist_ai_rmf": true,
                "owasp_agentic": true,
            },
        });
        let p: EvidencePacket = serde_json::from_value(legacy).unwrap();
        assert!(p.peer_verdicts.is_empty());
    }
}
