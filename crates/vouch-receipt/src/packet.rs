//! Evidence packet — the 8-field EU AI Act Art. 12 envelope.
//!
//! This crate's `EvidencePacket` is the JSON wire format the
//! `POST /seal` endpoint emits and the `vouch-verify` CLI
//! consumes. It wraps a `SealedPacket` (from vouch-evidence)
//! and adds the 8 EU AI Act Art. 12 fields.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use vouch_evidence::SealedPacket;

use crate::{Art12Coverage, C2paManifest, EU_AI_ACT_ART12_FIELDS};

/// The 8-field EU AI Act Art. 12 envelope that wraps a
/// sealed evidence packet. The HTTP `/seal` endpoint serializes
/// this directly. AC-3.5 (JSON Schema round-trip) + AC-3.9
/// (≥7/8 populated).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidencePacket {
    /// case_id — the orchestrator's case identifier (correlates
    /// to a specific invoice + tenant).
    pub case_id: String,
    /// Agent outputs aggregated into this packet (one per
    /// agent that contributed a decision).
    pub agent_outputs: Vec<AgentOutput>,
    /// Optional explicit hash-chain link (the BLAKE3 root of
    /// the chain the packet extends).
    pub hash_chain_link: Option<String>,
    /// ISO 8601 UTC — start time of the decision window.
    pub start_time: DateTime<Utc>,
    /// ISO 8601 UTC — end time of the decision window.
    pub end_time: DateTime<Utc>,
    /// Reference database used (e.g. "stanford-invoicenet-50").
    pub reference_database: String,
    /// The input data identifier (invoice id).
    pub input_data: String,
    /// Optional natural person id (operator).
    pub natural_person_id: Option<String>,
    /// Decision id (UUID).
    pub decision_id: String,
    /// Policy version baked into the agent (e.g. "apohara-vouch-1").
    pub policy_version: String,
    /// Hash chain previous link (BLAKE3 root or all-zero for genesis).
    pub hash_chain_prev: String,
    /// Optional C2PA manifest (populated when C2PA signing is enabled).
    pub c2pa_manifest: Option<C2paManifest>,
    /// Embedded sealed packet (optional — present when the
    /// orchestrator signs inline).
    pub sealed: Option<SealedPacket>,
}

/// A single agent decision that contributed to this packet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentOutput {
    /// Agent id (e.g. "extractor", "po-matcher", "fraud-auditor",
    /// "gaap-classifier", "provenance-signer").
    pub agent_id: String,
    /// Agent's verdict: "approve" | "halt" | "review_required".
    pub verdict: String,
    /// Human-readable summary.
    pub summary: String,
    /// Optional risk score (0.0..=1.0).
    pub risk_score: Option<f32>,
}

impl EvidencePacket {
    /// Build a packet with the 8 EU AI Act Art. 12 fields
    /// populated by default. All 8 fields populate when
    /// `sealed` is provided.
    ///
    /// `natural_person_id` (EU AI Act Art. 12 §4 — deployer
    /// identity) is REQUIRED. Callers must pass either:
    /// - the operator's email at the call site (preferred — read
    ///   from the tenant registry or request context), or
    /// - [`EvidencePacket::load_operator_email`] to read from
    ///   the `VOUCH_OPERATOR_EMAIL` env var.
    ///
    /// Hardcoding the operator email was the original
    /// implementation; it violated Art. 12 §4 (identity of the
    /// actual deployer, not a placeholder). The audit (#867,
    /// finding P1) flagged this; the fix makes the value
    /// explicit at every call site.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        case_id: impl Into<String>,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        reference_database: impl Into<String>,
        input_data: impl Into<String>,
        decision_id: impl Into<String>,
        policy_version: impl Into<String>,
        hash_chain_prev: impl Into<String>,
        natural_person_id: impl Into<String>,
        agent_outputs: Vec<AgentOutput>,
        sealed: Option<SealedPacket>,
    ) -> Self {
        Self {
            case_id: case_id.into(),
            agent_outputs,
            hash_chain_link: None,
            start_time,
            end_time,
            reference_database: reference_database.into(),
            input_data: input_data.into(),
            natural_person_id: Some(natural_person_id.into()),
            decision_id: decision_id.into(),
            policy_version: policy_version.into(),
            hash_chain_prev: hash_chain_prev.into(),
            c2pa_manifest: None,
            sealed,
        }
    }

    /// Load the deployer / operator email from the
    /// `VOUCH_OPERATOR_EMAIL` env var. Returns `Err` if unset —
    /// we never fall back to a hardcoded value (audit #867
    /// finding P1: a hardcoded operator email violates EU AI
    /// Act Art. 12 §4 because the deployer field must reflect
    /// the ACTUAL operator of the regulated AI system, not a
    /// placeholder).
    ///
    /// Callers that want a builder that fills in the env var
    /// for them should use [`build_with_env`] (added in the
    /// same audit fix).
    pub fn load_operator_email() -> Result<String, OperatorEmailError> {
        match std::env::var("VOUCH_OPERATOR_EMAIL") {
            Ok(s) if !s.trim().is_empty() => Ok(s),
            Ok(_) => Err(OperatorEmailError::EmptyEnv),
            Err(_) => Err(OperatorEmailError::UnsetEnv),
        }
    }

    /// Convenience: build a packet with the operator email read
    /// from `VOUCH_OPERATOR_EMAIL`. Returns Err if the env var
    /// is unset or blank — the audit (#867) flagged the previous
    /// hardcoded value as a regulatory blocker.
    #[allow(clippy::too_many_arguments)]
    pub fn build_with_env(
        case_id: impl Into<String>,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        reference_database: impl Into<String>,
        input_data: impl Into<String>,
        decision_id: impl Into<String>,
        policy_version: impl Into<String>,
        hash_chain_prev: impl Into<String>,
        agent_outputs: Vec<AgentOutput>,
        sealed: Option<SealedPacket>,
    ) -> Result<Self, OperatorEmailError> {
        let operator = Self::load_operator_email()?;
        Ok(Self::build(
            case_id,
            start_time,
            end_time,
            reference_database,
            input_data,
            decision_id,
            policy_version,
            hash_chain_prev,
            operator,
            agent_outputs,
            sealed,
        ))
    }

    /// Build the 8-field coverage report. AC-3.9: ≥7/8 must
    /// be populated for Article 12 compliance.
    pub fn art12_coverage(&self) -> Vec<Art12Coverage> {
        let f = |name: &'static str, populated: bool| Art12Coverage {
            field: name,
            populated,
        };
        vec![
            f(
                EU_AI_ACT_ART12_FIELDS[0],
                !self.start_time.to_rfc3339().is_empty(),
            ),
            f(
                EU_AI_ACT_ART12_FIELDS[1],
                !self.end_time.to_rfc3339().is_empty(),
            ),
            f(
                EU_AI_ACT_ART12_FIELDS[2],
                !self.reference_database.is_empty(),
            ),
            f(EU_AI_ACT_ART12_FIELDS[3], !self.input_data.is_empty()),
            f(EU_AI_ACT_ART12_FIELDS[4], self.natural_person_id.is_some()),
            f(EU_AI_ACT_ART12_FIELDS[5], !self.decision_id.is_empty()),
            f(EU_AI_ACT_ART12_FIELDS[6], !self.policy_version.is_empty()),
            f(EU_AI_ACT_ART12_FIELDS[7], !self.hash_chain_prev.is_empty()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet() -> EvidencePacket {
        let start: DateTime<Utc> = "2026-06-18T12:00:00Z".parse().unwrap();
        let end: DateTime<Utc> = "2026-06-18T12:01:30Z".parse().unwrap();
        EvidencePacket::build(
            "case-001",
            start,
            end,
            "stanford-invoicenet-50",
            "inv-001",
            "00000000-0000-0000-0000-000000000001",
            "apohara-vouch-1",
            "0".repeat(64),
            "operator@example.com",
            vec![AgentOutput {
                agent_id: "fraud-auditor".into(),
                verdict: "halt".into(),
                summary: "secret detected".into(),
                risk_score: Some(0.92),
            }],
            None,
        )
    }

    #[test]
    fn build_populates_all_eight_art12_fields() {
        let p = sample_packet();
        let coverage = p.art12_coverage();
        assert_eq!(coverage.len(), 8);
        assert!(coverage.iter().all(|c| c.populated));
        assert!(Art12Coverage::is_compliant(&coverage));
    }

    #[test]
    fn json_round_trip_preserves_all_fields() {
        let p = sample_packet();
        let s = serde_json::to_string(&p).unwrap();
        let back: EvidencePacket = serde_json::from_str(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn missing_natural_person_drops_to_seven_of_eight() {
        let mut p = sample_packet();
        p.natural_person_id = None;
        let coverage = p.art12_coverage();
        let populated = coverage.iter().filter(|c| c.populated).count();
        assert_eq!(populated, 7);
        assert!(Art12Coverage::is_compliant(&coverage));
    }

    #[test]
    fn empty_reference_database_fails_compliance() {
        let mut p = sample_packet();
        p.reference_database = String::new();
        let coverage = p.art12_coverage();
        let populated = coverage.iter().filter(|c| c.populated).count();
        assert_eq!(populated, 7);
        assert!(Art12Coverage::is_compliant(&coverage));
    }

    #[test]
    fn empty_decision_id_fails_compliance() {
        let mut p = sample_packet();
        p.decision_id = String::new();
        let coverage = p.art12_coverage();
        let populated = coverage.iter().filter(|c| c.populated).count();
        assert_eq!(populated, 7);
        assert!(Art12Coverage::is_compliant(&coverage));
    }
}

/// Error returned by `load_operator_email` when the env var
/// is unset or blank. Maps to a 500 from the HTTP layer if
/// the operator forgot to set up the deployer identity.
#[derive(Debug, thiserror::Error)]
pub enum OperatorEmailError {
    #[error("VOUCH_OPERATOR_EMAIL env var is not set; cannot populate EU AI Act Art. 12 §4 deployer identity")]
    UnsetEnv,
    #[error("VOUCH_OPERATOR_EMAIL env var is set but blank; cannot populate EU AI Act Art. 12 §4 deployer identity")]
    EmptyEnv,
}
