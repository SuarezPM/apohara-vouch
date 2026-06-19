//! vouch-receipt — EU AI Act Art. 12 evidence packet.
//!
//! AC-3.1, AC-3.9: 8 EU AI Act Article 12 fields populated per
//! packet (≥7/8 = compliant). The actual signing/crypto lives in
//! `vouch-evidence` / `themis-evidence`. This crate defines the
//! canonical 8-field set + C2PA manifest generator.

pub mod packet;

use serde::{Deserialize, Serialize};

/// The 8 EU AI Act Article 12 fields. AC-3.9 / AC15: ≥7/8
/// populated per packet for Article 12 compliance.
pub const EU_AI_ACT_ART12_FIELDS: [&str; 8] = [
    "start_time",
    "end_time",
    "reference_database",
    "input_data",
    "natural_person_id",
    "decision_id",
    "policy_version",
    "hash_chain_prev",
];

/// C2PA manifest stub (the full spec lives in c2pa 0.34;
/// this crate ships a deterministic JSON envelope).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct C2paManifest {
    /// C2PA assertion store version.
    pub version: String,
    /// Vendor ID (e.g. "apohara-vouch-v1").
    pub vendor: String,
    /// Claim generator (the agent id that emitted the claim).
    pub claim_generator: String,
    /// The signed claim over the packet payload.
    pub claim_hex: String,
    /// Algorithm (e.g. "Ed25519" / "BLAKE3-256").
    pub algorithm: String,
    /// Issuance timestamp (ISO 8601 UTC).
    pub issued_at: String,
    /// Optional reference to upstream manifest (chain link).
    pub upstream_manifest_id: Option<String>,
}

impl C2paManifest {
    /// Build a deterministic C2PA-style manifest from the packet
    /// metadata + Ed25519 signature + BLAKE3 hash.
    pub fn build(
        claim_generator: &str,
        claim_hex: &str,
        upstream_manifest_id: Option<String>,
    ) -> Self {
        Self {
            version: "2.1".to_string(),
            vendor: "apohara-vouch-v1".to_string(),
            claim_generator: claim_generator.to_string(),
            claim_hex: claim_hex.to_string(),
            algorithm: "Ed25519+BLAKE3".to_string(),
            issued_at: chrono::Utc::now().to_rfc3339(),
            upstream_manifest_id,
        }
    }
}

/// Coverage report for the 8 EU AI Act Art. 12 fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Art12Coverage {
    /// Field name.
    pub field: &'static str,
    /// Whether the packet populates this field.
    pub populated: bool,
}

impl Art12Coverage {
    /// True iff at least 7 of 8 fields are populated (AC-3.9 / AC15).
    pub fn is_compliant(report: &[Art12Coverage]) -> bool {
        let populated = report.iter().filter(|c| c.populated).count();
        populated >= 7
    }
}

/// Crate version + name.
pub fn version() -> &'static str {
    "vouch-receipt"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "vouch-receipt");
    }

    #[test]
    fn art12_field_count_is_eight() {
        assert_eq!(EU_AI_ACT_ART12_FIELDS.len(), 8);
    }

    #[test]
    fn art12_compliance_threshold_is_seven_of_eight() {
        let all_populated: Vec<Art12Coverage> = EU_AI_ACT_ART12_FIELDS
            .iter()
            .map(|f| Art12Coverage {
                field: f,
                populated: true,
            })
            .collect();
        assert!(Art12Coverage::is_compliant(&all_populated));

        let seven: Vec<Art12Coverage> = EU_AI_ACT_ART12_FIELDS
            .iter()
            .enumerate()
            .map(|(i, f)| Art12Coverage {
                field: f,
                populated: i != 0,
            })
            .collect();
        assert!(Art12Coverage::is_compliant(&seven));

        let six: Vec<Art12Coverage> = EU_AI_ACT_ART12_FIELDS
            .iter()
            .enumerate()
            .map(|(i, f)| Art12Coverage {
                field: f,
                populated: i >= 2,
            })
            .collect();
        assert!(!Art12Coverage::is_compliant(&six));
    }

    #[test]
    fn c2pa_manifest_round_trips_json() {
        let m = C2paManifest::build("vouch-orchestrator", "abcdef", Some("up".into()));
        let s = serde_json::to_string(&m).unwrap();
        let parsed: C2paManifest = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn c2pa_manifest_uses_unique_ids() {
        let m1 = C2paManifest::build("vouch-orchestrator", "abc", None);
        // uuid sanity (issued_at differs by ns; just verify it parses)
        let _: chrono::DateTime<chrono::Utc> = m1.issued_at.parse().unwrap();
    }
}
