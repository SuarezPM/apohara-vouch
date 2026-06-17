//! Framework enum + ComplianceMapper trait + ComplianceMap struct.

use serde::Serialize;
use themis_agents::baaar::Outcome;
use themis_agents::decision::AgentDecision;

/// The 5 regulatory frameworks THEMIS maps an Evidence Packet against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    /// EU Regulation 2022/2554 — Digital Operational Resilience Act.
    Dora,
    /// EU Regulation 2024/1689 — AI Act (high-risk system obligations).
    EuAiAct,
    /// NIST AI Risk Management Framework 1.0.
    NistAiRmf,
    /// OWASP Agentic 2026 (ASI01–ASI10).
    OwaspAgentic,
    /// ISO/IEC 42001:2023 — AI Management System (AIMS).
    #[serde(rename = "iso_42001")]
    Iso42001,
}

impl Framework {
    /// Stable string identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Framework::Dora => "dora",
            Framework::EuAiAct => "eu_ai_act",
            Framework::NistAiRmf => "nist_ai_rmf",
            Framework::OwaspAgentic => "owasp_agentic",
            Framework::Iso42001 => "iso_42001",
        }
    }
}

/// The shape of an Evidence Packet that mappers inspect. The
/// orchestrator's `EvidencePacket` has a Uuid for `packet_id`; we
/// use String here for serde stability and to avoid a cyclic
/// dependency with the orchestrator crate. The orchestrator
/// converts at the boundary (its EvidencePacket is the
/// authoritative source; this is a read-only mirror).
pub struct EvidencePacket {
    /// Packet id (string form).
    pub packet_id: String,
    /// Tenant (e.g. "stark", "wayne").
    pub tenant_id: String,
    /// Invoice id.
    pub invoice_id: String,
    /// Chain of agent decisions, in order.
    pub agent_decisions: Vec<AgentDecision>,
    /// BAAAR gate verdict.
    pub bbaaar_outcome: Outcome,
}

impl EvidencePacket {
    /// Convenience constructor for tests.
    pub fn new(
        tenant_id: impl Into<String>,
        invoice_id: impl Into<String>,
        agent_decisions: Vec<AgentDecision>,
        bbaaar_outcome: Outcome,
    ) -> Self {
        Self {
            packet_id: "00000000-0000-0000-0000-000000000001".to_string(),
            tenant_id: tenant_id.into(),
            invoice_id: invoice_id.into(),
            agent_decisions,
            bbaaar_outcome,
        }
    }
}

/// A single framework's coverage for one Evidence Packet.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ComplianceMap {
    /// Which framework this map is for.
    pub framework: Framework,
    /// Number of fields the mapper populated (non-null).
    pub populated: u16,
    /// Total number of fields the mapper *could* populate.
    pub total: u16,
    /// Per-field values: (field name, JSON value).
    pub fields: Vec<(&'static str, serde_json::Value)>,
    /// Human-readable notes (no fixed schema; mapper-defined).
    pub notes: Vec<String>,
}

impl ComplianceMap {
    /// New empty map.
    pub fn new(framework: Framework, total: u16) -> Self {
        Self {
            framework,
            populated: 0,
            total,
            fields: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Add a populated field.
    pub fn add_field(&mut self, name: &'static str, value: serde_json::Value) {
        self.fields.push((name, value));
        self.populated += 1;
    }

    /// Add a note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Coverage as 0.0..=1.0.
    pub fn coverage_pct(&self) -> f32 {
        if self.total == 0 {
            1.0
        } else {
            self.populated as f32 / self.total as f32
        }
    }
}

/// The trait every framework mapper implements.
pub trait ComplianceMapper: Send + Sync {
    /// Which framework this mapper is for.
    fn framework(&self) -> Framework;

    /// Inspect the packet and populate the `ComplianceMap`.
    fn map(&self, packet: &EvidencePacket) -> ComplianceMap;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framework_as_str_is_stable() {
        assert_eq!(Framework::Dora.as_str(), "dora");
        assert_eq!(Framework::EuAiAct.as_str(), "eu_ai_act");
        assert_eq!(Framework::NistAiRmf.as_str(), "nist_ai_rmf");
        assert_eq!(Framework::OwaspAgentic.as_str(), "owasp_agentic");
        assert_eq!(Framework::Iso42001.as_str(), "iso_42001");
    }

    #[test]
    fn compliance_map_starts_empty() {
        let m = ComplianceMap::new(Framework::Dora, 3);
        assert_eq!(m.populated, 0);
        assert_eq!(m.total, 3);
        assert_eq!(m.coverage_pct(), 0.0);
    }

    #[test]
    fn add_field_bumps_populated() {
        let mut m = ComplianceMap::new(Framework::Dora, 3);
        m.add_field("art_9", serde_json::json!("populated"));
        m.add_field("art_10", serde_json::json!("populated"));
        assert_eq!(m.populated, 2);
        assert_eq!(m.coverage_pct(), 2.0 / 3.0);
    }

    #[test]
    fn add_note_appends() {
        let mut m = ComplianceMap::new(Framework::Dora, 0);
        m.add_note("first");
        m.add_note("second");
        assert_eq!(m.notes, vec!["first", "second"]);
    }

    #[test]
    fn coverage_pct_of_total_zero_is_one() {
        let m = ComplianceMap::new(Framework::Dora, 0);
        assert_eq!(m.coverage_pct(), 1.0);
    }

    #[test]
    fn compliance_map_serializes_to_json() {
        let mut m = ComplianceMap::new(Framework::Dora, 3);
        m.add_field("art_9", serde_json::json!("value"));
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"framework\":\"dora\""));
        assert!(json.contains("\"populated\":1"));
    }
}
