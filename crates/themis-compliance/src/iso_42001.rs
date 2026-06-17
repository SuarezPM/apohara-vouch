//! ISO/IEC 42001:2023 — AI Management System (AIMS) mapper.
//!
//! ISO 42001 is the only AI governance standard that is independently
//! certifiable by an external auditor (DORA, EU AI Act, and NIST AI
//! RMF are regulations or guidance). For a Track 3 (Regulated &
//! High-Stakes) demo, the certifiability claim is the differentiator.
//!
//! Fields mapped:
//!   - Clause 6.1 — AI risk assessment: BaaarGate 5-condition check
//!     always runs. Populated for every packet.
//!   - Clause 8.4 — Impact assessment: a static reference to the
//!     compliance crate version (the "evidence" for the assessment).
//!   - Clause 9.1 — Monitoring & measurement: the test suite + BAAAR
//!     gate composition. The 310+ tests are the measurement
//!     mechanism.
//!   - Clause 10.2 — Continual improvement: a pointer to the
//!     post-hackathon sprint as the documented improvement cycle.

use crate::framework::{ComplianceMap, ComplianceMapper, EvidencePacket, Framework};

/// Maps an Evidence Packet to ISO/IEC 42001:2023 clauses.
pub struct Iso42001Mapper;

impl ComplianceMapper for Iso42001Mapper {
    fn framework(&self) -> Framework {
        Framework::Iso42001
    }

    fn map(&self, packet: &EvidencePacket) -> ComplianceMap {
        // 4 fields: 6.1 (risk assessment), 8.4 (impact assessment),
        // 9.1 (monitoring), 10.2 (improvement cycle).
        let mut m = ComplianceMap::new(self.framework(), 4);

        // Clause 6.1 — AI risk assessment. The BaaarGate 5-condition
        // check is always invoked in process_invoice; this clause is
        // populated for every packet regardless of outcome.
        m.add_field(
            "clause_6_1_risk_assessment",
            serde_json::json!({
                "mechanism": "BaaarGate::check (5 deterministic conditions: risk_score>0.85, secret_leak, coherence<0.3, debate_rounds>=5, explicit_halt)",
                "always_invoked": true,
                "agent_decisions_observed": packet.agent_decisions.len(),
            }),
        );

        // Clause 8.4 — Impact assessment. We reference the compliance
        // crate version as the "documented impact assessment".
        m.add_field(
            "clause_8_4_impact_assessment",
            serde_json::json!({
                "ref": format!("themis-compliance v{}", env!("CARGO_PKG_VERSION")),
                "scope": "AI decision-support system for buyer-side AP invoice fraud detection",
            }),
        );

        // Clause 9.1 — Monitoring & measurement. The 310+ test suite
        // is the measurement mechanism; BAAAR is the in-process gate.
        m.add_field(
            "clause_9_1_monitoring_measurement",
            serde_json::json!({
                "monitoring_mechanism": "BAAAR-gate + 310+-test suite",
                "evidence_packet_emitted": true,
                "audit_log_durable": true,
            }),
        );

        // Clause 10.2 — Continual improvement. Post-hackathon sprint
        // is the documented improvement cycle. A real production
        // deployment would replace this with a CI-fed changelog.
        m.add_field(
            "clause_10_2_continual_improvement",
            serde_json::json!({
                "improvement_cycle": "post-hackathon sprint (vNext roadmap)",
                "feed": "BAAAR HALT events + tenant incident reports → compliance mapper deltas",
            }),
        );

        m.add_note(format!(
            "ISO/IEC 42001:2023 AIMS clauses mapped: 4/4 populated for tenant={}, invoice={}",
            packet.tenant_id, packet.invoice_id
        ));

        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use themis_agents::baaar::Outcome;
    use themis_agents::decision::{AgentDecision, DecisionType};

    fn dec(tenant: &str, dt: DecisionType) -> AgentDecision {
        AgentDecision {
            agent_id: "x".to_string(),
            tenant_id: tenant.to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: dt,
            confidence: 0.9,
            reasoning: "x".to_string(),
            timestamp_ms: 0,
            payload: serde_json::json!({}),
        }
    }

    #[test]
    fn framework_is_iso_42001() {
        assert_eq!(Iso42001Mapper.framework(), Framework::Iso42001);
        assert_eq!(Iso42001Mapper.framework().as_str(), "iso_42001");
    }

    #[test]
    fn all_4_clauses_populated_on_empty_packet() {
        // ISO 42001 is structural — populated from metadata, not
        // decisions. Empty packet still gets 4/4 (analogous to DORA
        // art_9/art_17 on empty packet).
        let m = Iso42001Mapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![],
            Outcome::Approve,
        ));
        assert_eq!(m.populated, 4);
        assert_eq!(m.total, 4);
        assert!((m.coverage_pct() - 1.0).abs() < 0.001);
    }

    #[test]
    fn all_4_clauses_populated_on_well_formed_packet() {
        let m = Iso42001Mapper.map(&EvidencePacket::new(
            "wayne",
            "inv-002",
            vec![
                dec("wayne", DecisionType::Extracted),
                dec("wayne", DecisionType::FraudAssessed),
                dec("wayne", DecisionType::ProvenanceSigned),
            ],
            Outcome::Approve,
        ));
        assert_eq!(m.populated, 4);
        let field_names: Vec<&str> = m.fields.iter().map(|(n, _)| *n).collect();
        assert!(field_names.contains(&"clause_6_1_risk_assessment"));
        assert!(field_names.contains(&"clause_8_4_impact_assessment"));
        assert!(field_names.contains(&"clause_9_1_monitoring_measurement"));
        assert!(field_names.contains(&"clause_10_2_continual_improvement"));
    }

    #[test]
    fn clause_6_1_marks_baaar_mechanism() {
        let m = Iso42001Mapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![],
            Outcome::Approve,
        ));
        let (name, value) = m
            .fields
            .iter()
            .find(|(n, _)| *n == "clause_6_1_risk_assessment")
            .expect("clause_6_1 must be present");
        assert_eq!(*name, "clause_6_1_risk_assessment");
        let v = value.as_object().expect("clause_6_1 must be a JSON object");
        assert_eq!(
            v.get("always_invoked").and_then(|x| x.as_bool()),
            Some(true)
        );
        assert!(
            v.get("mechanism")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .contains("BaaarGate"),
            "clause_6_1 mechanism must reference BaaarGate"
        );
    }

    #[test]
    fn clause_8_4_references_compliance_crate_version() {
        let m = Iso42001Mapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![],
            Outcome::Approve,
        ));
        let (_, value) = m
            .fields
            .iter()
            .find(|(n, _)| *n == "clause_8_4_impact_assessment")
            .expect("clause_8_4 must be present");
        let v = value.as_object().expect("clause_8_4 must be a JSON object");
        let r#ref = v.get("ref").and_then(|x| x.as_str()).unwrap_or("");
        assert!(
            r#ref.starts_with("themis-compliance v"),
            "clause_8_4 ref must start with 'themis-compliance v', got: {}",
            r#ref
        );
    }
}
