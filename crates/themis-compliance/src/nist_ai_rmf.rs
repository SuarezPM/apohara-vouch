//! NIST AI RMF 1.0 (Govern / Map / Measure / Manage) mapper.

use crate::framework::EvidencePacket;
use themis_agents::decision::DecisionType;

use crate::framework::{ComplianceMap, ComplianceMapper, Framework};

/// Maps an Evidence Packet to NIST AI RMF's 4 functions.
pub struct NistAiRmfMapper;

impl ComplianceMapper for NistAiRmfMapper {
    fn framework(&self) -> Framework {
        Framework::NistAiRmf
    }

    fn map(&self, packet: &EvidencePacket) -> ComplianceMap {
        let mut m = ComplianceMap::new(self.framework(), 4);

        // Govern — the orchestrator state machine provides the
        // governance trail (Received → Done or Halt).
        let has_state_machine_trace = !packet.agent_decisions.is_empty();
        if has_state_machine_trace {
            m.add_field(
                "govern",
                serde_json::json!({
                    "mechanism": "InvoiceState state machine",
                    "decisions_in_chain": packet.agent_decisions.len(),
                }),
            );
        }

        // Map — the tenant registry (Stark / Wayne trust domains).
        m.add_field(
            "map",
            serde_json::json!({
                "trust_domain": packet.tenant_id,
                "registry": "TenantRegistry (2 default trust domains)",
            }),
        );

        // Measure — the live counter + BAAAR halt rate.
        let avg_confidence: f32 = if packet.agent_decisions.is_empty() {
            0.0
        } else {
            packet
                .agent_decisions
                .iter()
                .map(|d| d.confidence)
                .sum::<f32>()
                / packet.agent_decisions.len() as f32
        };
        m.add_field(
            "measure",
            serde_json::json!({
                "mean_confidence": avg_confidence,
                "outcome": match &packet.bbaaar_outcome {
                    themis_agents::baaar::Outcome::Approve => "approve",
                    themis_agents::baaar::Outcome::Halt(_) => "halt",
                },
            }),
        );

        // Manage — the Regression Tester re-verifies the
        // signature, the Provenance Signer seals the packet.
        let has_manage_evidence = packet.agent_decisions.iter().any(|d| {
            matches!(
                d.decision_type,
                DecisionType::RegressionResult | DecisionType::ProvenanceSigned
            )
        });
        if has_manage_evidence {
            m.add_field(
                "manage",
                serde_json::json!({
                    "agents": ["regression_tester", "provenance_signer"],
                    "evidence_packet_signed": true,
                }),
            );
        } else {
            m.add_note("no RegressionResult or ProvenanceSigned in chain; Manage evidence missing");
        }

        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::EvidencePacket;
    use themis_agents::baaar::Outcome;
    use themis_agents::decision::{AgentDecision, DecisionType};

    fn dec(dt: DecisionType, conf: f32) -> AgentDecision {
        AgentDecision {
            agent_id: "x".to_string(),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: dt,
            confidence: conf,
            reasoning: "x".to_string(),
            timestamp_ms: 0,
            payload: serde_json::json!({}),
        }
    }

    #[test]
    fn all_four_rmf_functions_populated() {
        let m = NistAiRmfMapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![
                dec(DecisionType::Extracted, 0.9),
                dec(DecisionType::ProvenanceSigned, 1.0),
                dec(DecisionType::RegressionResult, 1.0),
            ],
            Outcome::Approve,
        ));
        assert_eq!(m.populated, 4);
    }

    #[test]
    fn measure_reflects_mean_confidence() {
        let m = NistAiRmfMapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![
                dec(DecisionType::Extracted, 0.8),
                dec(DecisionType::PoMatched, 0.9),
                dec(DecisionType::FraudAssessed, 0.7),
            ],
            Outcome::Approve,
        ));
        let measure = m.fields.iter().find(|(n, _)| *n == "measure").unwrap();
        let mean = measure.1["mean_confidence"].as_f64().unwrap();
        // (0.8 + 0.9 + 0.7) / 3 = 0.8
        assert!((mean - 0.8).abs() < 1e-5);
    }

    #[test]
    fn manage_records_when_no_regression_or_provenance() {
        let m = NistAiRmfMapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![dec(DecisionType::Extracted, 0.9)],
            Outcome::Approve,
        ));
        // Manage is missing but a note is added.
        assert!(m.notes.iter().any(|n| n.contains("Manage")));
    }
}
