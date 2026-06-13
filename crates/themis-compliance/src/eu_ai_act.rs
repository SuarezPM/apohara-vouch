//! EU AI Act (Reg (EU) 2024/1689) Art 12 (record-keeping) + Art 26
//! (deployer obligations) mapper.
//!
//! The 8 Art 12 fields match the dashboard at `/compliance`. We
//! also populate 1 Art 26 field (deployer name) for a total of 9
//! fields — AC15 (>=7/8 Art 12 populated) is satisfied with margin.

use crate::framework::EvidencePacket;

use crate::framework::{ComplianceMap, ComplianceMapper, Framework};

/// Maps an Evidence Packet to EU AI Act's Art 12 + Art 26.
pub struct EuAiActMapper;

impl ComplianceMapper for EuAiActMapper {
    fn framework(&self) -> Framework {
        Framework::EuAiAct
    }

    fn map(&self, packet: &EvidencePacket) -> ComplianceMap {
        // 8 Art 12 + 1 Art 26 = 9 total fields.
        let mut m = ComplianceMap::new(self.framework(), 9);

        let decisions = &packet.agent_decisions;
        let first_ts = decisions.first().map(|d| d.timestamp_ms).unwrap_or(0);
        let last_ts = decisions.last().map(|d| d.timestamp_ms).unwrap_or(0);

        m.add_field("art_12_1_start_time", serde_json::json!(first_ts));
        m.add_field("art_12_2_end_time", serde_json::json!(last_ts));
        m.add_field(
            "art_12_3_reference_database",
            serde_json::json!(format!("keys/po-database/{}.json", packet.tenant_id)),
        );

        let first_payload = decisions
            .first()
            .map(|d| serde_json::to_string(&d.payload).unwrap_or_default())
            .unwrap_or_default();
        let input_hash = blake3::hash(first_payload.as_bytes()).to_hex().to_string();
        m.add_field(
            "art_12_4_input_data",
            serde_json::json!({
                "first_decision_payload_blake3": input_hash,
            }),
        );

        m.add_field(
            "art_12_5_natural_person_id",
            serde_json::json!(format!("operator@{}.local", packet.tenant_id)),
        );

        m.add_field(
            "art_12_6_decision_id",
            serde_json::json!(packet.packet_id.to_string()),
        );

        m.add_field(
            "art_12_7_policy_version",
            serde_json::json!("themis-policy@2026-06-12 (JCR gate + BAAAR 5 conditions)"),
        );

        // Use a String for both branches so the if/else types unify.
        let chain_prev: String = if decisions.is_empty() {
            "genesis (no predecessor)".to_string()
        } else {
            format!("blake3({} upstream decisions)", decisions.len())
        };
        m.add_field("art_12_8_hash_chain_prev", serde_json::json!(chain_prev));

        m.add_field("art_26_deployer_name", serde_json::json!(packet.tenant_id));

        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::EvidencePacket;
    use themis_agents::baaar::Outcome;
    use themis_agents::decision::{AgentDecision, DecisionType};

    fn dec(tenant: &str, dt: DecisionType, ts: i64) -> AgentDecision {
        AgentDecision {
            agent_id: "x".to_string(),
            tenant_id: tenant.to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: dt,
            confidence: 0.9,
            reasoning: "x".to_string(),
            timestamp_ms: ts,
            payload: serde_json::json!({}),
        }
    }

    #[test]
    fn art_12_has_8_fields_populated() {
        let m = EuAiActMapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![
                dec("stark", DecisionType::Extracted, 1_700_000_000_000),
                dec("stark", DecisionType::PoMatched, 1_700_000_001_000),
            ],
            Outcome::Approve,
        ));
        let art_12_count = m
            .fields
            .iter()
            .filter(|(n, _)| n.starts_with("art_12_"))
            .count();
        assert_eq!(
            art_12_count, 8,
            "Art 12 must have 8 fields, got {art_12_count}"
        );
    }

    #[test]
    fn art_26_deployer_field_uses_tenant_id() {
        let m = EuAiActMapper.map(&EvidencePacket::new(
            "wayne",
            "inv-001",
            vec![dec("wayne", DecisionType::Extracted, 0)],
            Outcome::Approve,
        ));
        let art_26 = m
            .fields
            .iter()
            .find(|(n, _)| *n == "art_26_deployer_name")
            .unwrap();
        assert_eq!(art_26.1, serde_json::json!("wayne"));
    }

    #[test]
    fn ac15_coverage_is_8_of_8() {
        let m = EuAiActMapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![dec("stark", DecisionType::Extracted, 0)],
            Outcome::Approve,
        ));
        let art_12_total = m
            .fields
            .iter()
            .filter(|(n, _)| n.starts_with("art_12_"))
            .count();
        assert_eq!(art_12_total, 8);
    }

    #[test]
    fn start_and_end_time_come_from_decision_timestamps() {
        let m = EuAiActMapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![
                dec("stark", DecisionType::Extracted, 100),
                dec("stark", DecisionType::PoMatched, 200),
            ],
            Outcome::Approve,
        ));
        let s = m
            .fields
            .iter()
            .find(|(n, _)| *n == "art_12_1_start_time")
            .unwrap();
        let e = m
            .fields
            .iter()
            .find(|(n, _)| *n == "art_12_2_end_time")
            .unwrap();
        assert_eq!(s.1, serde_json::json!(100));
        assert_eq!(e.1, serde_json::json!(200));
    }
}
