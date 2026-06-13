//! OWASP Agentic 2026 ASI01-ASI10 mapper.

use crate::framework::EvidencePacket;
use themis_agents::baaar::{BaaarReason, Outcome};
use themis_agents::decision::DecisionType;

use crate::framework::{ComplianceMap, ComplianceMapper, Framework};

/// The 10 OWASP Agentic 2026 categories (ASI01 through ASI10).
const ASI_CATEGORIES: &[&str] = &[
    "ASI01_prompt_injection",
    "ASI02_sensitive_data_exposure",
    "ASI03_supply_chain",
    "ASI04_data_and_model_poisoning",
    "ASI05_improper_output_handling",
    "ASI06_excessive_agency",
    "ASI07_system_prompt_leakage",
    "ASI08_vector_and_embedding_weaknesses",
    "ASI09_misinformation",
    "ASI10_rogue_agents",
];

/// Maps an Evidence Packet to OWASP Agentic's 10 ASI categories.
/// Each category is flagged as either "triggered" (the packet's
/// BAAAR findings or decisions implicate it) or "mitigated".
pub struct OwaspAgenticMapper;

impl ComplianceMapper for OwaspAgenticMapper {
    fn framework(&self) -> Framework {
        Framework::OwaspAgentic
    }

    fn map(&self, packet: &EvidencePacket) -> ComplianceMap {
        let mut m = ComplianceMap::new(self.framework(), ASI_CATEGORIES.len() as u16);

        // Detect which ASIs were triggered.
        let mut triggered: Vec<String> = Vec::new();

        // ASI02 — sensitive data exposure: a SecretLeak finding.
        let secret_leak = packet.agent_decisions.iter().any(|d| {
            d.payload
                .get("findings")
                .and_then(|f| f.as_array())
                .map(|arr| {
                    arr.iter()
                        .any(|f| f.get("kind").and_then(|k| k.as_str()) == Some("secret_leak"))
                })
                .unwrap_or(false)
        });
        if secret_leak
            || matches!(
                packet.bbaaar_outcome,
                Outcome::Halt(BaaarReason::SecretLeakDetected)
            )
        {
            m.add_field(
                "ASI02_sensitive_data_exposure",
                serde_json::json!("triggered"),
            );
            triggered.push("ASI02".to_string());
            m.add_note("ASI02 triggered by SecretLeak finding or BAAAR halt");
        } else {
            m.add_field(
                "ASI02_sensitive_data_exposure",
                serde_json::json!("mitigated"),
            );
        }

        // ASI06 — excessive agency: a non-FraudAuditor agent
        // emitted a halt (means an agent exceeded its scope).
        let excessive_agency = packet.agent_decisions.iter().any(|d| {
            d.decision_type != DecisionType::FraudAssessed
                && d.payload
                    .get("outcome")
                    .and_then(|v| v.as_str())
                    .map(|s| s.starts_with("halt_"))
                    .unwrap_or(false)
        });
        if excessive_agency {
            m.add_field("ASI06_excessive_agency", serde_json::json!("triggered"));
            triggered.push("ASI06".to_string());
        } else {
            m.add_field("ASI06_excessive_agency", serde_json::json!("mitigated"));
        }

        // ASI10 — rogue agents: a non-BAAAR halt (BaaarGate
        // disabled or overridden).
        let rogue_agent = matches!(packet.bbaaar_outcome, Outcome::Halt(_))
            && packet
                .agent_decisions
                .iter()
                .all(|d| d.decision_type != DecisionType::FraudAssessed);
        if rogue_agent {
            m.add_field("ASI10_rogue_agents", serde_json::json!("triggered"));
            triggered.push("ASI10".to_string());
        } else {
            m.add_field("ASI10_rogue_agents", serde_json::json!("mitigated"));
        }

        // The other 7 ASI categories (ASI01, ASI03, ASI04, ASI05,
        // ASI07, ASI08, ASI09) are not directly observable from the
        // Evidence Packet alone; they require out-of-band evidence
        // (e.g. supply-chain attestation). For now we mark them as
        // `not_assessed` so the framework count is honest. Whitelist
        // explicit indices to avoid duplicating ASI02/06/10 which
        // we already populated above.
        const NOT_ASSESSED: &[&str] = &[
            "ASI01_prompt_injection",
            "ASI03_supply_chain",
            "ASI04_data_and_model_poisoning",
            "ASI05_improper_output_handling",
            "ASI07_system_prompt_leakage",
            "ASI08_vector_and_embedding_weaknesses",
            "ASI09_misinformation",
        ];
        for asi in NOT_ASSESSED {
            m.add_field(asi, serde_json::json!("not_assessed"));
        }

        if !triggered.is_empty() {
            m.add_note(format!("triggered ASIs: {}", triggered.join(", ")));
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

    fn dec(dt: DecisionType, payload: serde_json::Value) -> AgentDecision {
        AgentDecision {
            agent_id: "x".to_string(),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: dt,
            confidence: 0.9,
            reasoning: "x".to_string(),
            timestamp_ms: 0,
            payload,
        }
    }

    #[test]
    fn all_10_asi_fields_populated() {
        let m = OwaspAgenticMapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![dec(DecisionType::Extracted, serde_json::json!({}))],
            Outcome::Approve,
        ));
        // 10 ASI fields + 1 ASI02 + 1 ASI06 + 1 ASI10 (mitigated)
        // = 13 entries. We assert at least 10 ASI fields exist.
        // Count ASI01..ASI10 (10 categories, the prefix "ASI" is the
        // shared one, with the digits 01-10 distinguishing).
        let asi_count = m
            .fields
            .iter()
            .filter(|(n, _)| n.starts_with("ASI"))
            .count();
        assert_eq!(asi_count, 10, "expected 10 ASI fields, got {asi_count}");
    }

    #[test]
    fn secret_leak_marks_asi02_triggered() {
        let m = OwaspAgenticMapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![dec(
                DecisionType::FraudAssessed,
                serde_json::json!({
                    "findings": [{"kind": "secret_leak", "description": "AWS key"}],
                }),
            )],
            Outcome::Halt(BaaarReason::SecretLeakDetected),
        ));
        let asi02 = m
            .fields
            .iter()
            .find(|(n, _)| *n == "ASI02_sensitive_data_exposure")
            .unwrap();
        assert_eq!(asi02.1, serde_json::json!("triggered"));
    }

    #[test]
    fn clean_packet_marks_all_as_mitigated_or_not_assessed() {
        let m = OwaspAgenticMapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![dec(DecisionType::Extracted, serde_json::json!({}))],
            Outcome::Approve,
        ));
        // No "triggered" entries on a clean packet.
        let triggered = m
            .fields
            .iter()
            .filter(|(_, v)| v == &serde_json::json!("triggered"))
            .count();
        assert_eq!(triggered, 0);
    }
}
