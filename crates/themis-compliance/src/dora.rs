//! DORA (EU Regulation 2022/2554) Art 9/10/17 mapper.

use themis_agents::baaar::{BaaarReason, Outcome};
use themis_agents::decision::DecisionType;

use crate::framework::{ComplianceMap, ComplianceMapper, EvidencePacket, Framework};

/// Maps an Evidence Packet to DORA's 3 sub-articles.
pub struct DoraMapper;

impl ComplianceMapper for DoraMapper {
    fn framework(&self) -> Framework {
        Framework::Dora
    }

    fn map(&self, packet: &EvidencePacket) -> ComplianceMap {
        let mut m = ComplianceMap::new(self.framework(), 3);

        // Art 9 — ICT risk management. The state machine and the
        // BAAAR gate (5 conditions, deterministic thresholds)
        // together constitute the risk-management process.
        let has_risk_management = packet.agent_decisions.iter().any(|d| {
            matches!(
                d.decision_type,
                DecisionType::FraudAssessed | DecisionType::WatchdogAlert
            )
        });
        if has_risk_management {
            m.add_field(
                "art_9_ict_risk_management",
                serde_json::json!({
                    "mechanism": "BaaarGate 5-condition kill-switch + StateMachine traversal",
                    "populated_from_decisions": packet.agent_decisions.len(),
                }),
            );
        }

        // Art 10 — Incident detection. The Audit Watchdog is the
        // detection agent; its WatchdogAlert decision captures the
        // incident.
        let watchdog_alert = packet
            .agent_decisions
            .iter()
            .find(|d| d.decision_type == DecisionType::WatchdogAlert);
        if let Some(alert) = watchdog_alert {
            m.add_field(
                "art_10_incident_detection",
                serde_json::json!({
                    "agent": "audit_watchdog",
                    "coherence_score": alert.confidence,
                    "reasoning": alert.reasoning,
                }),
            );
        } else {
            m.add_note("no WatchdogAlert decision in chain; Art 10 detection evidence missing");
        }

        // Art 17 — Incident reporting. A HALT outcome is the
        // incident; the Evidence Packet itself is the report.
        // R7: populate the incident classification, the DORA
        // reporting window (72h for major ICT incidents per Art
        // 17(3)), and the mock recipient (Spanish NCA: NCA-ES)
        // so the compliance dashboard shows a regulator-ready
        // report even in the demo.
        if let Outcome::Halt(reason) = packet.bbaaar_outcome {
            let incident_classification = match reason {
                BaaarReason::RiskScoreExceeded => "fraud_suspected",
                BaaarReason::SecretLeakDetected => "sanctions_match",
                BaaarReason::CoherenceTooLow => "data_incoherence",
                BaaarReason::MaxDebateRoundsReached => "policy_violation",
                BaaarReason::ExplicitHaltRequested => "policy_violation",
            };
            m.add_field(
                "art_17_incident_reporting",
                serde_json::json!({
                    "outcome": "halt",
                    "evidence_packet_id": packet.packet_id,
                    "tenant_id": packet.tenant_id,
                    "invoice_id": packet.invoice_id,
                    "halt_reason": format!("{reason:?}"),
                    "incident_classification": incident_classification,
                    "reporting_window_hours": 72,
                    "mock_recipient": "NCA-ES",
                }),
            );
        } else {
            m.add_field(
                "art_17_incident_reporting",
                serde_json::json!({
                    "outcome": "no_incident",
                    "incident_classification": "none",
                    "reporting_window_hours": 0,
                    "mock_recipient": "NCA-ES",
                    "note": "no HALT in this run; Art 17 reporting N/A",
                }),
            );
        }

        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use themis_agents::baaar::BaaarReason;
    use themis_agents::decision::{AgentDecision, DecisionType};

    /// Build an `EvidencePacket` for tests (the compliance-side
    /// definition, NOT the orchestrator's).
    fn ep(tenant: &str, dts: Vec<DecisionType>, outcome: Outcome) -> EvidencePacket {
        EvidencePacket {
            packet_id: "00000000-0000-0000-0000-000000000001".to_string(),
            tenant_id: tenant.to_string(),
            invoice_id: "inv-001".to_string(),
            agent_decisions: dts
                .into_iter()
                .map(|dt| AgentDecision {
                    agent_id: "x".to_string(),
                    tenant_id: tenant.to_string(),
                    invoice_id: "inv-001".to_string(),
                    decision_type: dt,
                    confidence: 0.9,
                    reasoning: "x".to_string(),
                    timestamp_ms: 0,
                    payload: serde_json::json!({}),
                })
                .collect(),
            bbaaar_outcome: outcome,
        }
    }

    #[allow(dead_code)]
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
    fn all_three_art_fields_populated_on_clean_packet() {
        let m = DoraMapper.map(&ep(
            "stark",
            vec![
                DecisionType::Extracted,
                DecisionType::FraudAssessed,
                DecisionType::WatchdogAlert,
            ],
            Outcome::Approve,
        ));
        assert_eq!(m.populated, 3);
        assert_eq!(m.total, 3);
    }

    #[test]
    fn halt_outcome_populates_art_17_with_incident_metadata() {
        let m = DoraMapper.map(&ep(
            "stark",
            vec![DecisionType::FraudAssessed],
            Outcome::Halt(BaaarReason::RiskScoreExceeded),
        ));
        let art_17 = m
            .fields
            .iter()
            .find(|(n, _)| *n == "art_17_incident_reporting");
        assert!(art_17.is_some());
        let val = &art_17.unwrap().1;
        assert_eq!(val["outcome"], "halt");
        // R7: incident_classification / reporting_window_hours / mock_recipient
        assert_eq!(val["incident_classification"], "fraud_suspected");
        assert_eq!(val["reporting_window_hours"], 72);
        assert_eq!(val["mock_recipient"], "NCA-ES");
    }

    #[test]
    fn secret_leak_halt_is_classified_as_sanctions_match() {
        let m = DoraMapper.map(&ep(
            "stark",
            vec![DecisionType::FraudAssessed],
            Outcome::Halt(BaaarReason::SecretLeakDetected),
        ));
        let art_17 = m
            .fields
            .iter()
            .find(|(n, _)| *n == "art_17_incident_reporting")
            .unwrap();
        assert_eq!(art_17.1["incident_classification"], "sanctions_match");
    }

    #[test]
    fn approve_outcome_populates_art_17_with_no_incident() {
        let m = DoraMapper.map(&ep(
            "wayne",
            vec![DecisionType::FraudAssessed, DecisionType::WatchdogAlert],
            Outcome::Approve,
        ));
        let art_17 = m
            .fields
            .iter()
            .find(|(n, _)| *n == "art_17_incident_reporting")
            .unwrap();
        assert_eq!(art_17.1["outcome"], "no_incident");
        assert_eq!(art_17.1["incident_classification"], "none");
        assert_eq!(art_17.1["reporting_window_hours"], 0);
        // NCA-ES still populated for the no-incident path (the
        // regulator hasn't been triggered, but the dashboard
        // needs the field).
        assert_eq!(art_17.1["mock_recipient"], "NCA-ES");
    }

    #[test]
    fn missing_watchdog_adds_a_note() {
        let m = DoraMapper.map(&ep(
            "stark",
            vec![DecisionType::Extracted],
            Outcome::Approve,
        ));
        assert!(m.notes.iter().any(|n| n.contains("Art 10")));
    }
}
