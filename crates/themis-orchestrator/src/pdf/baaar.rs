//! BAAAR matrix helpers — used by `page1_summary` and by the HALT
//! section of the summary page.
//!
//! All four helpers in this module were extracted from the original
//! monolithic `render_packet_pdf` because they have non-trivial
//! logic (extracting the live assessment from the FraudAuditor
//! payload) and benefit from unit tests independent of the PDF
//! renderer.

use themis_agents::baaar::BaaarReason;
use themis_agents::decision::AgentDecision;

/// Human-readable label for a `BaaarReason`. Used in the "REASON:"
/// line of the HALT section.
#[allow(dead_code)]
pub fn format_baaar_reason(reason: BaaarReason) -> &'static str {
    match reason {
        BaaarReason::RiskScoreExceeded => "risk_score > 0.85",
        BaaarReason::SecretLeakDetected => "secret leak detected",
        BaaarReason::CoherenceTooLow => "coherence_score < 0.3",
        BaaarReason::MaxDebateRoundsReached => "debate_rounds >= 5",
        BaaarReason::ExplicitHaltRequested => "operator requested halt",
    }
}

/// One row of the BAAAR matrix. Returns `(label, formatted_line)`
/// where `label == "fired"` marks the bold row.
pub fn condition_row<F: FnOnce(bool) -> String>(tripped: bool, line: F) -> (&'static str, String) {
    (if tripped { "fired" } else { "" }, line(tripped))
}

/// Pull the live BAAAR inputs from the FraudAuditor's decision
/// payload. `None` fields render as `n/a` in the matrix instead of
/// zero so the judge can see what's missing.
pub fn extract_assessment(
    decisions: &[AgentDecision],
) -> (Option<f32>, Option<f32>, Option<u32>, bool) {
    let payload = decisions
        .iter()
        .find(|d| d.agent_id == "fraud_auditor")
        .map(|d| &d.payload)
        .or_else(|| {
            decisions
                .iter()
                .find(|d| d.payload.get("assessment").is_some())
                .map(|d| &d.payload)
        });

    let Some(payload) = payload else {
        return (None, None, None, false);
    };

    let inner = payload.get("assessment").unwrap_or(payload);
    let risk_score = inner
        .get("risk_score")
        .and_then(|v| v.as_f64())
        .map(|v| v as f32);
    let coherence_score = inner
        .get("coherence_score")
        .and_then(|v| v.as_f64())
        .map(|v| v as f32);
    let debate_rounds = inner
        .get("debate_rounds")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let has_secret = inner
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|item| {
                item.get("kind")
                    .and_then(|k| k.as_str())
                    .is_some_and(|s| s == "secret_leak")
            })
        })
        .unwrap_or(false);

    (risk_score, coherence_score, debate_rounds, has_secret)
}

/// Build the 5-row BAAAR condition matrix. Each row is
/// `(label, formatted_line)` where `label == "fired"` marks the
/// bold row.
pub fn build_condition_matrix(decisions: &[AgentDecision]) -> Vec<(&'static str, String)> {
    let (risk_score, coherence_score, debate_rounds, has_secret) = extract_assessment(decisions);
    let explicit_halt = decisions.iter().any(|d| {
        d.payload
            .get("assessment")
            .and_then(|a| a.get("explicit_halt"))
            .and_then(|v| v.as_bool())
            .or_else(|| d.payload.get("explicit_halt").and_then(|v| v.as_bool()))
            .unwrap_or(false)
    });

    vec![
        condition_row(risk_score.is_some_and(|v| v > 0.85), |v| {
            format!(
                "[{}] risk_score > 0.85  score={}  {}",
                if v { "X" } else { " " },
                risk_score
                    .map(|x| format!("{x:.2}"))
                    .unwrap_or_else(|| "n/a".into()),
                if v { "FIRED" } else { "pass" }
            )
        }),
        condition_row(has_secret, |v| {
            format!(
                "[{}] secret_leak finding present        {}",
                if v { "X" } else { " " },
                if v { "FIRED" } else { "pass" }
            )
        }),
        condition_row(coherence_score.is_some_and(|v| v < 0.3), |v| {
            format!(
                "[{}] coherence_score < 0.3  coherence={}  {}",
                if v { "X" } else { " " },
                coherence_score
                    .map(|x| format!("{x:.2}"))
                    .unwrap_or_else(|| "n/a".into()),
                if v { "FIRED" } else { "pass" }
            )
        }),
        condition_row(debate_rounds.is_some_and(|v| v >= 5), |v| {
            format!(
                "[{}] debate_rounds >= 5  rounds={}  {}",
                if v { "X" } else { " " },
                debate_rounds
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "n/a".into()),
                if v { "FIRED" } else { "pass" }
            )
        }),
        condition_row(explicit_halt, |v| {
            format!(
                "[{}] explicit_halt requested         {}",
                if v { "X" } else { " " },
                if v { "FIRED" } else { "pass" }
            )
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use themis_agents::decision::{AgentDecision, DecisionType};

    fn decision_with_assessment(agent_id: &str, payload: serde_json::Value) -> AgentDecision {
        AgentDecision {
            agent_id: agent_id.to_string(),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: DecisionType::FraudAssessed,
            confidence: 0.9,
            reasoning: "ok".to_string(),
            timestamp_ms: 0,
            payload,
        }
    }

    #[test]
    fn format_reason_includes_threshold() {
        assert!(format_baaar_reason(BaaarReason::RiskScoreExceeded).contains("0.85"));
        assert!(format_baaar_reason(BaaarReason::ExplicitHaltRequested).contains("operator"));
    }

    #[test]
    fn extract_assessment_returns_none_when_no_fraud_auditor() {
        let decisions = vec![decision_with_assessment("extractor", serde_json::json!({}))];
        let (r, c, d, h) = extract_assessment(&decisions);
        assert!(r.is_none());
        assert!(c.is_none());
        assert!(d.is_none());
        assert!(!h);
    }

    #[test]
    fn extract_assessment_reads_risk_score_from_nested_payload() {
        let decisions = vec![decision_with_assessment(
            "fraud_auditor",
            serde_json::json!({"assessment": {"risk_score": 0.91, "coherence_score": 0.8}}),
        )];
        let (r, c, _, _) = extract_assessment(&decisions);
        assert_eq!(r, Some(0.91));
        assert_eq!(c, Some(0.8));
    }

    #[test]
    fn build_condition_matrix_marks_fired_row() {
        let decisions = vec![decision_with_assessment(
            "fraud_auditor",
            serde_json::json!({"assessment": {"risk_score": 0.91}}),
        )];
        let matrix = build_condition_matrix(&decisions);
        let fired: Vec<&str> = matrix.iter().map(|(l, _)| *l).collect();
        assert_eq!(fired[0], "fired");
        assert_eq!(fired[1], "");
    }
}
