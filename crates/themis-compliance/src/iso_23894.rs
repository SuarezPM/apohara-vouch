//! ISO/IEC 23894 — AI risk management mapper (regulatory completion B, C-16b).
//!
//! ISO/IEC 23894:2023 is the AI-specific companion to ISO 31000 (general
//! risk management). For Track 3 (Regulated & High-Stakes) demos, the
//! eight risk categories (R1 Data Quality through R8 Environmental)
//! give regulators a familiar vocabulary to ask "show me your AI risk
//! register."
//!
//! MVP scope: the `derive()` function returns 8 sample risk events —
//! one per category — with placeholder text and placeholder likelihood
//! and impact values. The follow-up sprint will wire log-mining so that
//! each `RiskEvent` is sourced from operational telemetry (FRIA findings,
//! QMS incidents, EU AI Act Art 15 accuracy metrics, etc.).
//!
//! The MVP is structurally honest: every event is timestamped, scored,
//! and serializable. A future commit can replace the placeholder
//! `RiskEvent` constructors with `derive()` reading from
//! `themis-orchestrator`'s structured log.

use chrono::{DateTime, Utc};
use serde::Serialize;

/// The eight ISO/IEC 23894 risk categories.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum RiskCategory {
    /// R1 — Data Quality: completeness, accuracy, and representativeness
    /// of the training/inference data.
    R1_DataQuality,
    /// R2 — Bias: demographic or representation bias in the data or
    /// model outputs.
    R2_Bias,
    /// R3 — Robustness: resilience to adversarial inputs, distribution
    /// shift, and noise.
    R3_Robustness,
    /// R4 — Explainability: ability to surface the rationale for an
    /// AI decision to a human reviewer.
    R4_Explainability,
    /// R5 — Privacy: leakage of PII or trade secrets through model
    /// outputs or embeddings.
    R5_Privacy,
    /// R6 — Security: prompt injection, jailbreaks, model theft, and
    /// supply-chain compromise.
    R6_Security,
    /// R7 — Human Oversight: the HITL loop is intact, escalation paths
    /// work, and the human can actually overrule the AI.
    R7_HumanOversight,
    /// R8 — Environmental: compute footprint, energy cost, and
    /// downstream carbon impact of model inference.
    R8_Environmental,
}

impl RiskCategory {
    /// Stable string id (matches the enum variant name).
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskCategory::R1_DataQuality => "R1_DataQuality",
            RiskCategory::R2_Bias => "R2_Bias",
            RiskCategory::R3_Robustness => "R3_Robustness",
            RiskCategory::R4_Explainability => "R4_Explainability",
            RiskCategory::R5_Privacy => "R5_Privacy",
            RiskCategory::R6_Security => "R6_Security",
            RiskCategory::R7_HumanOversight => "R7_HumanOversight",
            RiskCategory::R8_Environmental => "R8_Environmental",
        }
    }
}

/// A single AI risk event. ISO 23894 frames each risk as a triplet of
/// `likelihood` (probability of the risk materializing) and `impact`
/// (severity if it does).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RiskEvent {
    /// The ISO 23894 risk category this event falls under.
    pub category: RiskCategory,
    /// Free-form description of the risk in the THEMIS context.
    pub description: String,
    /// Likelihood in [0.0, 1.0].
    pub likelihood: f32,
    /// Impact in [0.0, 1.0].
    pub impact: f32,
    /// When the risk was observed (or recorded).
    pub timestamp: DateTime<Utc>,
}

/// The full ISO/IEC 23894 risk management report. 8 categories +
/// aggregate risk score + generation timestamp.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Iso23894Report {
    /// The 8 risk events (one per category).
    pub events: Vec<RiskEvent>,
    /// Aggregate risk score: mean of `likelihood * impact` across all
    /// events, clamped to `[0.0, 1.0]`.
    pub risk_score: f32,
    /// When the report was generated.
    pub generated_at: DateTime<Utc>,
}

/// Derive the ISO/IEC 23894 risk report.
///
/// MVP: returns one `RiskEvent` per category with placeholder text.
/// Follow-up: read from operational telemetry.
pub fn derive() -> Iso23894Report {
    let now = Utc::now();

    // Placeholder values. Each (likelihood, impact) pair is in [0.0, 1.0].
    // The MVP picks representative mid-range values; the follow-up
    // wires these from real telemetry.
    let events = vec![
        RiskEvent {
            category: RiskCategory::R1_DataQuality,
            description:
                "InvoiceNet 1K sample is public and verified; follow-up must ingest the tenant's \
                 own historical AP export to detect drift on PO matcher accuracy."
                    .to_string(),
            likelihood: 0.3,
            impact: 0.6,
            timestamp: now,
        },
        RiskEvent {
            category: RiskCategory::R2_Bias,
            description:
                "No demographic data flows into THEMIS (it's an AP fraud system, not a hiring or \
                 lending system); bias risk is bounded to currency/locale skew in InvoiceNet."
                    .to_string(),
            likelihood: 0.2,
            impact: 0.4,
            timestamp: now,
        },
        RiskEvent {
            category: RiskCategory::R3_Robustness,
            description:
                "INV-15 system-prompt verifier (C-03) + BAAAR HALT (5-condition gate) handle the \
                 adversarial-input channel; distribution shift on novel fraud patterns is the \
                 residual risk."
                    .to_string(),
            likelihood: 0.4,
            impact: 0.7,
            timestamp: now,
        },
        RiskEvent {
            category: RiskCategory::R4_Explainability,
            description:
                "Every agent emits structured findings (decision_type, confidence, reasoning, \
                 payload); EU AI Act Art 13 + Art 14 dashboards surface the rationale. Residual: \
                 free-form LLM reasoning is opaque."
                    .to_string(),
            likelihood: 0.3,
            impact: 0.5,
            timestamp: now,
        },
        RiskEvent {
            category: RiskCategory::R5_Privacy,
            description:
                "Dual-LLM split (C-07) + sanitization at the Privileged→Quarantined boundary \
                 prevents LLM-mediated PII leakage. Residual: raw invoice line items carry PII \
                 in plaintext until sanitized."
                    .to_string(),
            likelihood: 0.5,
            impact: 0.8,
            timestamp: now,
        },
        RiskEvent {
            category: RiskCategory::R6_Security,
            description:
                "AgentGuard seccomp/Landlock (C-02) + trust gate on signed messages (C-04) cover \
                 the agent↔tool attack surface. Residual: LLM-side jailbreaks require INV-15 \
                 + Honesty Auditor."
                    .to_string(),
            likelihood: 0.4,
            impact: 0.9,
            timestamp: now,
        },
        RiskEvent {
            category: RiskCategory::R7_HumanOversight,
            description:
                "Rogue monitor (C-06) + alert-fatigue detector ensure HITL stays engaged. \
                 Residual: a reviewer rubber-stamping the AI recommendation is the failure mode."
                    .to_string(),
            likelihood: 0.3,
            impact: 0.7,
            timestamp: now,
        },
        RiskEvent {
            category: RiskCategory::R8_Environmental,
            description:
                "Claude Sonnet 4.5 + Qwen3-Coder-30B + 5 mock LLM calls per run ≈ $1.49 per run; \
                 compute footprint is bounded. Follow-up: add kWh estimate per run."
                    .to_string(),
            likelihood: 0.2,
            impact: 0.3,
            timestamp: now,
        },
    ];

    // Aggregate risk score: mean of likelihood * impact.
    let raw: f32 = if events.is_empty() {
        0.0
    } else {
        events.iter().map(|e| e.likelihood * e.impact).sum::<f32>() / events.len() as f32
    };
    let risk_score = raw.clamp(0.0, 1.0);

    Iso23894Report {
        events,
        risk_score,
        generated_at: now,
    }
}

/// Serialize the ISO/IEC 23894 report to JSON.
pub fn to_json(report: &Iso23894Report) -> serde_json::Value {
    serde_json::json!({
        "standard": "ISO/IEC 23894:2023",
        "title": "AI risk management",
        "risk_score": report.risk_score,
        "generated_at": report.generated_at.to_rfc3339(),
        "events": report.events.iter().map(|e| {
            serde_json::json!({
                "category": e.category.as_str(),
                "description": e.description,
                "likelihood": e.likelihood,
                "impact": e.impact,
                "score": e.likelihood * e.impact,
                "timestamp": e.timestamp.to_rfc3339(),
            })
        }).collect::<Vec<serde_json::Value>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_includes_8_categories() {
        let r = derive();
        assert_eq!(
            r.events.len(),
            8,
            "expected 8 risk events, got {}",
            r.events.len()
        );
        // One event per category — every variant represented exactly once.
        let mut seen = std::collections::HashSet::new();
        for e in &r.events {
            assert!(
                seen.insert(e.category),
                "duplicate category: {:?}",
                e.category
            );
        }
        assert!(seen.contains(&RiskCategory::R1_DataQuality));
        assert!(seen.contains(&RiskCategory::R2_Bias));
        assert!(seen.contains(&RiskCategory::R3_Robustness));
        assert!(seen.contains(&RiskCategory::R4_Explainability));
        assert!(seen.contains(&RiskCategory::R5_Privacy));
        assert!(seen.contains(&RiskCategory::R6_Security));
        assert!(seen.contains(&RiskCategory::R7_HumanOversight));
        assert!(seen.contains(&RiskCategory::R8_Environmental));
    }

    #[test]
    fn risk_score_in_valid_range() {
        let r = derive();
        assert!(
            (0.0..=1.0).contains(&r.risk_score),
            "risk_score out of [0.0, 1.0]: {}",
            r.risk_score
        );
        // Per-event likelihood and impact are also bounded.
        for e in &r.events {
            assert!(
                (0.0..=1.0).contains(&e.likelihood),
                "likelihood out of range for {:?}: {}",
                e.category,
                e.likelihood
            );
            assert!(
                (0.0..=1.0).contains(&e.impact),
                "impact out of range for {:?}: {}",
                e.category,
                e.impact
            );
        }
    }

    #[test]
    fn to_json_serializes_all_events() {
        let r = derive();
        let j = to_json(&r);
        assert_eq!(
            j.get("standard").and_then(|v| v.as_str()),
            Some("ISO/IEC 23894:2023")
        );
        let events = j
            .get("events")
            .and_then(|v| v.as_array())
            .expect("events must be an array");
        assert_eq!(events.len(), 8);
        for (i, ev) in events.iter().enumerate() {
            assert!(ev.get("category").is_some(), "event {i} missing category");
            assert!(
                ev.get("description").is_some(),
                "event {i} missing description"
            );
            assert!(
                ev.get("likelihood").is_some(),
                "event {i} missing likelihood"
            );
            assert!(ev.get("impact").is_some(), "event {i} missing impact");
            assert!(ev.get("score").is_some(), "event {i} missing score");
            assert!(ev.get("timestamp").is_some(), "event {i} missing timestamp");
        }
        // risk_score is in [0.0, 1.0] in the JSON too.
        let score = j
            .get("risk_score")
            .and_then(|v| v.as_f64())
            .expect("risk_score must be a number");
        assert!(
            (0.0..=1.0).contains(&score),
            "JSON risk_score out of range: {}",
            score
        );
    }
}
