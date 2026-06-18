//! EU AI Act Art 27 — Fundamental Rights Impact Assessment (FRIA).
//!
//! Story C-16a / G03. FRIA is required for high-risk AI systems
//! under EU AI Act Art 27(1). The assessment covers 5 elements:
//! the foreseeable risks to fundamental rights, the data quality
//! measures, the human oversight design, the technical robustness,
//! and the residual fundamental-rights impact.
//!
//! THEMIS derives the FRIA from the same `risk_score` the BAAAR
//! gate uses (consistency: a single source of truth for risk
//! across the system) plus the tenant + use case context.
//!
//! The output is a `FriaReport` that the Evidence Packet carries
//! alongside the other EU AI Act fields. The dashboard renders
//! the 5 elements as a checklist.

use serde::Serialize;

/// Input shape for FRIA derivation. Mirrors the orchestrator's
/// pre-orchestration context: risk score, tenant, and a one-line
/// use-case description.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Fria {
    /// BAAAR risk score in `0.0..=1.0`. Same value the BAAAR
    /// gate evaluates; consistency is the design point.
    pub risk_score: f32,
    /// Tenant identifier (`stark`, `wayne`, ...).
    pub tenant_id: String,
    /// Short use-case description (e.g. "buyer-side AP invoice
    /// fraud detection").
    pub use_case: String,
}

/// The 5 Art 27 FRIA elements. Order matches the regulation's
/// Annex IV outline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FriaElement {
    /// (a) foreseeable risks to fundamental rights.
    RiskAssessment,
    /// (b) data quality measures used to train/operate the system.
    DataQuality,
    /// (c) human oversight design.
    HumanOversight,
    /// (d) technical robustness and accuracy.
    TechnicalRobustness,
    /// (e) residual fundamental-rights impact and mitigation.
    FundamentalRights,
}

impl FriaElement {
    /// Stable string identifier used in JSON output and in the
    /// Evidence Packet.
    pub fn as_str(self) -> &'static str {
        match self {
            FriaElement::RiskAssessment => "risk_assessment",
            FriaElement::DataQuality => "data_quality",
            FriaElement::HumanOversight => "human_oversight",
            FriaElement::TechnicalRobustness => "technical_robustness",
            FriaElement::FundamentalRights => "fundamental_rights",
        }
    }
}

/// A derived FRIA report. The 5 elements are always populated
/// (Art 27 requires all 5). Each element carries 1-2 sentences
/// of analysis derived from the input.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FriaReport {
    /// The 5 FRIA elements, in regulation order, paired with the
    /// analysis text. Always exactly 5 entries.
    pub elements: Vec<(FriaElement, String)>,
    /// The BAAAR risk score this report was derived from.
    pub risk_score: f32,
    /// Tenant id this report applies to.
    pub tenant_id: String,
    /// Use case the report applies to.
    pub use_case: String,
    /// UTC timestamp at derivation time.
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// Derive a `FriaReport` from the input. The 5 elements are filled
/// in regulation order. Each analysis sentence references the
/// concrete input (risk score, tenant, use case) so the output is
/// auditable, not boilerplate.
pub fn derive(input: &Fria) -> FriaReport {
    let risk_label = if input.risk_score >= 0.85 {
        "HIGH (BAAAR HALT threshold)"
    } else if input.risk_score >= 0.5 {
        "MEDIUM (operator review required)"
    } else {
        "LOW (auto-approve eligible)"
    };

    let elements = vec![
        (
            FriaElement::RiskAssessment,
            format!(
                "Foreseeable risks for tenant '{}' use case '{}' evaluated at risk_score={:.2} ({}). \
                 The BAAAR kill-switch fires above 0.85, with secondary triggers on secret leaks, \
                 low coherence, debate overflow, and explicit halt requests.",
                input.tenant_id, input.use_case, input.risk_score, risk_label
            ),
        ),
        (
            FriaElement::DataQuality,
            format!(
                "Training and operational data for '{}' is sourced from InvoiceNet (Stanford public) \
                 and tenant PO databases; quality is measured by the Fraud Auditor's confidence score \
                 and the Evidence Packet's input_data BLAKE3 hash (EU AI Act Art 12.4).",
                input.tenant_id
            ),
        ),
        (
            FriaElement::HumanOversight,
            format!(
                "Operators for tenant '{}' retain the right to override any agent decision at any time. \
                 The BAAAR HALT surface escalates CRITICAL events to a human reviewer with re-auth \
                 (alert-fatigue guard fires on >5 approvals per 60s).",
                input.tenant_id
            ),
        ),
        (
            FriaElement::TechnicalRobustness,
            "THEMIS 3.0 uses a 5-agent band-orchestrated pipeline with Ed25519-signed messages, \
             BLAKE3 hash chain, RFC 3161 timestamp, and Rekor v2 transparency log. \
             Coherence threshold is 0.3; debate overflow guard fires at 5 rounds."
                .to_string(),
        ),
        (
            FriaElement::FundamentalRights,
            format!(
                "Residual risk to fundamental rights is bounded by tenant isolation (separate Ed25519 \
                 keypair per tenant), EU AI Act Art 73 incident reporting (24h CRITICAL / 72h HIGH), \
                 and the EU AI Act Art 50 AI-generated disclosure banner. Risk score at derivation: {:.2}.",
                input.risk_score
            ),
        ),
    ];

    FriaReport {
        elements,
        risk_score: input.risk_score,
        tenant_id: input.tenant_id.clone(),
        use_case: input.use_case.clone(),
        generated_at: chrono::Utc::now(),
    }
}

/// Serialize to the standard FRIA JSON shape. Always 5 elements,
/// in regulation order. Used by the dashboard and the Evidence
/// Packet.
pub fn to_json(report: &FriaReport) -> serde_json::Value {
    let elements: Vec<serde_json::Value> = report
        .elements
        .iter()
        .map(|(elem, text)| {
            serde_json::json!({
                "element": elem.as_str(),
                "analysis": text,
            })
        })
        .collect();

    serde_json::json!({
        "framework": "eu_ai_act_art_27_fria",
        "tenant_id": report.tenant_id,
        "use_case": report.use_case,
        "risk_score": report.risk_score,
        "generated_at": report.generated_at,
        "elements": elements,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Fria {
        Fria {
            risk_score: 0.42,
            tenant_id: "stark".to_string(),
            use_case: "buyer-side AP invoice fraud detection".to_string(),
        }
    }

    #[test]
    fn derive_returns_5_elements() {
        let r = derive(&sample());
        assert_eq!(r.elements.len(), 5);
        // Order: Regulation Annex IV order.
        assert_eq!(r.elements[0].0, FriaElement::RiskAssessment);
        assert_eq!(r.elements[1].0, FriaElement::DataQuality);
        assert_eq!(r.elements[2].0, FriaElement::HumanOversight);
        assert_eq!(r.elements[3].0, FriaElement::TechnicalRobustness);
        assert_eq!(r.elements[4].0, FriaElement::FundamentalRights);
    }

    #[test]
    fn derive_includes_risk_score() {
        let r = derive(&sample());
        assert!((r.risk_score - 0.42).abs() < 1e-6);
        // The Risk Assessment element text must include the score.
        let (_, text) = &r.elements[0];
        assert!(text.contains("0.42"), "text must include risk score: {text}");
    }

    #[test]
    fn to_json_serializes_all_elements() {
        let r = derive(&sample());
        let j = to_json(&r);
        let arr = j.get("elements").and_then(|v| v.as_array()).expect("elements must be an array");
        assert_eq!(arr.len(), 5);
        // Each element has `element` and `analysis` keys.
        for (i, entry) in arr.iter().enumerate() {
            assert!(entry.get("element").is_some(), "entry {i} missing element key");
            assert!(entry.get("analysis").is_some(), "entry {i} missing analysis key");
        }
        // Framework + risk score + tenant propagated.
        assert_eq!(j.get("framework").and_then(|v| v.as_str()), Some("eu_ai_act_art_27_fria"));
        assert_eq!(j.get("tenant_id").and_then(|v| v.as_str()), Some("stark"));
        assert!(j.get("risk_score").and_then(|v| v.as_f64()).is_some());
    }
}
