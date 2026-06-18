//! Integration tests for ISO/IEC 23894 (AI risk management) and
//! ISO/IEC 5469 (AI functional safety) — Story C-16b / G12.

use themis_compliance::iso_23894::{self, RiskCategory};
use themis_compliance::iso_5469;

#[test]
fn test_iso_23894_full_flow() {
    let report = iso_23894::derive();
    assert_eq!(report.events.len(), 8);

    // Every R1..R8 category must be present.
    let cats: std::collections::HashSet<RiskCategory> =
        report.events.iter().map(|e| e.category).collect();
    assert!(cats.contains(&RiskCategory::R1_DataQuality));
    assert!(cats.contains(&RiskCategory::R2_Bias));
    assert!(cats.contains(&RiskCategory::R3_Robustness));
    assert!(cats.contains(&RiskCategory::R4_Explainability));
    assert!(cats.contains(&RiskCategory::R5_Privacy));
    assert!(cats.contains(&RiskCategory::R6_Security));
    assert!(cats.contains(&RiskCategory::R7_HumanOversight));
    assert!(cats.contains(&RiskCategory::R8_Environmental));

    let j = iso_23894::to_json(&report);
    assert_eq!(
        j.get("standard").and_then(|v| v.as_str()),
        Some("ISO/IEC 23894:2023")
    );
    let events = j
        .get("events")
        .and_then(|v| v.as_array())
        .expect("events must be an array");
    assert_eq!(events.len(), 8);
}

#[test]
fn test_iso_23894_risk_score_in_range() {
    let report = iso_23894::derive();
    assert!(
        (0.0..=1.0).contains(&report.risk_score),
        "risk_score out of [0.0, 1.0]: {}",
        report.risk_score
    );
    for e in &report.events {
        assert!(
            (0.0..=1.0).contains(&e.likelihood),
            "{:?}: likelihood out of range",
            e.category
        );
        assert!(
            (0.0..=1.0).contains(&e.impact),
            "{:?}: impact out of range",
            e.category
        );
    }
    // Mirror into JSON.
    let j = iso_23894::to_json(&report);
    let score = j
        .get("risk_score")
        .and_then(|v| v.as_f64())
        .expect("risk_score must be a number");
    assert!((0.0..=1.0).contains(&score), "JSON risk_score out of range: {}", score);
}

#[test]
fn test_iso_5469_full_flow() {
    let report = iso_5469::derive();
    assert_eq!(report.halt_events.len(), 5);
    assert_eq!(report.total_halts, 5);

    let j = iso_5469::to_json(&report);
    assert_eq!(
        j.get("standard").and_then(|v| v.as_str()),
        Some("ISO/IEC 5469")
    );
    let total = j
        .get("total_halts")
        .and_then(|v| v.as_u64())
        .expect("total_halts must be a number");
    assert_eq!(total, 5);
    let halts = j
        .get("halt_events")
        .and_then(|v| v.as_array())
        .expect("halt_events must be an array");
    assert_eq!(halts.len(), 5);
}

#[test]
fn test_iso_5469_halts_cover_severities() {
    let report = iso_5469::derive();
    let severities: std::collections::HashSet<&str> = report
        .halt_events
        .iter()
        .map(|h| h.severity.as_str())
        .collect();
    assert!(severities.contains("CRITICAL"), "missing CRITICAL severity");
    assert!(severities.contains("HIGH"), "missing HIGH severity");
    assert!(severities.contains("MEDIUM"), "missing MEDIUM severity");
    assert!(severities.contains("LOW"), "missing LOW severity");
}
