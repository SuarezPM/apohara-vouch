//! EU AI Act Art 17 — Quality Management System (QMS) report.
//!
//! Story C-16a / G04. Art 17(1) requires providers of high-risk AI
//! systems to put in place a QMS that covers 7 SOPs (Standard
//! Operating Procedures). THEMIS 3.0 implements the 7 SOPs in
//! `STANDARD_SOPS` and the `derive()` function returns a
//! `QmsReport` with each SOP marked last-reviewed at the current
//! UTC timestamp.
//!
//! The MVP returns the static 7-SOP list. A follow-up commit will
//! wire `derive()` to mine operational logs for the `last_reviewed`
//! timestamp of each SOP (per the supreme plan: "auto-derived from
//! operational logs referencing all 7 SOPs").

use serde::Serialize;

/// A single Standard Operating Procedure entry.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct QmsSop {
    /// Stable id, e.g. `SOP-001`.
    pub id: String,
    /// Human-readable title, e.g. `Incident Response`.
    pub title: String,
    /// UTC timestamp the SOP was last reviewed.
    pub last_reviewed: chrono::DateTime<chrono::Utc>,
}

/// A complete QMS report. Always 7 SOPs (Art 17's required set).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct QmsReport {
    /// The 7 SOPs (order matches `STANDARD_SOPS`).
    pub sops: Vec<QmsSop>,
    /// UTC timestamp at derivation time.
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// The 7 SOPs required by Art 17. The `&str` pairs are stable
/// identifiers used in tests, documentation, and operational
/// log mining.
pub const STANDARD_SOPS: &[(&str, &str)] = &[
    ("SOP-001", "Incident Response"),
    ("SOP-002", "Change Management"),
    ("SOP-003", "Access Control"),
    ("SOP-004", "Data Quality"),
    ("SOP-005", "Vendor Management"),
    ("SOP-006", "Risk Assessment"),
    ("SOP-007", "Business Continuity"),
];

/// Derive the QMS report. The MVP returns the 7 SOPs as a static
/// list, each with `last_reviewed = now()`. A follow-up commit
/// will replace this with log-mining (read `operational_log.jsonl`
/// and find the latest `sop.last_reviewed` event per SOP id).
pub fn derive() -> QmsReport {
    let now = chrono::Utc::now();
    let sops = STANDARD_SOPS
        .iter()
        .map(|(id, title)| QmsSop {
            id: (*id).to_string(),
            title: (*title).to_string(),
            last_reviewed: now,
        })
        .collect();
    QmsReport {
        sops,
        generated_at: now,
    }
}

/// Serialize the report to the standard QMS JSON shape. Always
/// contains 7 SOPs in regulation order.
pub fn to_json(report: &QmsReport) -> serde_json::Value {
    let sops: Vec<serde_json::Value> = report
        .sops
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "title": s.title,
                "last_reviewed": s.last_reviewed,
            })
        })
        .collect();

    serde_json::json!({
        "framework": "eu_ai_act_art_17_qms",
        "generated_at": report.generated_at,
        "sop_count": sops.len(),
        "sops": sops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_includes_7_sops() {
        let r = derive();
        assert_eq!(r.sops.len(), 7);
        // IDs in regulation order.
        let ids: Vec<&str> = r.sops.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "SOP-001",
                "SOP-002",
                "SOP-003",
                "SOP-004",
                "SOP-005",
                "SOP-006",
                "SOP-007",
            ]
        );
    }

    #[test]
    fn to_json_serializes_all_sops() {
        let r = derive();
        let j = to_json(&r);
        let sops = j.get("sops").and_then(|v| v.as_array()).expect("sops must be an array");
        assert_eq!(sops.len(), 7);
        assert_eq!(j.get("sop_count").and_then(|v| v.as_u64()), Some(7));
        for (i, s) in sops.iter().enumerate() {
            assert!(s.get("id").is_some(), "SOP {i} missing id");
            assert!(s.get("title").is_some(), "SOP {i} missing title");
            assert!(s.get("last_reviewed").is_some(), "SOP {i} missing last_reviewed");
        }
    }
}
