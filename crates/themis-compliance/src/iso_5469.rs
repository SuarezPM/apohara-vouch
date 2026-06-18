//! ISO/IEC 5469 — AI functional safety mapper (regulatory completion B, C-16b).
//!
//! ISO/IEC 5469 (functional safety for AI systems) is the AI-specific
//! counterpart to IEC 61508 (the industrial functional-safety standard).
//! For Track 3 demos, the 5 BAAAR HALT conditions give ISO 5469 a
//! concrete "safe-state" mechanism: when any condition fires, THEMIS
//! transitions to a deterministic halt with a cryptographically-signed
//! evidence packet. The four severity levels (CRITICAL / HIGH / MEDIUM
//! / LOW) cover the full IEC 61508 SIL-1..SIL-4 spectrum.
//!
//! MVP scope: `derive()` returns 5 sample HALT events — one per BAAAR
//! condition — covering the four severity levels at least once. The
//! follow-up sprint will wire the BAAAR event log so each `HaltEvent`
//! reflects an actual halt from the orchestrator.

use chrono::{DateTime, Utc};
use serde::Serialize;

/// A single BAAAR HALT event, projected into the ISO 5469 frame.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HaltEvent {
    /// Stable run identifier (the orchestrator's run UUID, when wired).
    pub run_id: String,
    /// Human-readable reason for the halt (e.g. "risk_score > 0.85").
    pub reason: String,
    /// Severity: CRITICAL, HIGH, MEDIUM, or LOW.
    pub severity: String,
    /// When the halt was observed.
    pub timestamp: DateTime<Utc>,
}

/// The full ISO/IEC 5469 functional-safety report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Iso5469Report {
    /// The BAAAR HALT events.
    pub halt_events: Vec<HaltEvent>,
    /// Total halt count (mirrors `halt_events.len()`; explicit for JSON
    /// readers that prefer a scalar).
    pub total_halts: u32,
    /// When the report was generated.
    pub generated_at: DateTime<Utc>,
}

/// Derive the ISO/IEC 5469 functional-safety report.
///
/// MVP: returns 5 sample HALT events (one per BAAAR condition) with
/// placeholder run_ids and reasons. The follow-up wires the actual
/// BAAAR event log from `themis-orchestrator`.
pub fn derive() -> Iso5469Report {
    let now = Utc::now();

    // 5 sample halts covering the 5 BAAAR conditions, with severities
    // chosen so every level (CRITICAL, HIGH, MEDIUM, LOW) appears at
    // least once.
    let halt_events = vec![
        // Condition 1: risk_score > 0.85 — CRITICAL (the canonical halt).
        HaltEvent {
            run_id: "run-baar-001".to_string(),
            reason: "risk_score exceeded 0.85 threshold (BAAAR condition 1)".to_string(),
            severity: "CRITICAL".to_string(),
            timestamp: now,
        },
        // Condition 2: secret_leak — CRITICAL (data exfiltration).
        HaltEvent {
            run_id: "run-baar-002".to_string(),
            reason: "potential secret leakage detected in agent output (BAAAR condition 2)"
                .to_string(),
            severity: "CRITICAL".to_string(),
            timestamp: now,
        },
        // Condition 3: coherence_score < 0.3 — MEDIUM (model degraded).
        HaltEvent {
            run_id: "run-baar-003".to_string(),
            reason: "inter-agent coherence score dropped below 0.3 (BAAAR condition 3)"
                .to_string(),
            severity: "MEDIUM".to_string(),
            timestamp: now,
        },
        // Condition 4: debate_rounds >= 5 — HIGH (agents not converging).
        HaltEvent {
            run_id: "run-baar-004".to_string(),
            reason: "debate reached 5 rounds without consensus (BAAAR condition 4)".to_string(),
            severity: "HIGH".to_string(),
            timestamp: now,
        },
        // Condition 5: explicit_halt_requested — LOW (human intervention).
        HaltEvent {
            run_id: "run-baar-005".to_string(),
            reason: "HITL operator requested explicit halt (BAAAR condition 5)".to_string(),
            severity: "LOW".to_string(),
            timestamp: now,
        },
    ];

    let total_halts = halt_events.len() as u32;

    Iso5469Report {
        halt_events,
        total_halts,
        generated_at: now,
    }
}

/// Serialize the ISO/IEC 5469 report to JSON.
pub fn to_json(report: &Iso5469Report) -> serde_json::Value {
    serde_json::json!({
        "standard": "ISO/IEC 5469",
        "title": "AI functional safety",
        "total_halts": report.total_halts,
        "generated_at": report.generated_at.to_rfc3339(),
        "halt_events": report.halt_events.iter().map(|h| {
            serde_json::json!({
                "run_id": h.run_id,
                "reason": h.reason,
                "severity": h.severity,
                "timestamp": h.timestamp.to_rfc3339(),
            })
        }).collect::<Vec<serde_json::Value>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_includes_5_halts() {
        let r = derive();
        assert_eq!(
            r.halt_events.len(),
            5,
            "expected 5 halt events, got {}",
            r.halt_events.len()
        );
        assert_eq!(r.total_halts, 5);
    }

    #[test]
    fn halts_cover_all_severities() {
        let r = derive();
        let severities: std::collections::HashSet<&str> =
            r.halt_events.iter().map(|h| h.severity.as_str()).collect();
        assert!(severities.contains("CRITICAL"), "missing CRITICAL severity");
        assert!(severities.contains("HIGH"), "missing HIGH severity");
        assert!(severities.contains("MEDIUM"), "missing MEDIUM severity");
        assert!(severities.contains("LOW"), "missing LOW severity");
        // Every halt has a non-empty reason and run_id.
        for h in &r.halt_events {
            assert!(!h.run_id.is_empty(), "halt run_id must not be empty");
            assert!(!h.reason.is_empty(), "halt reason must not be empty");
            assert!(!h.severity.is_empty(), "halt severity must not be empty");
        }
    }

    #[test]
    fn to_json_serializes_all_halts() {
        let r = derive();
        let j = to_json(&r);
        assert_eq!(j.get("standard").and_then(|v| v.as_str()), Some("ISO/IEC 5469"));
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
        for (i, h) in halts.iter().enumerate() {
            assert!(h.get("run_id").is_some(), "halt {i} missing run_id");
            assert!(h.get("reason").is_some(), "halt {i} missing reason");
            assert!(h.get("severity").is_some(), "halt {i} missing severity");
            assert!(h.get("timestamp").is_some(), "halt {i} missing timestamp");
        }
    }
}
