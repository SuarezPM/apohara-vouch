//! vouch-frontend — demo UI for vouch.apohara.dev (S-10).
//!
//! This crate is **parallel** to `themis-frontend`. Different name, same
//! pattern: Axum server + vanilla HTML/JS + SSE stream. The two crates
//! are deliberately separated because the THEMIS demo (PR review, 6
//! agents, BAAAR HALT) and the VOUCH demo (invoice fraud, 5 agents, EU
//! AI Act Art. 12 dashboard) have different compliance surfaces and
//! different cost-rate tables.
//!
//! The Python `vouch-agents` pipeline writes `cost-log.csv`; this crate
//! reads it and pushes each row as an SSE event to the browser. The
//! `/evidence/:case_id` endpoint serves a C2PA-signed PDF that the
//! Python `approval_manager.render_memo_pdf` produces (cached in memory
//! after first generation so the second download is instant — AC-10.5
//! <2s).

#![warn(missing_docs)]

/// SSE handler + evidence download endpoint.
pub mod sse;

/// Rate table + cost-math helpers.
pub mod cost_calculator;

/// Canonical CSV header + row schema validator.
pub mod cost_log_schema;

/// In-memory Evidence Packet PDF cache (case_id -> bytes).
pub mod evidence_cache;

/// Crate version + name.
pub fn version() -> &'static str {
    "vouch-frontend"
}

/// Re-export the 8 EU AI Act Article 12 fields so the frontend crate and
/// the test fixtures agree on the field set. Sourced from
/// `vouch-receipt` (the canonical 8-field list, AC-3.9 / AC-10.4).
pub use vouch_receipt::EU_AI_ACT_ART12_FIELDS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "vouch-frontend");
    }

    #[test]
    fn art12_fields_count_is_eight() {
        assert_eq!(EU_AI_ACT_ART12_FIELDS.len(), 8);
    }

    #[test]
    fn art12_fields_are_canonical_names() {
        // Pin the field set so a silent rename in vouch-receipt
        // would break this test and surface the regression.
        assert_eq!(EU_AI_ACT_ART12_FIELDS[0], "start_time");
        assert_eq!(EU_AI_ACT_ART12_FIELDS[1], "end_time");
        assert_eq!(EU_AI_ACT_ART12_FIELDS[2], "reference_database");
        assert_eq!(EU_AI_ACT_ART12_FIELDS[3], "input_data");
        assert_eq!(EU_AI_ACT_ART12_FIELDS[4], "natural_person_id");
        assert_eq!(EU_AI_ACT_ART12_FIELDS[5], "decision_id");
        assert_eq!(EU_AI_ACT_ART12_FIELDS[6], "policy_version");
        assert_eq!(EU_AI_ACT_ART12_FIELDS[7], "hash_chain_prev");
    }
}
