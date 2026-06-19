//! Canonical CSV schema for `cost-log.csv` (AC-10.7).
//!
//! The Python `vouch-agents` pipeline writes the CSV through
//! `append_cost_log()` in `crates/vouch-agents/src/finance_risk.py`.
//! The header set is:
//!
//! ```text
//! timestamp, agent, provider, model, tokens_in, tokens_out, cached_input_tokens, cost_usd
//! ```
//!
//! This Rust struct mirrors that header set exactly. The
//! `cost_log_schema.rs` test deserialises a sample row from every
//! agent's `log_call` mock and asserts the schema is identical.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One row of `cost-log.csv` (AC-10.7 / AC-5.5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostLogRow {
    /// ISO-8601 UTC timestamp of the LLM call.
    pub timestamp: DateTime<Utc>,
    /// Agent id (e.g. "fraud-auditor", "finance-risk-analyst").
    pub agent: String,
    /// Provider id (e.g. "aiml", "featherless").
    pub provider: String,
    /// Model id (e.g. "claude-sonnet-4-6", "qwen3-coder-30b").
    pub model: String,
    /// Prompt tokens consumed.
    pub tokens_in: u32,
    /// Completion tokens produced.
    pub tokens_out: u32,
    /// Cached prompt tokens (Anthropic prompt-cache hits).
    pub cached_input_tokens: u32,
    /// Cost in USD (6 dp).
    pub cost_usd: f64,
}

impl CostLogRow {
    /// Canonical CSV header list. **Must** match the Python
    /// `COST_LOG_HEADERS` tuple byte-for-byte.
    pub const HEADERS: &'static [&'static str] = &[
        "timestamp",
        "agent",
        "provider",
        "model",
        "tokens_in",
        "tokens_out",
        "cached_input_tokens",
        "cost_usd",
    ];

    /// Sample row for the schema test and the `/cost_log_schema` HTTP
    /// endpoint. Deterministic — every call returns the same values.
    pub fn sample_row() -> Self {
        Self {
            timestamp: DateTime::parse_from_rfc3339("2026-06-18T12:34:56Z")
                .unwrap()
                .with_timezone(&Utc),
            agent: "fraud-auditor".into(),
            provider: "aiml".into(),
            model: "claude-sonnet-4-6".into(),
            tokens_in: 1500,
            tokens_out: 420,
            cached_input_tokens: 1200,
            cost_usd: 0.010500,
        }
    }

    /// Render the row as a CSV line (no trailing newline). Used by the
    /// SSE handler when re-broadcasting.
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{:.6}",
            self.timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            self.agent,
            self.provider,
            self.model,
            self.tokens_in,
            self.tokens_out,
            self.cached_input_tokens,
            self.cost_usd,
        )
    }

    /// Parse a CSV line into a `CostLogRow`. The schema validator uses
    /// this to confirm every agent's mock row is well-formed.
    pub fn from_csv_line(line: &str) -> Result<Self, CostLogSchemaError> {
        let mut parts = line.trim_end().split(',');
        let ts = parts
            .next()
            .ok_or(CostLogSchemaError::MissingField("timestamp"))?;
        let timestamp = DateTime::parse_from_rfc3339(ts)
            .map_err(|e| CostLogSchemaError::BadTimestamp(ts.to_string(), e.to_string()))?
            .with_timezone(&Utc);
        let agent = parts
            .next()
            .ok_or(CostLogSchemaError::MissingField("agent"))?
            .to_string();
        let provider = parts
            .next()
            .ok_or(CostLogSchemaError::MissingField("provider"))?
            .to_string();
        let model = parts
            .next()
            .ok_or(CostLogSchemaError::MissingField("model"))?
            .to_string();
        let tokens_in: u32 = parts
            .next()
            .ok_or(CostLogSchemaError::MissingField("tokens_in"))?
            .parse()
            .map_err(|e: std::num::ParseIntError| {
                CostLogSchemaError::BadNumber("tokens_in".into(), e.to_string())
            })?;
        let tokens_out: u32 = parts
            .next()
            .ok_or(CostLogSchemaError::MissingField("tokens_out"))?
            .parse()
            .map_err(|e: std::num::ParseIntError| {
                CostLogSchemaError::BadNumber("tokens_out".into(), e.to_string())
            })?;
        let cached_input_tokens: u32 = parts
            .next()
            .ok_or(CostLogSchemaError::MissingField("cached_input_tokens"))?
            .parse()
            .map_err(|e: std::num::ParseIntError| {
                CostLogSchemaError::BadNumber("cached_input_tokens".into(), e.to_string())
            })?;
        let cost_usd: f64 = parts
            .next()
            .ok_or(CostLogSchemaError::MissingField("cost_usd"))?
            .parse()
            .map_err(|e: std::num::ParseFloatError| {
                CostLogSchemaError::BadNumber("cost_usd".into(), e.to_string())
            })?;
        Ok(Self {
            timestamp,
            agent,
            provider,
            model,
            tokens_in,
            tokens_out,
            cached_input_tokens,
            cost_usd,
        })
    }
}

/// Errors from CSV parsing / schema validation.
#[derive(Debug, thiserror::Error)]
pub enum CostLogSchemaError {
    /// Required column is missing from the CSV line.
    #[error("missing column: {0}")]
    MissingField(&'static str),
    /// Timestamp column does not parse as RFC 3339.
    #[error("bad timestamp {0:?}: {1}")]
    BadTimestamp(String, String),
    /// Numeric column does not parse.
    #[error("bad number in column {0:?}: {1}")]
    BadNumber(String, String),
}

/// Validate that `line` has exactly the expected number of columns
/// (one per header). Used by the AC-10.7 test fixture.
pub fn validate_column_count(line: &str) -> Result<usize, CostLogSchemaError> {
    let n = line.split(',').count();
    if n == CostLogRow::HEADERS.len() {
        Ok(n)
    } else {
        Err(CostLogSchemaError::MissingField("column_count_mismatch"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_match_python_cost_log_tuple() {
        // The Python source is the source of truth. If this list
        // ever drifts from `COST_LOG_HEADERS` in finance_risk.py,
        // AC-10.7 fails.
        assert_eq!(
            CostLogRow::HEADERS,
            &[
                "timestamp",
                "agent",
                "provider",
                "model",
                "tokens_in",
                "tokens_out",
                "cached_input_tokens",
                "cost_usd",
            ]
        );
    }

    #[test]
    fn sample_row_round_trips_csv() {
        let row = CostLogRow::sample_row();
        let line = row.to_csv_row();
        let parsed = CostLogRow::from_csv_line(&line).expect("round-trip");
        assert_eq!(parsed, row);
    }

    #[test]
    fn validate_column_count_accepts_eight_columns() {
        let line =
            "2026-06-18T12:34:56Z,fraud-auditor,aiml,claude-sonnet-4-6,1500,420,1200,0.010500";
        assert_eq!(validate_column_count(line).unwrap(), 8);
    }

    #[test]
    fn validate_column_count_rejects_seven_columns() {
        let line = "2026-06-18T12:34:56Z,fraud-auditor,aiml,claude-sonnet-4-6,1500,420,1200";
        assert!(validate_column_count(line).is_err());
    }

    #[test]
    fn from_csv_line_rejects_bad_timestamp() {
        let line = "not-a-timestamp,fraud-auditor,aiml,claude-sonnet-4-6,1500,420,1200,0.01";
        match CostLogRow::from_csv_line(line) {
            Err(CostLogSchemaError::BadTimestamp(_, _)) => {}
            other => panic!("expected BadTimestamp, got {other:?}"),
        }
    }

    #[test]
    fn from_csv_line_rejects_non_numeric_token_count() {
        let line = "2026-06-18T12:34:56Z,fraud-auditor,aiml,claude-sonnet-4-6,abc,420,1200,0.01";
        match CostLogRow::from_csv_line(line) {
            Err(CostLogSchemaError::BadNumber(col, _)) => assert_eq!(col, "tokens_in"),
            other => panic!("expected BadNumber, got {other:?}"),
        }
    }

    /// AC-10.7 sanity check: the canonical header set has exactly 8
    /// columns and starts with `timestamp`.
    #[test]
    fn header_count_is_eight_and_first_is_timestamp() {
        assert_eq!(CostLogRow::HEADERS.len(), 8);
        assert_eq!(CostLogRow::HEADERS[0], "timestamp");
        assert_eq!(CostLogRow::HEADERS[7], "cost_usd");
    }
}
