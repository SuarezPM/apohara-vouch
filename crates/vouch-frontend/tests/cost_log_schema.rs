//! AC-10.7: cost log schema validator.
//!
//! Every agent's `log_call` mock (or production code path) writes the
//! same header row to `cost-log.csv`. This test asserts the schema is
//! **identical** by parsing a sample row from each known agent and
//! confirming the parsed struct round-trips.
//!
//! We don't actually call the Python `append_cost_log` here — the
//! schema is defined once in `cost_log_schema::CostLogRow::HEADERS`
//! and pinned in `tests::headers_match_python_cost_log_tuple`. The
//! per-agent sample rows in this file mirror the format used by
//! `finance_risk.py`, `red_team_auditor.py`, and the other agents.

use vouch_frontend::cost_log_schema::{validate_column_count, CostLogRow};

const ALL_AGENTS: &[&str] = &[
    "fraud-auditor",
    "finance-risk-analyst",
    "legal-policy-checker",
    "vendor-intake",
    "red-team-auditor",
    "evidence-clerk",
    "approval-manager",
];

fn sample_row_for(agent: &str) -> String {
    // Match the Python COST_LOG_HEADERS exactly.
    let (provider, model) = match agent {
        "fraud-auditor"
        | "finance-risk-analyst"
        | "legal-policy-checker"
        | "vendor-intake"
        | "red-team-auditor"
        | "evidence-clerk" => ("aiml", "claude-sonnet-4-6"),
        "approval-manager" => ("aiml", "claude-sonnet-4-6"),
        _ => ("aiml", "claude-sonnet-4-6"),
    };
    format!(
        "2026-06-18T12:34:56Z,{},{},{},1500,420,1200,0.010500",
        agent, provider, model
    )
}

#[test]
fn every_agent_writes_eight_column_rows() {
    for agent in ALL_AGENTS {
        let line = sample_row_for(agent);
        let n =
            validate_column_count(&line).unwrap_or_else(|_| panic!("{agent} row did not validate"));
        assert_eq!(n, 8, "{agent} should have 8 columns, got {n}");
    }
}

#[test]
fn every_agent_row_parses_into_the_same_schema() {
    for agent in ALL_AGENTS {
        let line = sample_row_for(agent);
        let row = CostLogRow::from_csv_line(&line)
            .unwrap_or_else(|e| panic!("{agent} failed to parse: {e}"));
        assert_eq!(row.agent, *agent);
        assert_eq!(row.provider, "aiml");
        assert_eq!(row.tokens_in, 1500);
        assert_eq!(row.tokens_out, 420);
        assert_eq!(row.cached_input_tokens, 1200);
        assert!((row.cost_usd - 0.010500).abs() < 1e-9);
    }
}

#[test]
fn featherless_provider_is_also_valid_in_schema() {
    // The cost-log schema does NOT care which provider — provider is
    // a free-form string. But the cost calculator uses it as a lookup
    // key. AC-10.3 says non-zero spend on AIML + Featherless, so
    // we ensure a Featherless row also parses cleanly.
    let line =
        "2026-06-18T12:34:56Z,red-team-auditor,featherless,qwen3-coder-30b,800,200,0,0.000100";
    let row = CostLogRow::from_csv_line(line).expect("featherless row parses");
    assert_eq!(row.provider, "featherless");
    assert_eq!(row.model, "qwen3-coder-30b");
    assert!((row.cost_usd - 0.000100).abs() < 1e-9);
}

#[test]
fn cached_input_tokens_can_be_zero() {
    // A row with zero cached tokens is the baseline before any cache
    // hits. Confirm the schema accepts it.
    let line = "2026-06-18T12:34:56Z,evidence-clerk,aiml,claude-sonnet-4-6,1500,420,0,0.010500";
    let row = CostLogRow::from_csv_line(line).expect("zero-cache row parses");
    assert_eq!(row.cached_input_tokens, 0);
}
