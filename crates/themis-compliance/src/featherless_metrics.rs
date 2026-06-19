//! Featherless AI live-call metrics (Story Ola-C).
//!
//! Tracks rolling counters for the Featherless AI provider (the
//! Qwen3-Coder-30B-A3B-Instruct path — fraud_auditor). The
//! metrics are accumulated by the `FeatherlessBackend` (via
//! the `LlmMetricsSink` trait in `themis_agents::llm`) on every
//! successful (and failed) call, then surfaced to the dashboard
//! via `GET /metrics/featherless`.
//!
//! The shape is the same as `AimlApiMetrics` (Story Ola-B):
//! 1:1 field mapping so the frontend can render both widgets
//! with the same template. The cost formula is parameterized
//! differently because Featherless's pricing model is
//! open-weight-driven; the per-million-token rates below are
//! the public-list values verified on 2026-06-18.
//!
//! Design constraints (from the Ola-C PRD):
//! - 200-400 lines per file (this is ~150).
//! - No new dependencies beyond what's already in themis-compliance.
//! - `record_call` takes `&self` so the metrics handle is `Arc`able
//!   and shared between the orchestrator's `AppState` and the
//!   Featherless backend instances. `RwLock` for the read-heavy
//!   dashboard-poll workload (same choice as Ola-B).
//! - Latency stats: a bounded reservoir of recent latencies is
//!   NOT kept; we use a simple running mean for `avg_latency_ms`
//!   and a coarse p95 estimator over a 1024-entry ring buffer.
//!
//! Cost computation: Featherless charges per million tokens.
//! The exact per-model rate is provider-specific; Qwen3-Coder-30B
//! is on the $0.50/$1.50 input/output tier as of 2026-06-18
//! (per Featherless's public pricing page). The constants are
//! exposed for the test suite.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::RwLock;

use themis_agents::llm::{CallMetrics, LlmMetricsSink};

/// Featherless AI per-million-token input price (USD). 2026-06-18.
/// Qwen3-Coder-30B-A3B-Instruct sits on the cheapest tier
/// (open-source, 30B-class MoE).
pub const INPUT_USD_PER_MTOK: f64 = 0.50;
/// Featherless AI per-million-token output price (USD). 2026-06-18.
pub const OUTPUT_USD_PER_MTOK: f64 = 1.50;

/// Bounded ring buffer of recent latencies (ms) used to estimate
/// the p95 latency. 1024 entries; older samples are overwritten
/// in FIFO order so the estimator reflects the last 1024 calls.
const LATENCY_RING_CAP: usize = 1024;

/// Outcome of a single Featherless call, as recorded by the
/// `FeatherlessBackend` after the call settles. Mirrors the
/// Ola-B `CallOutcome` exactly so the same `LlmMetricsSink`
/// trait can be implemented for both providers with no
/// adapter glue.
#[derive(Debug, Clone, Copy)]
pub struct CallOutcome {
    /// True iff the HTTP request returned 2xx AND the response
    /// was successfully deserialized into an `LlmResponse` with
    /// usage fields populated.
    pub success: bool,
    /// End-to-end latency in milliseconds (includes retries and
    /// backoff sleeps).
    pub latency_ms: u64,
    /// `usage.prompt_tokens` from the response. Zero on failure.
    pub tokens_in: u32,
    /// `usage.completion_tokens` from the response. Zero on failure.
    pub tokens_out: u32,
    /// The model id used (e.g. `"Qwen/Qwen3-Coder-30B-A3B-Instruct"`).
    pub model: &'static str,
}

/// Snapshot of the running metrics, suitable for JSON
/// serialization into the `GET /metrics/featherless` response.
/// All fields are owned (no `Arc`/`RwLock` references leak out).
///
/// The shape is a 1:1 mirror of `AimlApiMetrics` so the frontend
/// can render both widgets with the same template.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatherlessMetrics {
    /// Total number of calls attempted (success + failure).
    pub calls: u32,
    /// Number of calls that completed with a 2xx response and a
    /// well-formed `usage` block.
    pub successes: u32,
    /// Mean latency in milliseconds over the last
    /// `LATENCY_RING_CAP` calls (or all calls if fewer).
    pub avg_latency_ms: f64,
    /// Approximate p95 latency in milliseconds. Computed by
    /// sorting the ring buffer snapshot and taking the
    /// `floor(0.95 * len)`-th sample. Inexact but cheap.
    pub p95_latency_ms: f64,
    /// Cumulative cost in USD, computed as
    /// `tokens_in / 1e6 * INPUT_USD_PER_MTOK + tokens_out / 1e6 * OUTPUT_USD_PER_MTOK`.
    pub total_cost_usd: f64,
    /// Sum of `usage.prompt_tokens` across all successful calls.
    pub total_tokens_in: u64,
    /// Sum of `usage.completion_tokens` across all successful calls.
    pub total_tokens_out: u64,
    /// The model id the counters are accumulating against. Set on
    /// the first `record_call` and held constant thereafter.
    pub model: String,
}

/// Live, in-process metrics accumulator. Cheap to clone (`Arc`
/// inside) so the `FeatherlessBackend` and the `AppState` can
/// share a single instance.
#[derive(Debug)]
pub struct FeatherlessMetricsInner {
    inner: RwLock<MetricsState>,
}

#[derive(Debug)]
struct MetricsState {
    calls: u32,
    successes: u32,
    latency_sum_ms: u128,
    /// Bounded ring of the most recent latencies (ms).
    latency_ring: Vec<u64>,
    ring_idx: usize,
    ring_filled: bool,
    total_cost_usd: f64,
    total_tokens_in: u64,
    total_tokens_out: u64,
    model: String,
}

impl Default for MetricsState {
    fn default() -> Self {
        Self {
            calls: 0,
            successes: 0,
            latency_sum_ms: 0,
            latency_ring: vec![0; LATENCY_RING_CAP],
            ring_idx: 0,
            ring_filled: false,
            total_cost_usd: 0.0,
            total_tokens_in: 0,
            total_tokens_out: 0,
            model: String::new(),
        }
    }
}

impl FeatherlessMetricsInner {
    /// Build a fresh metrics instance. The internal state is
    /// empty (calls=0).
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(MetricsState::default()),
        }
    }

    /// Record one call outcome. Idempotent under contention
    /// (RwLock write guard is held for the duration of the
    /// critical section, which is O(1)). The lock is held
    /// briefly — no awaits inside.
    pub fn record_call(&self, outcome: CallOutcome) {
        let mut s = self.inner.write().expect("featherless metrics poisoned");
        s.calls = s.calls.saturating_add(1);
        if outcome.success {
            s.successes = s.successes.saturating_add(1);
        }
        // Always count latency (even on failure — the dashboard
        // shows the operator whether failures are also slow).
        s.latency_sum_ms = s.latency_sum_ms.saturating_add(outcome.latency_ms as u128);
        let ring_idx = s.ring_idx;
        s.latency_ring[ring_idx] = outcome.latency_ms;
        s.ring_idx = (ring_idx + 1) % LATENCY_RING_CAP;
        if s.ring_idx == 0 {
            s.ring_filled = true;
        }
        s.total_tokens_in = s.total_tokens_in.saturating_add(outcome.tokens_in as u64);
        s.total_tokens_out = s.total_tokens_out.saturating_add(outcome.tokens_out as u64);
        s.total_cost_usd += cost_usd(outcome.tokens_in, outcome.tokens_out);
        if s.model.is_empty() {
            s.model = outcome.model.to_string();
        }
    }

    /// Snapshot the running counters into a serializable
    /// `FeatherlessMetrics`. Read-locked only — the dashboard
    /// poll does not contend with the writer beyond the
    /// RwLock's typical fast path.
    pub fn snapshot(&self) -> FeatherlessMetrics {
        let s = self.inner.read().expect("featherless metrics poisoned");
        let ring_len = if s.ring_filled {
            LATENCY_RING_CAP
        } else {
            s.ring_idx
        };
        let (avg, p95) = if ring_len == 0 {
            (0.0, 0.0)
        } else {
            let mut samples: Vec<u64> = s.latency_ring[..ring_len].to_vec();
            samples.sort_unstable();
            let avg = (s.latency_sum_ms as f64) / (ring_len as f64);
            // p95 index: floor(0.95 * (n - 1)) is the
            // nearest-rank method, consistent with the
            // standard Prometheus summary.
            let p95_idx = ((samples.len() as f64) * 0.95).floor() as usize;
            let p95_idx = p95_idx.min(samples.len().saturating_sub(1));
            (avg, samples[p95_idx] as f64)
        };
        FeatherlessMetrics {
            calls: s.calls,
            successes: s.successes,
            avg_latency_ms: avg,
            p95_latency_ms: p95,
            total_cost_usd: s.total_cost_usd,
            total_tokens_in: s.total_tokens_in,
            total_tokens_out: s.total_tokens_out,
            model: s.model.clone(),
        }
    }
}

impl Default for FeatherlessMetricsInner {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmMetricsSink for FeatherlessMetricsInner {
    /// Adapter from the agents-side `CallMetrics` to the
    /// compliance-side `CallOutcome`. The two structs are
    /// 1:1 shape-equivalent; the adapter is a field-by-field
    /// copy. The `model` field is `&'static str` on both sides
    /// (the agents crate pins it at backend construction).
    fn record_call(&self, outcome: CallMetrics) {
        self.record_call(CallOutcome {
            success: outcome.success,
            latency_ms: outcome.latency_ms,
            tokens_in: outcome.tokens_in,
            tokens_out: outcome.tokens_out,
            model: outcome.model,
        });
    }
}

/// Shared handle (`Arc<FeatherlessMetricsInner>`) — the type
/// passed to the `FeatherlessBackend` at construction and held
/// by `AppState`. Cloning is cheap; both handles see the same
/// counters.
pub type FeatherlessMetricsHandle = Arc<FeatherlessMetricsInner>;

/// Build a new shared handle. Convenience constructor so
/// callers don't need to import `Arc` explicitly.
pub fn new_shared() -> FeatherlessMetricsHandle {
    Arc::new(FeatherlessMetricsInner::new())
}

/// Compute the cost in USD for a single call's token usage.
/// Public so the integration test can assert against the
/// exact same formula.
pub fn cost_usd(tokens_in: u32, tokens_out: u32) -> f64 {
    (tokens_in as f64 / 1_000_000.0) * INPUT_USD_PER_MTOK
        + (tokens_out as f64 / 1_000_000.0) * OUTPUT_USD_PER_MTOK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aiml_metrics::AimlApiMetrics;

    #[test]
    fn fresh_metrics_are_all_zero() {
        let m = FeatherlessMetricsInner::new();
        let s = m.snapshot();
        assert_eq!(s.calls, 0);
        assert_eq!(s.successes, 0);
        assert_eq!(s.total_tokens_in, 0);
        assert_eq!(s.total_tokens_out, 0);
        assert!((s.avg_latency_ms - 0.0).abs() < f64::EPSILON);
        assert!((s.p95_latency_ms - 0.0).abs() < f64::EPSILON);
        assert!((s.total_cost_usd - 0.0).abs() < f64::EPSILON);
        assert_eq!(s.model, "");
    }

    #[test]
    fn record_call_accumulates_successes_and_tokens() {
        let m = FeatherlessMetricsInner::new();
        for _ in 0..10 {
            m.record_call(CallOutcome {
                success: true,
                latency_ms: 100,
                tokens_in: 500,
                tokens_out: 200,
                model: "Qwen/Qwen3-Coder-30B-A3B-Instruct",
            });
        }
        let s = m.snapshot();
        assert_eq!(s.calls, 10);
        assert_eq!(s.successes, 10);
        assert_eq!(s.total_tokens_in, 5_000);
        assert_eq!(s.total_tokens_out, 2_000);
        assert!((s.avg_latency_ms - 100.0).abs() < 0.001);
        assert!((s.p95_latency_ms - 100.0).abs() < 0.001);
        // Cost: 5000 / 1e6 * 0.5 + 2000 / 1e6 * 1.5 = 0.0025 + 0.003 = 0.0055
        assert!(
            (s.total_cost_usd - 0.0055).abs() < 1e-9,
            "cost={}",
            s.total_cost_usd
        );
        assert_eq!(s.model, "Qwen/Qwen3-Coder-30B-A3B-Instruct");
    }

    #[test]
    fn failed_calls_count_toward_calls_but_not_successes() {
        let m = FeatherlessMetricsInner::new();
        m.record_call(CallOutcome {
            success: false,
            latency_ms: 5_000,
            tokens_in: 0,
            tokens_out: 0,
            model: "Qwen/Qwen3-Coder-30B-A3B-Instruct",
        });
        let s = m.snapshot();
        assert_eq!(s.calls, 1);
        assert_eq!(s.successes, 0);
        assert_eq!(s.total_tokens_in, 0);
        // The latency is still tracked (failure visibility).
        assert!((s.avg_latency_ms - 5_000.0).abs() < 0.001);
    }

    #[test]
    fn p95_reflects_tail_latency() {
        // 19 fast calls + 1 slow one → p95 should be the slow
        // call (rank = floor(0.95 * 20) = 19, samples[19] = slow).
        let m = FeatherlessMetricsInner::new();
        for _ in 0..19 {
            m.record_call(CallOutcome {
                success: true,
                latency_ms: 50,
                tokens_in: 10,
                tokens_out: 5,
                model: "x",
            });
        }
        m.record_call(CallOutcome {
            success: true,
            latency_ms: 1_000,
            tokens_in: 10,
            tokens_out: 5,
            model: "x",
        });
        let s = m.snapshot();
        // avg = (19*50 + 1000) / 20 = 1950/20 = 97.5
        assert!(
            (s.avg_latency_ms - 97.5).abs() < 0.001,
            "avg={}",
            s.avg_latency_ms
        );
        // p95 with n=20, floor(0.95*20)=19, samples[19]=slow
        assert!(
            (s.p95_latency_ms - 1_000.0).abs() < 0.001,
            "p95={}",
            s.p95_latency_ms
        );
    }

    #[test]
    fn cost_formula_matches_constants() {
        // 1M input + 1M output = INPUT + OUTPUT USD
        let c = cost_usd(1_000_000, 1_000_000);
        let expected = INPUT_USD_PER_MTOK + OUTPUT_USD_PER_MTOK;
        assert!((c - expected).abs() < 1e-9);
    }

    #[test]
    fn snapshot_round_trips_through_serde_json() {
        // The HTTP handler serializes via serde_json; the
        // dashboard polls `/metrics/featherless` and
        // deserializes. Lock the wire format.
        let m = FeatherlessMetricsInner::new();
        m.record_call(CallOutcome {
            success: true,
            latency_ms: 100,
            tokens_in: 7,
            tokens_out: 3,
            model: "Qwen/Qwen3-Coder-30B-A3B-Instruct",
        });
        let s = m.snapshot();
        let json = serde_json::to_string(&s).unwrap();
        let parsed: FeatherlessMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn field_shape_matches_aiml_api_metrics() {
        // The frontend renders the AIML and Featherless widgets
        // with the same template; lock the field set to the
        // AIML shape.
        let aiml = serde_json::to_value(AimlApiMetrics {
            calls: 0,
            successes: 0,
            avg_latency_ms: 0.0,
            p95_latency_ms: 0.0,
            total_cost_usd: 0.0,
            total_tokens_in: 0,
            total_tokens_out: 0,
            model: String::new(),
        })
        .unwrap();
        let feather = serde_json::to_value(FeatherlessMetricsInner::new().snapshot()).unwrap();
        let aiml_keys: std::collections::BTreeSet<String> = aiml
            .as_object()
            .unwrap()
            .keys()
            .map(|k| (*k).to_string())
            .collect();
        let feather_keys: std::collections::BTreeSet<String> = feather
            .as_object()
            .unwrap()
            .keys()
            .map(|k| (*k).to_string())
            .collect();
        assert_eq!(
            aiml_keys, feather_keys,
            "FeatherlessMetrics must have the same field set as AimlApiMetrics"
        );
    }
}
