//! Story Ola-C integration test: 50 real calls to Featherless AI.
//!
//! Gated behind `#[ignore]` so the default `cargo test` does
//! not hit the public API. Run with:
//!
//!   `cargo test -p themis-orchestrator --test featherless_50_real_e2e -- --ignored --nocapture`
//!
//! The test:
//! 1. Reads `FEATHERLESS_API_KEY` from env. Skips if unset.
//! 2. Creates a `FeatherlessBackend` with the production
//!    Qwen3-Coder-30B-A3B-Instruct model id.
//! 3. Attaches a `FeatherlessMetrics` sink via
//!    `with_metrics(...)` so every call (success or failure)
//!    bumps the counters.
//! 4. Fires 50 real calls in sequence. Stagger by 7ms between
//!    calls (PRD cap: 4 concurrent requests; we use
//!    sequential to stay well under the ceiling, no need for
//!    the parallel-spawn pattern).
//! 5. Snapshots the metrics and asserts `calls >= 50` and
//!    `successes >= 45` (the PRD acceptance criterion allows
//!    up to 5 transient failures — provider timeouts, rate
//!    limits, etc.).
//!
//! The test also exercises the per-agent dispatch in
//! `routing::build_routed_dispatch`: the fraud_auditor key
//! maps to a `FeatherlessBackend` with the metrics sink, and
//! the other 5 LLM-driven agents map to AIML API (skipped in
//! this test, but asserted via the dispatch shape).

use std::sync::Arc;
use std::time::Duration;

use themis_agents::llm::{FeatherlessBackend, LlmBackend, LlmRequest};
use themis_compliance::featherless_metrics::{FeatherlessMetricsHandle, FeatherlessMetricsInner};
use themis_orchestrator::routing::{
    backend_for_agent, build_routed_dispatch, AgentBackend, FRAUD_AUDITOR_FEATHERLESS_MODEL,
};

/// Per-call system prompt. Kept short — the model only needs
/// to know its role for the test to be a valid call.
const SYS_PROMPT: &str = "You are a test client. Respond with one word.";

/// Per-call user prompt. Increments so each call has a
/// distinct body (defensive against any provider-side dedup).
fn user_prompt(i: u32) -> String {
    format!("Call number {i}. Reply with the single word: pong")
}

#[tokio::test]
#[ignore = "requires FEATHERLESS_API_KEY; run with --ignored"]
async fn featherless_50_real_calls_e2e() {
    // 1. Env gate. Skip (with a diagnostic) if no key.
    let api_key = match std::env::var("FEATHERLESS_API_KEY") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            eprintln!("[featherless_50_real_e2e] skip: FEATHERLESS_API_KEY not set");
            return;
        }
    };

    // 2. Metrics sink. Fresh per-test so concurrent runs don't
    //    bleed into each other. The PRD requires the
    //    integration test to assert `calls >= 50` and
    //    `successes >= 45` against the LIVE counters.
    let metrics: FeatherlessMetricsHandle = Arc::new(FeatherlessMetricsInner::new());
    let backend: Arc<dyn LlmBackend> = Arc::new(
        FeatherlessBackend::new(api_key, FRAUD_AUDITOR_FEATHERLESS_MODEL)
            .with_metrics(metrics.clone()),
    );

    // 3. Fire 50 calls sequentially. 7ms stagger between
    //    starts to stay under the 4-concurrent cap (we're
    //    already serial here, so this is just defensive).
    const N: u32 = 50;
    let mut successes = 0u32;
    let mut errors = 0u32;
    for i in 1..=N {
        let req = LlmRequest {
            system_prompt: SYS_PROMPT.to_string(),
            user_prompt: user_prompt(i),
            max_tokens: 16,
            temperature: 0.0,
            seed: None,
            response_schema: None,
            response_schema_name: None,
        };
        match backend.complete(req).await {
            Ok(resp) => {
                if !resp.text.is_empty() {
                    successes += 1;
                } else {
                    errors += 1;
                }
            }
            Err(e) => {
                eprintln!("[featherless_50_real_e2e] call {i} failed: {e}");
                errors += 1;
            }
        }
        // Stagger; skip after the last call.
        if i < N {
            tokio::time::sleep(Duration::from_millis(7)).await;
        }
    }

    // 4. Assert the metrics counters (not the local counters).
    //    The PRD requires the test to validate the live
    //    counters exposed by `FeatherlessMetrics` — that's
    //    the same handle the production binary attaches to
    //    AppState and reads in the `/metrics/featherless`
    //    handler.
    let snap = metrics.snapshot();
    eprintln!(
        "[featherless_50_real_e2e] metrics snapshot: calls={} successes={} tokens_in={} tokens_out={} cost_usd={:.6}",
        snap.calls, snap.successes, snap.total_tokens_in, snap.total_tokens_out, snap.total_cost_usd
    );

    assert!(
        snap.calls >= N,
        "calls counter must be >= {N} (50), got {}",
        snap.calls
    );
    assert!(
        snap.successes >= 45,
        "successes must be >= 45 (PRD allowance for transient failures), got {} (of {} calls)",
        snap.successes,
        snap.calls
    );
    // The model id is set on the first call.
    assert_eq!(snap.model, FRAUD_AUDITOR_FEATHERLESS_MODEL);
    // The local counter and the metrics counter agree (sanity).
    assert_eq!(snap.calls, successes + errors);
}

/// Routing test: when `FEATHERLESS_API_KEY` is set, the
/// `fraud_auditor` key in the dispatch map MUST resolve to a
/// `FeatherlessBackend` with the Qwen3-Coder-30B model id.
/// The other 5 LLM-driven agents must resolve to AIML API
/// (when `AIML_API_KEY` is also set; otherwise to the
/// mock fallback).
#[tokio::test]
#[ignore = "requires FEATHERLESS_API_KEY; run with --ignored"]
async fn routing_fraud_auditor_uses_featherless() {
    let api_key = match std::env::var("FEATHERLESS_API_KEY") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            eprintln!("[routing_fraud_auditor_uses_featherless] skip: FEATHERLESS_API_KEY not set");
            return;
        }
    };
    // The dispatch map is built from env. Sanity: the key IS
    // set (we just read it). The dispatch will route the
    // fraud_auditor to Featherless.
    let _ = api_key; // suppress unused warning

    // Pure logic check first: backend_for_agent ignores env.
    assert_eq!(
        backend_for_agent("fraud_auditor"),
        AgentBackend::Featherless,
        "fraud_auditor MUST route to Featherless per the Ola-C PRD"
    );
    assert_eq!(
        backend_for_agent("extractor"),
        AgentBackend::AimlApi,
        "extractor MUST route to AIML API"
    );
    assert_eq!(
        backend_for_agent("gaap_classifier"),
        AgentBackend::AimlApi,
        "gaap_classifier MUST route to AIML API"
    );
    assert_eq!(
        backend_for_agent("demo_narrator"),
        AgentBackend::AimlApi,
        "shadow agents MUST route to AIML API"
    );
    assert_eq!(
        backend_for_agent("po_matcher"),
        AgentBackend::None,
        "po_matcher is deterministic — no LLM"
    );

    // Dispatch map check: with the env set, the live
    // dispatch table maps fraud_auditor to the Featherless
    // Qwen3 model and the other 5 to the AIML API Claude
    // Sonnet model.
    let metrics: FeatherlessMetricsHandle = Arc::new(FeatherlessMetricsInner::new());
    let dispatch = build_routed_dispatch(metrics);
    let fa = dispatch
        .get("fraud_auditor")
        .expect("dispatch has fraud_auditor");
    assert_eq!(
        fa.model_id(),
        FRAUD_AUDITOR_FEATHERLESS_MODEL,
        "fraud_auditor dispatch entry must be the Featherless Qwen3 model when FEATHERLESS_API_KEY is set, got {}",
        fa.model_id()
    );
    // The other 5 LLM-driven agents: AIML API if key set, else
    // mock fallback. Both are valid; the test asserts the
    // dispatch entry exists and is non-Featherless.
    for name in [
        "extractor",
        "gaap_classifier",
        "demo_narrator",
        "regression_tester",
        "audit_watchdog",
    ] {
        let m = dispatch.get(name).expect("dispatch has entry");
        assert_ne!(
            m.model_id(),
            FRAUD_AUDITOR_FEATHERLESS_MODEL,
            "{name} MUST NOT use the Featherless model — only fraud_auditor does"
        );
    }
}
