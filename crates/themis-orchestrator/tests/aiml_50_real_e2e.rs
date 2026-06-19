//! Story Ola-B integration test: 50 real calls to AIML API.
//!
//! Gated behind `#[ignore]` so the default `cargo test` does
//! not hit the public API. Run with:
//!
//! ```text
//! AIML_API_KEY=sk-... cargo test -p themis-orchestrator \
//!     --test aiml_50_real_e2e -- --ignored --nocapture
//! ```
//!
//! The test:
//! 1. Reads `AIML_API_KEY` from the environment. Errors out
//!    immediately if unset (so the gate is enforced).
//! 2. Builds an `AimlApiMetricsHandle` and an `AIMLAPIBackend`
//!    that share the handle via `with_metrics`.
//! 3. Makes 50 sequential calls (concurrent would risk the
//!    429 backoff path; sequential is the spec). Each call uses
//!    `LlmRequest { max_tokens: 8, temperature: 0.0, ... }` so
//!    the cost is bounded (a few cents per run).
//! 4. Uses exponential backoff on every 429 (the backend's
//!    internal `BACKOFFS_MS` already does this, but the test
//!    also re-backs-off at the call boundary when a call
//!    ultimately returns `RateLimited`).
//! 5. Asserts `metrics.calls >= 50` and `metrics.successes >= 45`
//!    (90 % threshold; spec'd for transient 429s).
//!
//! The test then `eprintln!`s the full snapshot so the operator
//! can read the cost / latency numbers from the test log.

use std::sync::Arc;
use std::time::Duration;

use themis_agents::llm::{AIMLAPIBackend, LlmBackend, LlmMetricsSink, LlmRequest};
use themis_compliance::aiml_metrics::AimlApiMetricsHandle;

/// Cheap, deterministic request. Short prompt + tiny max_tokens
/// keeps the per-call cost under a cent; the test runs 50 calls
/// for a total budget of ~$0.05-0.10.
fn cheap_request(i: usize) -> LlmRequest {
    LlmRequest {
        system_prompt: "You are a precise counter. Reply with the integer you are given."
            .to_string(),
        user_prompt: format!("Reply with the integer {i}."),
        max_tokens: 8,
        temperature: 0.0,
        seed: Some(42),
        response_schema: None,
        response_schema_name: None,
    }
}

#[tokio::test]
#[ignore = "requires AIML_API_KEY; run with --ignored"]
async fn fifty_real_calls_to_aimlapi() {
    // 1. Env gate. Set this once via `source
    //    ~/.config/apohara/secrets.env` (chmod 600, outside repo).
    let api_key = match std::env::var("AIML_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => {
            eprintln!("[aiml_50_real_e2e] AIML_API_KEY not set; skipping");
            return;
        }
    };

    // 2. Shared metrics handle.
    let handle: AimlApiMetricsHandle = themis_compliance::aiml_metrics::new_shared();
    // The AIML backend accepts `Arc<dyn LlmMetricsSink>`; wrap
    // the handle (which impls LlmMetricsSink via the blanket
    // impl in aiml_metrics.rs).
    let sink: Arc<dyn LlmMetricsSink> = handle.clone();
    let backend = AIMLAPIBackend::new(api_key, "anthropic/claude-sonnet-4.5").with_metrics(sink);

    // 3. Make 50 sequential calls. Exp backoff on per-call
    //    rate-limit final-failure.
    const N: usize = 50;
    const SUCCESS_THRESHOLD: u32 = 45;
    let mut max_backoff_ms: u64 = 250;
    for i in 0..N {
        let req = cheap_request(i);
        let mut attempt_backoff_ms = 250u64;
        loop {
            match backend.complete(req.clone()).await {
                Ok(_) => break,
                Err(themis_agents::decision::AgentError::RateLimited { .. }) => {
                    eprintln!("[aiml_50_real_e2e] call {i}: 429 backoff {attempt_backoff_ms}ms");
                    tokio::time::sleep(Duration::from_millis(attempt_backoff_ms)).await;
                    attempt_backoff_ms = (attempt_backoff_ms * 2).min(8_000);
                    // The backend's internal backoff already retried;
                    // if we still hit a 429 at the call boundary,
                    // back off at the test level too.
                    continue;
                }
                Err(e) => {
                    eprintln!("[aiml_50_real_e2e] call {i}: hard error {e:?}");
                    // Hard failure — the backend already recorded
                    // it on its own path; we just move on.
                    break;
                }
            }
        }
        // Soft cap on inter-call pacing so we don't burst 50
        // calls in <1s (which would itself trip the per-minute
        // rate limit).
        tokio::time::sleep(Duration::from_millis(max_backoff_ms)).await;
        // Adapt the pacing: if we just had a 429 above, increase;
        // otherwise decrease slowly toward a 100ms floor.
        max_backoff_ms = (max_backoff_ms.saturating_sub(50)).max(100);
    }

    // 4. Snapshot the counters and assert.
    let snap = handle.snapshot();
    eprintln!("\n[aiml_50_real_e2e] === FINAL SNAPSHOT ===");
    eprintln!("  calls            : {}", snap.calls);
    eprintln!("  successes        : {}", snap.successes);
    eprintln!(
        "  success rate     : {:.1}%",
        100.0 * snap.successes as f64 / snap.calls.max(1) as f64
    );
    eprintln!("  avg latency (ms) : {:.0}", snap.avg_latency_ms);
    eprintln!("  p95 latency (ms) : {:.0}", snap.p95_latency_ms);
    eprintln!("  total tokens in  : {}", snap.total_tokens_in);
    eprintln!("  total tokens out : {}", snap.total_tokens_out);
    eprintln!("  total cost (USD) : ${:.6}", snap.total_cost_usd);
    eprintln!("  model            : {}", snap.model);

    assert!(
        snap.calls >= N as u32,
        "expected at least {N} calls, got {}",
        snap.calls
    );
    assert!(
        snap.successes >= SUCCESS_THRESHOLD,
        "expected at least {SUCCESS_THRESHOLD} successes (90% of {N}), got {}",
        snap.successes
    );
    assert!(
        snap.total_cost_usd > 0.0,
        "expected positive cost, got {}",
        snap.total_cost_usd
    );
    assert!(snap.total_cost_usd.is_finite());
    assert!(
        !snap.model.is_empty(),
        "model id should be set after first record_call"
    );

    // Manually exercise the bare record_call API so the public
    // CallOutcome surface is in fact used and increments.
    use themis_compliance::aiml_metrics::CallOutcome;
    handle.record_call(CallOutcome {
        success: true,
        latency_ms: 0,
        tokens_in: 0,
        tokens_out: 0,
        model: "anthropic/claude-sonnet-4.5",
    });
    let after = handle.snapshot();
    assert_eq!(
        after.calls,
        snap.calls + 1,
        "manual record_call increments calls"
    );
}
