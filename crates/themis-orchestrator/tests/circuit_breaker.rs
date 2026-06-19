//! Integration tests for Story C-05 — Circuit breaker + exponential
//! backoff (ASI08 / G21).
//!
//! Verifies the full state machine deterministically using a
//! short timeout (100ms) instead of waiting 30s. The same
//! transitions apply at the production 30s timeout.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use themis_orchestrator::circuit_breaker::{CircuitBreaker, CircuitBreakerError, CircuitState};
use themis_orchestrator::retry::{retry_with_backoff, BackoffPolicy};

/// Threshold=5 (matches PRD). Timeout=100ms (test-friendly
/// substitute for the production 30s, otherwise tests would
/// block for half a minute each).
const THRESHOLD: u32 = 5;
const TEST_TIMEOUT: Duration = Duration::from_millis(100);

fn err_str() -> Result<(), &'static str> {
    Err("nope")
}

#[test]
fn test_breaker_opens_at_5_failures_and_rejects() {
    let cb = CircuitBreaker::with_params(THRESHOLD, TEST_TIMEOUT);
    for i in 0..THRESHOLD {
        let r: Result<(), CircuitBreakerError<&'static str>> = cb.call(err_str);
        assert!(
            matches!(r, Err(CircuitBreakerError::Inner("nope"))),
            "call {i} should be Inner error, got {r:?}"
        );
        if i + 1 < THRESHOLD {
            assert!(
                matches!(cb.state(), CircuitState::Closed),
                "still Closed after {} failures",
                i + 1
            );
        }
    }
    // After 5 failures, the breaker is Open.
    assert!(
        matches!(cb.state(), CircuitState::Open { .. }),
        "state must be Open after {THRESHOLD} failures, got {:?}",
        cb.state()
    );
    // 6th call is rejected without running.
    let r: Result<(), CircuitBreakerError<&'static str>> = cb.call(|| Ok(()));
    assert!(
        matches!(r, Err(CircuitBreakerError::Rejected { .. })),
        "6th call must be Rejected, got {r:?}"
    );
}

#[test]
fn test_breaker_half_opens_after_timeout() {
    let cb = CircuitBreaker::with_params(THRESHOLD, TEST_TIMEOUT);
    for _ in 0..THRESHOLD {
        let _: Result<(), CircuitBreakerError<&'static str>> = cb.call(err_str);
    }
    assert!(matches!(cb.state(), CircuitState::Open { .. }));

    // Wait past the timeout — instead of 30s, we use 120ms.
    std::thread::sleep(TEST_TIMEOUT + Duration::from_millis(20));

    // Next call should transition Open → HalfOpen and execute.
    let r: Result<i32, CircuitBreakerError<&'static str>> = cb.call(|| Ok(123));
    assert!(matches!(r, Ok(123)), "expected Ok(123), got {r:?}");
    // On success in HalfOpen, state transitions to Closed.
    assert!(matches!(cb.state(), CircuitState::Closed));
}

#[test]
fn test_breaker_recovers_on_success() {
    let cb = CircuitBreaker::with_params(THRESHOLD, TEST_TIMEOUT);
    for _ in 0..THRESHOLD {
        let _: Result<(), CircuitBreakerError<&'static str>> = cb.call(err_str);
    }
    assert!(matches!(cb.state(), CircuitState::Open { .. }));

    // Wait past timeout → next call enters HalfOpen.
    std::thread::sleep(TEST_TIMEOUT + Duration::from_millis(20));

    // Trial call succeeds → Closed.
    let r: Result<&'static str, CircuitBreakerError<&'static str>> = cb.call(|| Ok("trial-ok"));
    assert!(
        matches!(r, Ok("trial-ok")),
        "expected Ok(trial-ok), got {r:?}"
    );
    assert!(matches!(cb.state(), CircuitState::Closed));
    assert_eq!(cb.failures.load(Ordering::SeqCst), 0);

    // And a fresh Closed breaker accepts more calls.
    let r2: Result<&'static str, CircuitBreakerError<&'static str>> =
        cb.call(|| Ok("after-recovery"));
    assert!(matches!(r2, Ok("after-recovery")));
}

#[tokio::test(flavor = "current_thread")]
async fn test_retry_exponential_backoff_timing() {
    // The retry module uses tokio::time::sleep under the hood.
    // We use a short policy (5 attempts, 10ms initial, 2x) so the
    // whole test runs in <100ms wall-clock and verifies the
    // exponential schedule matches the PRD shape (delays double
    // each attempt). The production config is 100/200/400/800/
    // 1600ms — same ratio, just scaled 10×.
    let p = BackoffPolicy {
        max_attempts: 5,
        initial_delay: Duration::from_millis(10),
        multiplier: 2.0,
    };

    // 1. Schedule shape: verify the delays are exactly 10/20/40/80ms.
    assert_eq!(p.compute_delay(0), Duration::from_millis(10));
    assert_eq!(p.compute_delay(1), Duration::from_millis(20));
    assert_eq!(p.compute_delay(2), Duration::from_millis(40));
    assert_eq!(p.compute_delay(3), Duration::from_millis(80));
    assert_eq!(p.compute_delay(4), Duration::from_millis(160));

    // 2. End-to-end: 5 failing attempts → cumulative sleep = 10+20+40+80 = 150ms.
    let calls = Arc::new(AtomicU32::new(0));
    let calls_in = Arc::clone(&calls);
    let start = std::time::Instant::now();
    let r: Result<(), &'static str> = retry_with_backoff(&p, || {
        let calls = Arc::clone(&calls_in);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Err("permafail")
        }
    })
    .await;
    let elapsed = start.elapsed();
    assert_eq!(r, Err("permafail"));
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    let expected_ms: u64 = 10 + 20 + 40 + 80; // 150ms
    let elapsed_ms = elapsed.as_millis() as u64;
    assert!(
        elapsed_ms >= expected_ms,
        "expected at least {expected_ms}ms cumulative delay, got {elapsed_ms}ms"
    );
}
