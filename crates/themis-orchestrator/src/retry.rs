//! Exponential backoff retry — ASI08 defense in depth.
//!
//! Wraps any async fallible operation with an exponential backoff
//! retry policy. Each `BackoffPolicy::compute_delay(attempt)` returns
//! `initial * multiplier^attempt`, capped at 5 seconds.
//!
//! Default sequence at `initial = 100ms`, `multiplier = 2.0`:
//!
//! ```text
//!   attempt 0 →   100ms
//!   attempt 1 →   200ms
//!   attempt 2 →   400ms
//!   attempt 3 →   800ms
//!   attempt 4 →  1600ms
//!   attempt 5 →  3200ms (capped at 5000ms — no cap hit here)
//! ```
//!
//! Used by the orchestrator to retry transient Band / LLM
//! failures before escalating to the circuit breaker.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use tokio::time::sleep;

/// Default maximum attempts before giving up.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Default initial delay.
pub const DEFAULT_INITIAL_DELAY: Duration = Duration::from_millis(100);

/// Default multiplier (each attempt doubles the previous).
pub const DEFAULT_MULTIPLIER: f64 = 2.0;

/// Hard cap on a single delay — keeps tail latency bounded even
/// if `max_attempts` is set high.
pub const MAX_DELAY_CAP: Duration = Duration::from_secs(5);

/// Exponential backoff policy.
#[derive(Debug, Clone)]
pub struct BackoffPolicy {
    /// Max attempts (including the first call). Must be `>= 1`.
    pub max_attempts: u32,
    /// Delay before retry attempt `attempt` (0-indexed).
    pub initial_delay: Duration,
    /// Multiplier applied per attempt (e.g. `2.0` for doubling).
    pub multiplier: f64,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            initial_delay: DEFAULT_INITIAL_DELAY,
            multiplier: DEFAULT_MULTIPLIER,
        }
    }
}

impl BackoffPolicy {
    /// Construct with the defaults (5 attempts, 100ms initial, 2× multiplier).
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with a custom max attempts (initial + multiplier stay default).
    pub fn with_max_attempts(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            ..Self::default()
        }
    }

    /// Compute the delay for a given 0-indexed retry attempt.
    ///
    /// `attempt = 0` is the delay AFTER the first failure (before
    /// attempt #2). The result is `initial * multiplier^attempt`,
    /// capped at `MAX_DELAY_CAP`.
    pub fn compute_delay(&self, attempt: u32) -> Duration {
        let factor = self.multiplier.powi(attempt as i32);
        let ms = (self.initial_delay.as_millis() as f64) * factor;
        let capped_ms = ms.min(MAX_DELAY_CAP.as_millis() as f64);
        if capped_ms < 0.0 || !capped_ms.is_finite() {
            return MAX_DELAY_CAP;
        }
        Duration::from_millis(capped_ms as u64)
    }
}

/// Retry an async fallible operation with exponential backoff.
///
/// On `Err`, sleeps `compute_delay(attempt)` and tries again until
/// `max_attempts` is reached. The LAST error is returned on
/// exhaustion.
pub async fn retry_with_backoff<F, Fut, T, E>(policy: &BackoffPolicy, mut f: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: fmt::Debug,
{
    let mut last_err: Option<E> = None;
    for attempt in 0..policy.max_attempts {
        match f().await {
            Ok(value) => return Ok(value),
            Err(e) => {
                if attempt + 1 >= policy.max_attempts {
                    last_err = Some(e);
                    break;
                }
                let delay = policy.compute_delay(attempt);
                last_err = Some(e);
                sleep(delay).await;
            }
        }
    }
    // Exhausted — unwrap the last error.
    Err(last_err.expect("retry_with_backoff: loop body always sets last_err on Err"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn compute_delay_exponential() {
        let p = BackoffPolicy::new();
        assert_eq!(p.compute_delay(0), Duration::from_millis(100));
        assert_eq!(p.compute_delay(1), Duration::from_millis(200));
        assert_eq!(p.compute_delay(2), Duration::from_millis(400));
        assert_eq!(p.compute_delay(3), Duration::from_millis(800));
        assert_eq!(p.compute_delay(4), Duration::from_millis(1600));
    }

    #[tokio::test]
    async fn retry_succeeds_on_second_attempt() {
        let p = BackoffPolicy::new();
        let calls = Arc::new(AtomicU32::new(0));
        let calls_in = Arc::clone(&calls);
        let r: Result<&'static str, &'static str> = retry_with_backoff(&p, || {
            let calls = Arc::clone(&calls_in);
            async move {
                let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 2 {
                    Err("transient")
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
        assert_eq!(r, Ok("ok"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn retry_gives_up_after_max_attempts() {
        let p = BackoffPolicy::with_max_attempts(3);
        let calls = Arc::new(AtomicU32::new(0));
        let calls_in = Arc::clone(&calls);
        let r: Result<(), &'static str> = retry_with_backoff(&p, || {
            let calls = Arc::clone(&calls_in);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err("permafail")
            }
        })
        .await;
        assert_eq!(r, Err("permafail"));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
