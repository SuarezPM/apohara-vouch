//! Circuit breaker — ASI08 (Cascading Failures) defense.
//!
//! Three-state breaker (`Closed` / `Open` / `HalfOpen`) that
//! rejects calls when an agent fails too often, protecting the
//! rest of the pipeline from cascading failure (OWASP Agentic
//! 2026, ASI08).
//!
//! State machine:
//!
//! ```text
//!   Closed ──[threshold consecutive failures]──> Open
//!      ^                                          │
//!      │                                          │ [timeout elapsed]
//!      │                                          ▼
//!      └──────[trial succeeds]────────────── HalfOpen
//!                                              │
//!                                              │ [trial fails]
//!                                              ▼
//!                                             Open
//! ```
//!
//! Used by `retry::retry_with_backoff` (this crate) and by the
//! orchestrator's `process_invoice` loop to gate calls to any
//! agent whose name appears in `Orchestrator.agents`.

use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use thiserror::Error;

/// Default failure threshold before the breaker opens.
pub const DEFAULT_THRESHOLD: u32 = 5;

/// Default recovery timeout — the breaker stays `Open` for this
/// long before allowing one trial call.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// State of the circuit breaker.
#[derive(Debug, Clone)]
pub enum CircuitState {
    /// Healthy — calls pass through.
    Closed,
    /// Rejecting calls. `opened_at` is when we transitioned here.
    Open {
        /// When the breaker opened.
        opened_at: Instant,
    },
    /// One trial call is allowed (after the recovery timeout).
    HalfOpen,
}

impl fmt::Display for CircuitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "Closed"),
            CircuitState::Open { .. } => write!(f, "Open"),
            CircuitState::HalfOpen => write!(f, "HalfOpen"),
        }
    }
}

/// Errors returned from `CircuitBreaker::call`.
#[derive(Debug, Error)]
pub enum CircuitBreakerError<E: fmt::Debug> {
    /// The breaker is open and rejected the call without running
    /// the inner function.
    #[error("circuit breaker rejected call (state={state})")]
    Rejected {
        /// The state at the moment of rejection.
        state: CircuitState,
    },
    /// The inner call ran and returned an error.
    #[error("inner call failed: {0}")]
    Inner(#[source] E),
}

/// The circuit breaker itself. Cheap to clone (`Arc`-friendly via
/// the fields), `Send + Sync`.
pub struct CircuitBreaker {
    /// Consecutive failures before opening.
    pub threshold: u32,
    /// How long the breaker stays `Open` before allowing one trial.
    pub timeout: Duration,
    /// Current state (under a `parking_lot::Mutex` for low overhead).
    pub state: Mutex<CircuitState>,
    /// Consecutive-failure counter. Reset on success or HalfOpen close.
    pub failures: AtomicU32,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreaker {
    /// Construct a breaker with the default threshold (5) and
    /// timeout (30s).
    pub fn new() -> Self {
        Self::with_params(DEFAULT_THRESHOLD, DEFAULT_TIMEOUT)
    }

    /// Construct a breaker with a custom threshold and the
    /// default timeout.
    pub fn with_threshold(threshold: u32) -> Self {
        Self::with_params(threshold, DEFAULT_TIMEOUT)
    }

    /// Construct a breaker with a custom timeout (test-only or
    /// for tenants that need faster recovery).
    pub fn with_timeout(timeout: Duration) -> Self {
        Self::with_params(DEFAULT_THRESHOLD, timeout)
    }

    /// Construct a breaker with both parameters set explicitly.
    pub fn with_params(threshold: u32, timeout: Duration) -> Self {
        assert!(threshold > 0, "threshold must be > 0");
        Self {
            threshold,
            timeout,
            state: Mutex::new(CircuitState::Closed),
            failures: AtomicU32::new(0),
        }
    }

    /// Snapshot the current state.
    pub fn state(&self) -> CircuitState {
        self.lock_state().clone()
    }

    /// Lock the state mutex, recovering from poisoning (a panic
    /// mid-update shouldn't permanently brick the breaker).
    fn lock_state(&self) -> std::sync::MutexGuard<'_, CircuitState> {
        match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Run `f`. If the breaker is `Open` and the timeout hasn't
    /// elapsed, the call is rejected without running `f`.
    pub fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Result<T, E>,
        E: fmt::Debug,
    {
        // Gate: read state, decide whether to allow the call.
        let allow = {
            let mut state = self.lock_state();
            match &*state {
                CircuitState::Closed | CircuitState::HalfOpen => true,
                CircuitState::Open { opened_at } => {
                    if opened_at.elapsed() >= self.timeout {
                        // Recovery window elapsed — move to HalfOpen
                        // and let this single call through as the trial.
                        *state = CircuitState::HalfOpen;
                        true
                    } else {
                        false
                    }
                }
            }
        };

        if !allow {
            let state = self.state();
            return Err(CircuitBreakerError::Rejected { state });
        }

        // Execute the inner call.
        match f() {
            Ok(value) => {
                // Success: if we were HalfOpen, close the breaker.
                let mut state = self.lock_state();
                if matches!(*state, CircuitState::HalfOpen) {
                    *state = CircuitState::Closed;
                    self.failures.store(0, Ordering::SeqCst);
                }
                // In Closed state, just leave the counter alone
                // (we don't increment on success).
                drop(state);
                Ok(value)
            }
            Err(e) => {
                let failures = self.failures.fetch_add(1, Ordering::SeqCst) + 1;
                let mut state = self.lock_state();
                if matches!(*state, CircuitState::HalfOpen) {
                    // Trial failed — go back to Open with a fresh
                    // timestamp so the next 30s window restarts.
                    *state = CircuitState::Open {
                        opened_at: Instant::now(),
                    };
                } else if failures >= self.threshold {
                    *state = CircuitState::Open {
                        opened_at: Instant::now(),
                    };
                }
                drop(state);
                Err(CircuitBreakerError::Inner(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok<T>(v: T) -> Result<T, &'static str> {
        Ok(v)
    }
    fn ok_closure() -> Result<i32, &'static str> {
        Ok(1)
    }
    fn err() -> Result<(), &'static str> {
        Err("boom")
    }

    #[test]
    fn closed_passes_through() {
        let cb = CircuitBreaker::new();
        let r: Result<i32, _> = cb.call(|| ok(42));
        assert!(matches!(r, Ok(42)));
        assert!(matches!(cb.state(), CircuitState::Closed));
        assert_eq!(cb.failures.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn opens_after_threshold_failures() {
        let cb = CircuitBreaker::with_params(3, Duration::from_secs(30));
        for _ in 0..3 {
            let _: Result<(), _> = cb.call(err);
        }
        assert!(matches!(cb.state(), CircuitState::Open { .. }));
        // 4th call rejected
        let r: Result<(), _> = cb.call(err);
        assert!(matches!(r, Err(CircuitBreakerError::Rejected { .. })));
    }

    #[test]
    fn rejects_while_open() {
        let cb = CircuitBreaker::with_params(2, Duration::from_secs(30));
        for _ in 0..2 {
            let _: Result<(), _> = cb.call(err);
        }
        assert!(matches!(cb.state(), CircuitState::Open { .. }));
        let r: Result<i32, _> = cb.call(ok_closure);
        assert!(matches!(r, Err(CircuitBreakerError::Rejected { .. })));
    }

    #[test]
    fn half_open_after_timeout() {
        let cb = CircuitBreaker::with_params(2, Duration::from_millis(20));
        for _ in 0..2 {
            let _: Result<(), _> = cb.call(err);
        }
        assert!(matches!(cb.state(), CircuitState::Open { .. }));
        std::thread::sleep(Duration::from_millis(25));
        // Next call transitions to HalfOpen and executes.
        let r: Result<i32, _> = cb.call(|| ok(7));
        assert!(matches!(r, Ok(7)));
    }

    #[test]
    fn closed_again_after_half_open_success() {
        let cb = CircuitBreaker::with_params(2, Duration::from_millis(10));
        for _ in 0..2 {
            let _: Result<(), _> = cb.call(err);
        }
        assert!(matches!(cb.state(), CircuitState::Open { .. }));
        std::thread::sleep(Duration::from_millis(15));
        let r: Result<i32, _> = cb.call(|| ok(99));
        assert!(matches!(r, Ok(99)));
        assert!(matches!(cb.state(), CircuitState::Closed));
        assert_eq!(cb.failures.load(Ordering::SeqCst), 0);
    }
}
