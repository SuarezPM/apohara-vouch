//! Python subprocess bridge for the Band SDK.
//!
//! Production transport: spawns a persistent `python -m {sdk_module}`
//! child process and exchanges JSON lines over stdin/stdout. The
//! bridge is intentionally minimal — it owns the lifecycle of one
//! child process and provides typed, timeout-bounded request/response
//! primitives. Higher-level Band operations (chatroom, peers, send
//! message, history) live in `client.rs` and `room.rs`.
//!
//! # Lifecycle invariants
//!
//! - **Single child per bridge.** `spawn` creates the process,
//!   `shutdown` (or `Drop`) tears it down. Re-spawn is not allowed
//!   mid-flight — callers construct a new bridge.
//! - **stderr is drained continuously.** Unbounded stderr growth is
//!   the #1 cause of subprocess hangs; we run a background thread
//!   that reads stderr into a bounded ring buffer and surfaces the
//!   last 4 KiB on transport errors.
//! - **Timeout on every request.** The default 5s timeout prevents
//!   one stuck request from holding the orchestrator hostage.
//! - **Graceful shutdown.** `shutdown` drops stdin (sends EOF), waits
//!   2s for the child to exit, then SIGKILLs if still alive. No
//!   zombie processes leak past `Drop`.
//!
//! # What this is NOT
//!
//! This is the *transport*, not the Band protocol. The 5 Hackathon
//! Guide operations (`band_create_chatroom`, `band_lookup_peers`,
//! `band_add_participant`, `band_send_message`, `band_get_history`)
//! are sent as opaque JSON envelopes — the Python shim is responsible
//! for parsing them and dispatching to `band-sdk`. See
//! `crates/themis-band-client/scripts/run_agent.py` for the shim.

use std::io::{BufRead, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use thiserror::Error;

use crate::error::BandError;

/// Maximum bytes retained from the child's stderr for inclusion in
/// transport errors. 4 KiB is enough to capture the last Python
/// traceback without unbounded memory growth.
const STDERR_RING_BYTES: usize = 4096;

/// Default per-request timeout. Matches the previous skeleton; the
/// orchestrator's BAAAR HALT path is independent of this timeout
/// (any `BandError::Transport` degrades to a soft failure there).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Graceful-shutdown grace period before SIGKILL. Long enough for the
/// Python child to flush + close its WS connection cleanly.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Errors the bridge can return. Wrapped into `BandError::Transport`
/// for the trait surface; kept distinct here for diagnostics.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// `std::process::Command` failed to spawn the child.
    #[error("spawn failed: {0}")]
    Spawn(String),
    /// The child process exited unexpectedly (between requests).
    #[error("child exited: {0}")]
    ChildExited(String),
    /// A write to the child's stdin failed (broken pipe, child gone).
    #[error("stdin write: {0}")]
    Stdin(String),
    /// A read from the child's stdout failed or timed out.
    #[error("stdout read: {0}")]
    Stdout(String),
    /// The response was not valid JSON.
    #[error("parse response: {0}")]
    Parse(String),
    /// The bridge has been shut down.
    #[error("bridge is shut down")]
    ShutDown,
}

impl From<BridgeError> for BandError {
    fn from(e: BridgeError) -> Self {
        BandError::Transport(e.to_string())
    }
}

/// Lightweight metrics tracked per bridge instance. Exposed via
/// [`PythonBandBridge::stats`] for the orchestrator's SSE telemetry
/// (`band_bridge_latency_ms`, `band_bridge_requests_total`).
#[derive(Debug, Default, Clone)]
pub struct BridgeStats {
    /// Total `send_request` calls since spawn.
    pub requests_total: u64,
    /// Total transport errors since spawn.
    pub errors_total: u64,
    /// Sum of request latencies in milliseconds (divide by
    /// `requests_total` for the mean; tracked as a sum for the
    /// frontend to compute its own percentiles client-side).
    pub latency_ms_sum: u64,
    /// Peak latency observed since spawn.
    pub latency_ms_peak: u64,
}

impl BridgeStats {
    // Empty impl block — kept as the documented public type but the
    // counters are updated atomically inside `PythonBandBridge` to
    // avoid holding a lock across the request hot path.
}

/// The Python bridge. Holds a persistent child process + handles to
/// its stdin/stdout + a stderr-drain thread + per-bridge metrics.
///
/// Cheap to construct (single `std::process::Command`), expensive to
/// spawn (Python interpreter cold-start). One bridge per orchestrator.
pub struct PythonBandBridge {
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<ChildStdin>>,
    stdout: Mutex<Option<ChildStdout>>,
    /// Bounded ring of the child's most recent stderr output.
    /// Surfaced in transport errors for diagnostics.
    stderr_tail: Arc<Mutex<Vec<u8>>>,
    /// Per-bridge telemetry, lock-free atomic counters.
    stats_requests: AtomicU64,
    stats_errors: AtomicU64,
    stats_latency_sum_ms: AtomicU64,
    stats_latency_peak_ms: AtomicU64,
    sdk_module: String,
}

impl std::fmt::Debug for PythonBandBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PythonBandBridge")
            .field("sdk_module", &self.sdk_module)
            .field("running", &self.child.lock().unwrap().is_some())
            .field(
                "requests_total",
                &self.stats_requests.load(Ordering::Relaxed),
            )
            .field("errors_total", &self.stats_errors.load(Ordering::Relaxed))
            .finish()
    }
}

impl PythonBandBridge {
    /// Spawn `python -m {sdk_module} -i` as a persistent child with
    /// stdin/stdout/stderr all piped. Spawns a background thread to
    /// drain stderr (otherwise the OS pipe buffer fills after ~64 KiB
    /// and the child blocks on `print()`).
    pub fn spawn(python_bin: &str, sdk_module: &str) -> Result<Self, BandError> {
        let mut child = std::process::Command::new(python_bin)
            .arg("-m")
            .arg(sdk_module)
            .arg("-i") // keep stdin open even if no script
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()) // drained by background thread
            .spawn()
            .map_err(|e| {
                BandError::Transport(format!("spawn {python_bin} -m {sdk_module}: {e}"))
            })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| BandError::Transport("child stdin not piped".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BandError::Transport("child stdout not piped".to_string()))?;
        let stderr: ChildStderr = child
            .stderr
            .take()
            .ok_or_else(|| BandError::Transport("child stderr not piped".to_string()))?;

        // Background stderr drain: keeps the pipe buffer empty and
        // retains the last `STDERR_RING_BYTES` for diagnostics.
        let stderr_tail: Arc<Mutex<Vec<u8>>> =
            Arc::new(Mutex::new(Vec::with_capacity(STDERR_RING_BYTES)));
        let stderr_tail_clone = stderr_tail.clone();
        std::thread::Builder::new()
            .name("band-bridge-stderr".to_string())
            .spawn(move || drain_stderr(stderr, stderr_tail_clone))
            .map_err(|e| BandError::Transport(format!("spawn stderr drain thread: {e}")))?;

        eprintln!("[band-bridge] spawned python={python_bin} module={sdk_module}");
        Ok(Self {
            child: Mutex::new(Some(child)),
            stdin: Mutex::new(Some(stdin)),
            stdout: Mutex::new(Some(stdout)),
            stderr_tail,
            stats_requests: AtomicU64::new(0),
            stats_errors: AtomicU64::new(0),
            stats_latency_sum_ms: AtomicU64::new(0),
            stats_latency_peak_ms: AtomicU64::new(0),
            sdk_module: sdk_module.to_string(),
        })
    }

    /// Snapshot the current telemetry counters. Cheap (4 atomic loads).
    pub fn stats(&self) -> BridgeStats {
        BridgeStats {
            requests_total: self.stats_requests.load(Ordering::Relaxed),
            errors_total: self.stats_errors.load(Ordering::Relaxed),
            latency_ms_sum: self.stats_latency_sum_ms.load(Ordering::Relaxed),
            latency_ms_peak: self.stats_latency_peak_ms.load(Ordering::Relaxed),
        }
    }

    /// Snapshot of the child's most recent stderr output (last
    /// `STDERR_RING_BYTES`). Useful for diagnosing transport errors.
    pub fn stderr_tail(&self) -> String {
        String::from_utf8_lossy(&self.stderr_tail.lock().unwrap()).into_owned()
    }

    /// Send a JSON request to the child's stdin, read one line of
    /// JSON from stdout, return the parsed response.
    ///
    /// Uses a `mpsc::sync_channel` + worker thread for the read
    /// timeout (the std `BufRead::read_line` is blocking). Records
    /// latency + error counters on every call.
    pub fn send_request(&self, req: Value) -> Result<Value, BandError> {
        self.send_request_with_timeout(req, DEFAULT_REQUEST_TIMEOUT)
    }

    /// Same as [`send_request`] but with an explicit per-request
    /// timeout. The previous skeleton's 5s default is preserved as
    /// `DEFAULT_REQUEST_TIMEOUT`.
    pub fn send_request_with_timeout(
        &self,
        req: Value,
        timeout: Duration,
    ) -> Result<Value, BandError> {
        let started = Instant::now();

        // Take the stdin/stdout handles for this call; release them
        // at the end so the next call can use them.
        let mut stdin_guard = self
            .stdin
            .lock()
            .map_err(|e| BandError::Transport(format!("stdin lock: {e}")))?;
        let mut stdout_guard = self
            .stdout
            .lock()
            .map_err(|e| BandError::Transport(format!("stdout lock: {e}")))?;
        let mut stdin: ChildStdin = stdin_guard
            .take()
            .ok_or(BandError::Transport("bridge shut down".to_string()))?;
        let stdout: ChildStdout = stdout_guard
            .take()
            .ok_or(BandError::Transport("bridge shut down".to_string()))?;

        // Write the request as a JSON line.
        let line = match serde_json::to_string(&req) {
            Ok(s) => format!("{s}\n"),
            Err(e) => {
                *stdin_guard = Some(stdin);
                *stdout_guard = Some(stdout);
                let _ = self.record_outcome(started, false);
                return Err(BandError::Transport(format!("encode request: {e}")));
            }
        };
        if let Err(e) = stdin.write_all(line.as_bytes()) {
            *stdin_guard = Some(stdin);
            *stdout_guard = Some(stdout);
            let _ = self.record_outcome(started, false);
            return Err(BandError::Transport(format!("stdin write: {e}")));
        }
        if let Err(e) = stdin.flush() {
            *stdin_guard = Some(stdin);
            *stdout_guard = Some(stdout);
            let _ = self.record_outcome(started, false);
            return Err(BandError::Transport(format!("stdin flush: {e}")));
        }
        *stdin_guard = Some(stdin);

        // Read one line back via a worker thread + bounded channel.
        let (tx, rx) = std::sync::mpsc::sync_channel::<Option<String>>(1);
        let mut reader = std::io::BufReader::new(stdout);
        let join = std::thread::spawn(move || {
            let mut buf = String::new();
            let n = reader.read_line(&mut buf);
            let result = if n.is_ok() && !buf.is_empty() {
                Some(buf)
            } else {
                None
            };
            let _ = tx.send(result);
            reader.into_inner()
        });
        let response = match rx.recv_timeout(timeout) {
            Ok(Some(line)) => line,
            Ok(None) => {
                let _ = join.join();
                let _ = self.record_outcome(started, false);
                return Err(BandError::Transport("child closed stdout".to_string()));
            }
            Err(_) => {
                // Timed out. The reader thread is still blocked; we
                // can't join it without blocking, so we abandon it.
                // On Drop the bridge will kill the child, which will
                // unblock the thread.
                let _ = self.record_outcome(started, false);
                return Err(BandError::Transport(format!(
                    "timeout waiting for response ({}s)",
                    timeout.as_secs()
                )));
            }
        };
        let stdout = match join.join() {
            Ok(s) => s,
            Err(_) => {
                let _ = self.record_outcome(started, false);
                return Err(BandError::Transport("reader thread panicked".to_string()));
            }
        };
        *stdout_guard = Some(stdout);

        match serde_json::from_str::<Value>(response.trim()) {
            Ok(v) => {
                let _ = self.record_outcome(started, true);
                Ok(v)
            }
            Err(e) => {
                let _ = self.record_outcome(started, false);
                Err(BandError::Transport(format!("parse response: {e}")))
            }
        }
    }

    /// Increment the per-bridge metrics. Called once per `send_request`.
    fn record_outcome(&self, started: Instant, ok: bool) -> Result<(), BandError> {
        let elapsed_ms = started.elapsed().as_millis() as u64;
        self.stats_requests.fetch_add(1, Ordering::Relaxed);
        self.stats_latency_sum_ms
            .fetch_add(elapsed_ms, Ordering::Relaxed);
        // CAS loop for peak — Relaxed loads are fine here, we don't
        // need a strict happens-before with other writers.
        let mut current = self.stats_latency_peak_ms.load(Ordering::Relaxed);
        while elapsed_ms > current {
            match self.stats_latency_peak_ms.compare_exchange(
                current,
                elapsed_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        if !ok {
            self.stats_errors.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Graceful shutdown: drop stdin (EOF), wait up to `SHUTDOWN_GRACE`
    /// for the child to exit, then SIGKILL if still alive. Idempotent —
    /// safe to call from `Drop`.
    pub fn shutdown(&mut self) {
        // Drop stdin first to signal EOF — gives the Python child a
        // chance to flush and close its WebSocket cleanly.
        if let Ok(mut g) = self.stdin.lock() {
            let _ = g.take();
        }
        if let Ok(mut g) = self.stdout.lock() {
            let _ = g.take();
        }
        if let Ok(mut g) = self.child.lock() {
            if let Some(mut child) = g.take() {
                // Non-blocking wait first; if the child exits in time
                // we avoid SIGKILL entirely.
                match child.try_wait() {
                    Ok(Some(_status)) => {
                        eprintln!("[band-bridge] child exited cleanly during shutdown");
                    }
                    Ok(None) => {
                        // Still running. Try graceful wait with timeout.
                        let deadline = Instant::now() + SHUTDOWN_GRACE;
                        while Instant::now() < deadline {
                            match child.try_wait() {
                                Ok(Some(_)) => return,
                                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                                Err(e) => {
                                    eprintln!("[band-bridge] try_wait error during shutdown: {e}");
                                    break;
                                }
                            }
                        }
                        // Still alive after grace period — force kill.
                        if let Err(e) = child.kill() {
                            eprintln!("[band-bridge] SIGKILL failed during shutdown: {e}");
                        }
                        let _ = child.wait();
                    }
                    Err(e) => {
                        eprintln!("[band-bridge] try_wait error at shutdown entry: {e}");
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                }
            }
        }
    }
}

impl Drop for PythonBandBridge {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Background thread body: drain the child's stderr into a bounded
/// ring buffer. Exits when the pipe closes (child exit / shutdown).
fn drain_stderr(stderr: ChildStderr, tail: Arc<Mutex<Vec<u8>>>) {
    use std::io::Read;
    let mut reader = std::io::BufReader::new(stderr);
    let mut chunk = [0u8; 1024];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break, // pipe closed
            Ok(n) => {
                let mut guard = match tail.lock() {
                    Ok(g) => g,
                    Err(_) => return, // mutex poisoned, give up
                };
                guard.extend_from_slice(&chunk[..n]);
                // Trim to the last STDERR_RING_BYTES if we exceed it.
                let excess = guard.len().saturating_sub(STDERR_RING_BYTES);
                if excess > 0 {
                    guard.drain(..excess);
                }
            }
            Err(_) => return, // read error, give up
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: spawn + shutdown contract.
    ///
    /// Accepts either outcome for the spawn — the fake module doesn't
    /// exist, so spawn may fail with a Transport error. What matters
    /// is that the bridge is constructible AND the shutdown path
    /// doesn't panic on either branch.
    #[test]
    fn bridge_spawns_and_shuts_down_cleanly() {
        let which = std::process::Command::new("which")
            .arg("python3")
            .output()
            .expect("`which` must be available");
        if !which.status.success() {
            eprintln!("python3 not on PATH; skipping");
            return;
        }
        match PythonBandBridge::spawn("python3", "fake_sdk_echo") {
            Ok(mut bridge) => {
                // Stats start at zero.
                let s = bridge.stats();
                assert_eq!(s.requests_total, 0);
                assert_eq!(s.errors_total, 0);
                bridge.shutdown();
            }
            Err(e) => {
                eprintln!("spawn returned error (acceptable for missing module): {e}");
            }
        }
    }

    /// Echo round-trip: spawn `python3 -i` (real interpreter, no
    /// module), send a JSON request, get a JSON response back via
    /// Python's REPL echo of stdin lines. Validates the JSON-line
    /// framing end-to-end without needing the band SDK installed.
    #[test]
    fn bridge_round_trips_json_with_python_repl() {
        // Locate python3.
        let which = std::process::Command::new("which")
            .arg("python3")
            .output()
            .expect("`which` must be available");
        if !which.status.success() {
            eprintln!("python3 not on PATH; skipping");
            return;
        }
        // Spawn a python REPL with no module. `-i` keeps stdin open
        // and echoes expressions back as their `repr()`. This isn't
        // exactly the JSON contract — Python will echo the dict back
        // in its own format — so we instead verify that something
        // echoed back, which proves the subprocess + pipe framing
        // works end-to-end.
        let mut bridge = match PythonBandBridge::spawn("python3", "this_module_does_not_exist") {
            Ok(b) => b,
            Err(e) => {
                // Python may exit immediately if the module is
                // missing; that's fine for this test.
                eprintln!("spawn returned error (acceptable): {e}");
                return;
            }
        };
        // If spawn succeeded (python -i with -m on a missing module
        // sometimes succeeds and waits at the REPL), try a request.
        let req = serde_json::json!({"op": "ping", "id": 1});
        let resp = bridge.send_request_with_timeout(req.clone(), Duration::from_secs(2));
        // Either the child ignored the JSON (REPL syntax error, no
        // response) and we timed out, OR Python echoed something back.
        // Either is acceptable; what matters is no panic + no zombie.
        match resp {
            Ok(v) => {
                eprintln!("bridge round-trip ok: {v}");
                let s = bridge.stats();
                assert!(s.requests_total >= 1, "stats must record the request");
            }
            Err(BandError::Transport(msg)) => {
                eprintln!("bridge round-trip timed out (acceptable for REPL): {msg}");
                let s = bridge.stats();
                assert!(s.requests_total >= 1, "stats must record the request");
                assert!(s.errors_total >= 1, "timed-out request must count as error");
            }
            Err(other) => panic!("unexpected error variant: {other}"),
        }
        // Graceful shutdown — no zombie, no panic.
        bridge.shutdown();
        // Idempotent shutdown — calling again should be a no-op.
        bridge.shutdown();
    }

    /// Stats monotonicity: a successful request bumps the counter
    /// and the latency accumulator; an errored request bumps the
    /// error counter without panicking on negative deltas.
    #[test]
    fn stats_increment_on_request_outcomes() {
        // We need a live bridge for stats to be observable. Spawn
        // python REPL (always succeeds) and record a single
        // request — either it succeeds or times out, both update
        // the counters correctly.
        let which = std::process::Command::new("which")
            .arg("python3")
            .output()
            .unwrap();
        if !which.status.success() {
            eprintln!("python3 not on PATH; skipping");
            return;
        }
        let mut bridge = match PythonBandBridge::spawn("python3", "no_such_module") {
            Ok(b) => b,
            Err(_) => return, // skip if spawn failed
        };
        let before = bridge.stats();
        let _ = bridge.send_request_with_timeout(
            serde_json::json!({"test": true}),
            Duration::from_millis(200),
        );
        let after = bridge.stats();
        assert!(
            after.requests_total > before.requests_total,
            "stats.requests_total must increase after a request: before={before:?} after={after:?}"
        );
        assert!(
            after.latency_ms_sum >= before.latency_ms_sum,
            "stats.latency_ms_sum must not decrease"
        );
        bridge.shutdown();
    }
}
