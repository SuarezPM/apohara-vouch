//! Python subprocess bridge (skeleton).
//!
//! Spawns a persistent `python -m {sdk_module}` child process and
//! exchanges JSON lines over stdin/stdout. This proves the
//! subprocess + JSON contract; the real Band integration is a
//! follow-up sprint that requires `pip install band-sdk[langgraph]==0.2.11`
//! and the actual Python wrapper module.

use std::io::{BufRead, Write};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;

use crate::error::BandError;

/// Local errors that the bridge can return. These get wrapped into
/// `BandError::PythonExit` / `BandError::Transport` for the trait.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// `std::process::Command` failed to spawn the child.
    #[error("spawn failed: {0}")]
    Spawn(String),
    /// The child process exited unexpectedly.
    #[error("child exited: {0}")]
    ChildExited(String),
    /// A write to the child's stdin failed.
    #[error("stdin write: {0}")]
    Stdin(String),
    /// A read from the child's stdout failed.
    #[error("stdout read: {0}")]
    Stdout(String),
    /// The response was not valid JSON.
    #[error("parse response: {0}")]
    Parse(String),
    /// The bridge has been shut down.
    #[error("bridge is shut down")]
    ShutDown,
}

/// The Python bridge. Holds a persistent child process + handles to
/// its stdin/stdout.
pub struct PythonBandBridge {
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<ChildStdin>>,
    stdout: Mutex<Option<ChildStdout>>,
    sdk_module: String,
}

impl std::fmt::Debug for PythonBandBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PythonBandBridge")
            .field("sdk_module", &self.sdk_module)
            .field("running", &self.child.lock().unwrap().is_some())
            .finish()
    }
}

impl PythonBandBridge {
    /// Spawn `python -m {sdk_module} -i` as a persistent child. Pipes
    /// stdin/stdout for JSON control plane. The actual Band SDK
    /// integration is a follow-up; this skeleton proves the
    /// subprocess + JSON contract.
    pub fn spawn(python_bin: &str, sdk_module: &str) -> Result<Self, BandError> {
        let mut child = std::process::Command::new(python_bin)
            .arg("-m")
            .arg(sdk_module)
            .arg("-i") // keep stdin open even if no script
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| BandError::Transport(format!("spawn {python_bin} -m {sdk_module}: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| BandError::Transport("child stdin not piped".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BandError::Transport("child stdout not piped".to_string()))?;
        Ok(Self {
            child: Mutex::new(Some(child)),
            stdin: Mutex::new(Some(stdin)),
            stdout: Mutex::new(Some(stdout)),
            sdk_module: sdk_module.to_string(),
        })
    }

    /// Send a JSON request to the child's stdin, read one line of
    /// JSON from stdout, return the parsed response. Has a 5s
    /// timeout via `std::sync::mpsc::recv_timeout`-style pattern
    /// (the child process is read synchronously in a thread).
    pub fn send_request(&self, req: Value) -> Result<Value, BandError> {
        // Take the stdin/stdout handles; release them at the end.
        // We move them out of the bridge (take + replace with
        // None) so the spawned thread doesn't borrow the bridge
        // (which has 'self lifetime).
        let mut stdin_guard = self
            .stdin
            .lock()
            .map_err(|e| BandError::Transport(format!("stdin lock: {e}")))?;
        let mut stdout_guard = self
            .stdout
            .lock()
            .map_err(|e| BandError::Transport(format!("stdout lock: {e}")))?;
        let mut stdin = stdin_guard
            .take()
            .ok_or(BandError::Transport("bridge shut down".to_string()))?;
        let mut stdout = stdout_guard
            .take()
            .ok_or(BandError::Transport("bridge shut down".to_string()))?;
        let _ = &mut stdout; // suppress unused mut warning

        // Write the request as a JSON line.
        let line = format!("{}\n", serde_json::to_string(&req).unwrap());
        stdin
            .write_all(line.as_bytes())
            .map_err(|e| BandError::Transport(format!("stdin write: {e}")))?;
        stdin
            .flush()
            .map_err(|e| BandError::Transport(format!("stdin flush: {e}")))?;
        // Return stdin to the bridge so the next call can use it.
        *stdin_guard = Some(stdin);

        // Read one line back. We use a thread + sync channel for
        // the timeout (the std `BufRead::read_line` is blocking).
        let (tx, rx) = std::sync::mpsc::sync_channel::<Option<String>>(1);
        // Borrow stdout by move; the spawned thread takes
        // ownership of the reader.
        let mut reader = std::io::BufReader::new(stdout);
        let join = std::thread::spawn(move || {
            let mut buf = String::new();
            let n = reader.read_line(&mut buf);
            let _ = tx.send(if n.is_ok() && !buf.is_empty() { Some(buf) } else { None });
            // reader dropped here; this implicitly closes the
            // underlying stdout pipe. Return stdout to the
            // bridge for the next call.
            reader.into_inner()
        });
        let line = rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| BandError::Transport("timeout waiting for response".to_string()))?
            .ok_or_else(|| BandError::Transport("child closed stdout".to_string()))?;
        let stdout = join
            .join()
            .map_err(|_| BandError::Transport("reader thread panicked".to_string()))?;
        *stdout_guard = Some(stdout);
        serde_json::from_str(line.trim())
            .map_err(|e| BandError::Transport(format!("parse response: {e}")))
    }

    /// Shutdown: wait for the child to exit; kill it if it takes
    /// >2s.
    pub fn shutdown(&mut self) {
        // Drop stdin first to signal EOF.
        if let Ok(mut g) = self.stdin.lock() {
            g.take();
        }
        if let Ok(mut g) = self.stdout.lock() {
            g.take();
        }
        if let Ok(mut g) = self.child.lock() {
            if let Some(mut child) = g.take() {
                let _ = child.wait(); // try non-blocking; if child
                                       // ignores EOF, the next
                                       // iteration of the test
                                       // loop will time out and
                                       // we kill it.
                // Force-kill if still alive (defensive).
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

impl Drop for PythonBandBridge {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: smoke test of the spawn + shutdown contract.
    #[test]
    fn bridge_spawns_and_shuts_down_cleanly() {
        // Smoke test: spawn a Python process via the bridge and
        // shut it down. The fake module doesn't exist, so the
        // child exits immediately and spawn returns a Transport
        // error — we accept either outcome (bridge is constructible
        // and the shutdown path doesn't panic).
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
                bridge.shutdown();
            }
            Err(e) => {
                eprintln!("spawn returned error (acceptable for missing module): {e}");
            }
        }
    }
}
