//! Per-agent WebSocket connection to `wss://app.band.ai/api/v1/socket/websocket`.
//!
//! One subprocess per agent (extractor, po_matcher, fraud_auditor,
//! gaap_classifier, provenance_signer, demo_narrator). The subprocess
//! is a thin Python shim (`bin/run_agent.py`) that uses
//! `band-sdk[langgraph]==0.2.11` to maintain a long-lived Phoenix
//! Channels WebSocket connection.
//!
//! The Rust side never touches the wire directly — it spawns the
//! subprocess, pipes JSON control messages on stdin, and reads JSON
//! events on stdout. This keeps the persistent-connection logic
//! (reconnect, heartbeat, join_room) in the official Python SDK
//! where the Band team maintains it, while the Rust orchestrator
//! stays hermetic.

use std::io::{BufRead, Write};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::types::{AgentId, RoomId};

/// Default WebSocket endpoint. The Band Phoenix Channels server lives
/// behind a TLS-terminating proxy at `app.band.ai`.
pub const BAND_WS_URL: &str = "wss://app.band.ai/api/v1/socket/websocket";

/// Errors from the per-agent WebSocket bridge.
#[derive(Debug, Error)]
pub enum SocketError {
    /// Spawning the Python shim failed.
    #[error("spawn run_agent.py: {0}")]
    Spawn(String),
    /// The shim exited unexpectedly.
    #[error("shim exited: {0}")]
    ShimExit(String),
    /// Stdout was not piped (configuration error).
    #[error("shim stdout not piped")]
    NoStdout,
    /// Stdin was not piped (configuration error).
    #[error("shim stdin not piped")]
    NoStdin,
    /// A JSON control message could not be parsed.
    #[error("parse control: {0}")]
    Parse(String),
    /// A write to the shim's stdin failed.
    #[error("stdin write: {0}")]
    Stdin(String),
    /// The shim reported an error on stderr or as an event.
    #[error("shim error: {0}")]
    ShimError(String),
    /// The join_room request did not succeed within the timeout.
    #[error("join_room timed out after {0}s")]
    JoinTimeout(u64),
    /// The bridge has been shut down.
    #[error("socket shut down")]
    ShutDown,
}

/// Result of an attempt to join a Band room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    /// The room id we joined.
    pub room_id: String,
    /// The Band-assigned chatroom slug (public URL-safe id).
    pub chatroom_slug: String,
    /// Public URL of the chat room on `app.band.ai`.
    pub public_url: String,
    /// Wall-clock ms the join completed.
    pub joined_at_ms: i64,
}

/// An event received from the WebSocket (after the Python shim
/// re-serialized it as JSON on stdout).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandSocketEvent {
    /// The Phoenix Channels event name.
    pub event: String,
    /// The event payload, exactly as the shim decoded it from JSON.
    pub payload: serde_json::Value,
    /// Wall-clock ms the event was observed (shim-side, for the
    /// transcript timeline).
    #[serde(default)]
    pub ts_ms: i64,
    /// Agent id this event belongs to.
    #[serde(default)]
    pub agent_id: String,
}

/// Handle to a single agent's subprocess bridge. Owns the child PID,
/// stdin/stdout pipes, and an async task that forwards events to an
/// `mpsc::Receiver` the orchestrator can poll.
pub struct SocketHandle {
    /// Band agent id (UUID). One handle per agent.
    pub agent_id: AgentId,
    /// Band room id (UUID).
    pub room_id: RoomId,
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<ChildStdin>>,
    rx: mpsc::Receiver<BandSocketEvent>,
    /// Pending request/reply correlation: the stdout thread polls
    /// this for outstanding `phx_reply` requests and sends the
    /// matching payload through the `SyncSender`.
    pending_requests: Arc<Mutex<Vec<PendingRequest>>>,
    /// Number of WebSocket events this handle has observed.
    events_observed: Arc<std::sync::atomic::AtomicU64>,
}

/// An outstanding request awaiting its `phx_reply` from the shim.
struct PendingRequest {
    /// Monotonic ref id we sent on stdin; the shim echoes it back.
    ref_id: u64,
    /// Sink for the matched reply payload. `SyncSender` (bound 1).
    reply: std::sync::mpsc::SyncSender<serde_json::Value>,
}

impl std::fmt::Debug for PendingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRequest")
            .field("ref_id", &self.ref_id)
            .finish()
    }
}

impl std::fmt::Debug for SocketHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketHandle")
            .field("agent_id", &self.agent_id)
            .field("room_id", &self.room_id)
            .finish()
    }
}

impl SocketHandle {
    /// Spawn the Python shim and connect to the Band WebSocket for
    /// the given agent.
    pub fn spawn(
        python_bin: &str,
        shim_path: &str,
        agent_id: &str,
        api_key: &str,
        room_id: &str,
        ws_url: &str,
    ) -> Result<Self, SocketError> {
        let mut child = std::process::Command::new(python_bin)
            .arg(shim_path)
            .arg("--agent-id")
            .arg(agent_id)
            .arg("--api-key")
            .arg(api_key)
            .arg("--room-id")
            .arg(room_id)
            .arg("--ws-url")
            .arg(ws_url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SocketError::Spawn(format!("{python_bin} {shim_path}: {e}")))?;
        let stdin = child.stdin.take().ok_or(SocketError::NoStdin)?;
        let stdout = child.stdout.take().ok_or(SocketError::NoStdout)?;
        let (tx, rx) = mpsc::channel(256);
        let events_observed = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let pending_requests: Arc<Mutex<Vec<PendingRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let events_observed_reader = events_observed.clone();
        let pending_reader = pending_requests.clone();
        // Drain stdout in a dedicated OS thread (synchronous read).
        std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                if line.is_empty() {
                    continue;
                }
                let ev: BandSocketEvent = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                events_observed_reader.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Correlate phx_reply with the matching pending request.
                if ev.event == "phx_reply" {
                    let reply_ref = ev.payload.get("ref").and_then(|r| r.as_u64()).or_else(|| {
                        ev.payload
                            .get("ref")
                            .and_then(|r| r.as_str())
                            .and_then(|s| s.parse::<u64>().ok())
                    });
                    if let Some(r) = reply_ref {
                        let pending = pending_reader.lock().ok().and_then(|mut g| {
                            let pos = g.iter().position(|p| p.ref_id == r);
                            pos.map(|i| g.swap_remove(i))
                        });
                        if let Some(req) = pending {
                            let _ = req.reply.send(ev.payload.clone());
                            continue;
                        }
                    }
                }
                if tx.blocking_send(ev).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            agent_id: AgentId::new(agent_id.to_string()),
            room_id: RoomId::new(room_id.to_string()),
            child: Mutex::new(Some(child)),
            stdin: Mutex::new(Some(stdin)),
            rx,
            pending_requests,
            events_observed,
        })
    }

    /// Send a `post_message` request and wait for the `phx_reply`.
    pub async fn post_message(&mut self, body: &str) -> Result<String, SocketError> {
        let req = serde_json::json!({
            "op": "post_message",
            "body": body,
        });
        let resp = self.send_request(&req).await?;
        Ok(resp
            .get("message_id")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string())
    }

    /// Send a `join_room` request (the shim already joined at
    /// spawn; this is for completeness).
    pub async fn join_room(&mut self, room_id: &str) -> Result<JoinResponse, SocketError> {
        let req = serde_json::json!({
            "op": "join_room",
            "room_id": room_id,
        });
        let resp = tokio::task::block_in_place(|| self.send_request_raw_blocking(&req, 30))?;
        let join: JoinResponse = serde_json::from_value(resp)
            .map_err(|e| SocketError::Parse(format!("join_room: {e}")))?;
        Ok(join)
    }

    /// Receive the next event from the WebSocket.
    pub async fn recv_event(&mut self) -> Option<BandSocketEvent> {
        self.rx.recv().await
    }

    /// How many WebSocket events this handle has observed.
    pub fn events_observed(&self) -> u64 {
        self.events_observed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Send a JSON control request and wait for the matching
    /// `phx_reply`. Blocking; intended to be wrapped in
    /// `tokio::task::block_in_place`.
    fn send_request_raw_blocking(
        &mut self,
        req: &serde_json::Value,
        timeout_secs: u64,
    ) -> Result<serde_json::Value, SocketError> {
        let ref_id: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut req = req.clone();
        if let Some(obj) = req.as_object_mut() {
            obj.insert("ref".to_string(), serde_json::json!(ref_id));
        } else {
            return Err(SocketError::Stdin(
                "send_request: req must be a JSON object".to_string(),
            ));
        }
        let (tx, rx) = std::sync::mpsc::sync_channel::<serde_json::Value>(1);
        // Register BEFORE writing to stdin so a fast reply can't race us.
        {
            let mut g = self
                .pending_requests
                .lock()
                .map_err(|e| SocketError::ShimError(format!("pending lock: {e}")))?;
            g.push(PendingRequest { ref_id, reply: tx });
        }
        {
            let mut stdin_guard = self
                .stdin
                .lock()
                .map_err(|e| SocketError::Stdin(format!("lock: {e}")))?;
            let mut stdin = stdin_guard.take().ok_or(SocketError::ShutDown)?;
            let line = format!("{}\n", serde_json::to_string(&req).unwrap_or_default());
            stdin
                .write_all(line.as_bytes())
                .map_err(|e| SocketError::Stdin(e.to_string()))?;
            stdin
                .flush()
                .map_err(|e| SocketError::Stdin(format!("flush: {e}")))?;
            *stdin_guard = Some(stdin);
        }
        match rx.recv_timeout(Duration::from_secs(timeout_secs)) {
            Ok(v) => {
                if let Ok(mut g) = self.pending_requests.lock() {
                    g.retain(|p| p.ref_id != ref_id);
                }
                Ok(v)
            }
            Err(_) => {
                if let Ok(mut g) = self.pending_requests.lock() {
                    g.retain(|p| p.ref_id != ref_id);
                }
                Err(SocketError::JoinTimeout(timeout_secs))
            }
        }
    }

    /// Convenience wrapper for `post_message`.
    pub async fn send_request(
        &mut self,
        req: &serde_json::Value,
    ) -> Result<serde_json::Value, SocketError> {
        let resp = tokio::task::block_in_place(|| self.send_request_raw_blocking(req, 10))?;
        let status = resp.get("status").and_then(|s| s.as_str()).unwrap_or("");
        if status != "ok" {
            return Err(SocketError::ShimError(format!(
                "status={status} payload={resp}"
            )));
        }
        Ok(resp)
    }

    /// Gracefully shut down the subprocess.
    pub fn shutdown(&mut self) {
        if let Ok(mut g) = self.stdin.lock() {
            g.take();
        }
        if let Ok(mut g) = self.child.lock() {
            if let Some(mut child) = g.take() {
                let _ = child.wait_timeout(Duration::from_secs(2));
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

impl Drop for SocketHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Trait extension on `Child` (not provided by std): wait up to
/// `Duration` for the child to exit.
trait ChildWaitTimeout {
    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>>;
}

impl ChildWaitTimeout for Child {
    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if let Some(status) = self.try_wait()? {
                return Ok(Some(status));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_well_formed() {
        assert!(BAND_WS_URL.starts_with("wss://"));
        assert!(BAND_WS_URL.ends_with("/api/v1/socket/websocket"));
    }

    #[test]
    fn socket_error_display_is_informative() {
        let e = SocketError::JoinTimeout(30);
        assert!(e.to_string().contains("30"));
    }

    #[test]
    fn band_socket_event_deserializes_minimal() {
        let json =
            r#"{"event":"room:new_msg","payload":{"body":"hello"},"ts_ms":1,"agent_id":"a"}"#;
        let ev: BandSocketEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.event, "room:new_msg");
        assert_eq!(ev.payload["body"], "hello");
        assert_eq!(ev.agent_id, "a");
    }
}
