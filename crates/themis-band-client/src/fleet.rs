//! BandFleet — spawn and supervise all 6 THEMIS agents as
//! long-lived WebSocket subprocesses.
//!
//! Reads `BAND_AGENT_<NAME>_ID` + `BAND_AGENT_<NAME>_API_KEY` env
//! vars (sourced from `~/.config/apohara/secrets.env`), spawns one
//! `scripts/run_agent.py` per agent, and exposes:
//!
//! - `BandFleet::spawn_all` — returns 6 `SocketHandle`s.
//! - `BandFleet::metrics` — `FleetMetrics { ws_events_total,
//!   agents_connected, room_id }` for the `/metrics/band` JSON
//!   endpoint.
//!
//! This module is the Rust side of the Ola-A spec. The Python shim
//! (`scripts/run_agent.py`) owns the actual wire protocol.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::socket::{BandSocketEvent, SocketHandle, BAND_WS_URL};

/// Canonical 6 agent names, in the order the orchestrator
/// declares them.
pub const AGENT_NAMES: [&str; 6] = [
    "extractor",
    "po_matcher",
    "fraud_auditor",
    "gaap_classifier",
    "provenance_signer",
    "demo_narrator",
];

/// Build the env-var name for an agent's UUID id.
fn id_env(name: &str) -> String {
    format!("BAND_AGENT_{}_ID", name.to_ascii_uppercase())
}

/// Build the env-var name for an agent's API key.
fn key_env(name: &str) -> String {
    format!("BAND_AGENT_{}_API_KEY", name.to_ascii_uppercase())
}

/// One configured agent (id + api_key from env).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Canonical agent name.
    pub name: String,
    /// Band-assigned UUID.
    pub agent_id: String,
    /// Band-assigned API key.
    pub api_key: String,
}

/// Errors from `BandFleet`.
#[derive(Debug, Error)]
pub enum FleetError {
    /// Required env var missing or empty.
    #[error("env var {0} missing or empty")]
    MissingEnv(String),
    /// Subprocess spawn failed for a specific agent.
    #[error("agent {0}: spawn failed: {1}")]
    SpawnFailed(String, String),
    /// A handle errored after spawn.
    #[error("agent {0}: {1}")]
    Agent(String, String),
}

/// Telemetry for the `/metrics/band` JSON endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetMetrics {
    /// Total WebSocket events observed across all agents.
    pub ws_events_total: u64,
    /// Number of agents currently connected (handle still alive).
    pub agents_connected: usize,
    /// The Band room id (chatroom UUID) the fleet is joined to.
    pub room_id: String,
    /// Per-agent event counts (for forensics).
    pub per_agent: std::collections::BTreeMap<String, u64>,
}

/// The fleet of 6 agent subprocesses + the room they all share.
pub struct BandFleet {
    /// The shared room id (Band chatroom UUID).
    pub room_id: String,
    /// Public URL of the chatroom on `app.band.ai`.
    pub public_url: String,
    handles: Vec<SocketHandle>,
    /// Bumps every time any agent observes a WS event.
    ws_events_total: Arc<AtomicU64>,
    /// When `Some`, used as `agents_connected` in `metrics()`.
    agents_connected_override: Option<usize>,
}

impl std::fmt::Debug for BandFleet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BandFleet")
            .field("room_id", &self.room_id)
            .field("public_url", &self.public_url)
            .field("agents_connected", &self.handles.len())
            .finish()
    }
}

impl BandFleet {
    /// Read all 6 agent configs from the environment.
    pub fn configs_from_env() -> Result<Vec<AgentConfig>, FleetError> {
        let mut out = Vec::with_capacity(AGENT_NAMES.len());
        for name in AGENT_NAMES {
            let agent_id = std::env::var(id_env(name))
                .map_err(|_| FleetError::MissingEnv(id_env(name)))?
                .trim()
                .to_string();
            if agent_id.is_empty() {
                return Err(FleetError::MissingEnv(id_env(name)));
            }
            let api_key = std::env::var(key_env(name))
                .map_err(|_| FleetError::MissingEnv(key_env(name)))?
                .trim()
                .to_string();
            if api_key.is_empty() {
                return Err(FleetError::MissingEnv(key_env(name)));
            }
            out.push(AgentConfig {
                name: name.to_string(),
                agent_id,
                api_key,
            });
        }
        Ok(out)
    }

    /// Spawn one `run_agent.py` subprocess per agent and join
    /// the shared `room_id`.
    pub fn spawn_all(python_bin: &str, shim_path: &str, room_id: &str) -> Result<Self, FleetError> {
        let configs = Self::configs_from_env()?;
        let ws_url = std::env::var("BAND_WS_URL").unwrap_or_else(|_| BAND_WS_URL.to_string());
        let mut handles = Vec::with_capacity(configs.len());
        for cfg in &configs {
            let h = SocketHandle::spawn(
                python_bin,
                shim_path,
                &cfg.agent_id,
                &cfg.api_key,
                room_id,
                &ws_url,
            )
            .map_err(|e| FleetError::SpawnFailed(cfg.name.clone(), e.to_string()))?;
            handles.push(h);
        }
        Ok(Self {
            room_id: room_id.to_string(),
            public_url: format!("https://app.band.ai/rooms/{room_id}"),
            handles,
            ws_events_total: Arc::new(AtomicU64::new(0)),
            agents_connected_override: None,
        })
    }

    /// Spawn a single agent (used by the `band_hello_world`
    /// integration test).
    pub fn spawn_one(
        python_bin: &str,
        shim_path: &str,
        room_id: &str,
    ) -> Result<(String, SocketHandle), FleetError> {
        let name = "extractor";
        let agent_id = std::env::var(id_env(name))
            .map_err(|_| FleetError::MissingEnv(id_env(name)))?
            .trim()
            .to_string();
        let api_key = std::env::var(key_env(name))
            .map_err(|_| FleetError::MissingEnv(key_env(name)))?
            .trim()
            .to_string();
        if agent_id.is_empty() || api_key.is_empty() {
            return Err(FleetError::MissingEnv(format!(
                "BAND_AGENT_{}_ID/BAND_AGENT_{}_API_KEY",
                name.to_ascii_uppercase(),
                name.to_ascii_uppercase()
            )));
        }
        let ws_url = std::env::var("BAND_WS_URL").unwrap_or_else(|_| BAND_WS_URL.to_string());
        let handle =
            SocketHandle::spawn(python_bin, shim_path, &agent_id, &api_key, room_id, &ws_url)
                .map_err(|e| FleetError::SpawnFailed(name.to_string(), e.to_string()))?;
        Ok((name.to_string(), handle))
    }

    /// Number of currently-connected agent handles.
    pub fn agents_connected(&self) -> usize {
        self.agents_connected_override.unwrap_or(self.handles.len())
    }

    /// Snapshot of `/metrics/band` telemetry.
    pub fn metrics(&self) -> FleetMetrics {
        let mut per_agent = std::collections::BTreeMap::new();
        let mut total = 0u64;
        for (i, h) in self.handles.iter().enumerate() {
            let n = h.events_observed();
            total += n;
            let name = AGENT_NAMES.get(i).copied().unwrap_or("?");
            per_agent.insert(name.to_string(), n);
        }
        let agents_connected = self.agents_connected_override.unwrap_or(self.handles.len());
        FleetMetrics {
            ws_events_total: total,
            agents_connected,
            room_id: self.room_id.clone(),
            per_agent,
        }
    }

    /// Move every handle out of the fleet.
    pub fn into_handles(self) -> Vec<SocketHandle> {
        self.handles
    }

    /// Increment the shared event counter.
    pub fn record_event(&self) {
        self.ws_events_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Construct an empty `BandFleet` "shell" with no live
    /// subprocess handles but a known `room_id` + `agents_connected`.
    pub fn shell(room_id: String, agents_connected: usize) -> Self {
        let public_url = format!("https://app.band.ai/rooms/{room_id}");
        Self {
            room_id,
            public_url,
            handles: Vec::new(),
            ws_events_total: Arc::new(AtomicU64::new(0)),
            agents_connected_override: Some(agents_connected),
        }
    }

    /// Override `agents_connected` on the shell.
    pub fn set_agents_connected(&mut self, n: usize) {
        self.agents_connected_override = Some(n);
    }

    /// Share the internal `ws_events_total` counter.
    pub fn ws_events_total_handle(&self) -> Arc<AtomicU64> {
        self.ws_events_total.clone()
    }
}

/// Convenience: convert a stream of `BandSocketEvent`s from one
/// handle into a shared broadcast sink the orchestrator can read.
pub fn fan_out(
    mut handle: SocketHandle,
    sink: mpsc::Sender<BandSocketEvent>,
) -> tokio::task::JoinHandle<()> {
    let agent = handle.agent_id.0.clone();
    tokio::spawn(async move {
        while let Some(ev) = handle.recv_event().await {
            if sink.send(ev).await.is_err() {
                break;
            }
        }
        let _ = agent;
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_names_count_is_six() {
        assert_eq!(AGENT_NAMES.len(), 6);
        assert!(AGENT_NAMES.contains(&"extractor"));
        assert!(AGENT_NAMES.contains(&"demo_narrator"));
    }

    #[test]
    fn env_var_names_match_uppercase_snake_case() {
        assert_eq!(id_env("extractor"), "BAND_AGENT_EXTRACTOR_ID");
        assert_eq!(key_env("po_matcher"), "BAND_AGENT_PO_MATCHER_API_KEY");
        assert_eq!(
            id_env("provenance_signer"),
            "BAND_AGENT_PROVENANCE_SIGNER_ID"
        );
    }

    #[test]
    fn metrics_default_is_zero() {
        let m = FleetMetrics::default();
        assert_eq!(m.ws_events_total, 0);
        assert_eq!(m.agents_connected, 0);
    }

    #[test]
    fn shell_reports_agent_count() {
        let f = BandFleet::shell("room".to_string(), 6);
        let m = f.metrics();
        assert_eq!(m.agents_connected, 6);
        assert_eq!(m.room_id, "room");
    }
}
