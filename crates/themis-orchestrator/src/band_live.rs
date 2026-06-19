//! HTTP handlers for the live Band room integration (Story Ola-A).
//!
//! * `GET /band-live`        — Server-Sent Events stream of
//!                             `BandSocketEvent`s from the 6-agent
//!                             fleet (echoed to the frontend).
//! * `GET /metrics/band`     — JSON `{ ws_events_total,
//!                             agents_connected, room_id }`.
//! * `POST /band/start-room` — spawns 6 agent WebSocket
//!                             subprocesses on `app.band.ai`,
//!                             returns the public room URL.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response, Sse};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use themis_band_client::fleet::FleetMetrics;
use themis_band_client::socket::BandSocketEvent;
use tokio::sync::{broadcast, Mutex};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

/// Shared state for the `/band-live` SSE stream + `/band/start-room`
/// endpoint.
pub struct BandLiveState {
    /// Live fan-out registry.
    pub registry: Mutex<Option<FanoutRegistry>>,
    /// Broadcast sink for fleet events (the SSE handler subscribes).
    pub tx: broadcast::Sender<BandSocketEvent>,
}

/// The spawned fleet: 6 agent handles + the room id + a shared
/// event counter.
pub struct FanoutRegistry {
    /// The chatroom UUID.
    pub room_id: String,
    /// Public URL of the chatroom on `app.band.ai`.
    pub public_url: String,
    /// How many agent subprocesses were spawned.
    pub agents_connected: usize,
    /// Total WS events observed across all agents (incremented
    /// by the fan-out tasks).
    pub ws_events_total: Arc<AtomicU64>,
}

impl FanoutRegistry {
    /// Snapshot the current metrics.
    pub fn metrics(&self) -> FleetMetrics {
        FleetMetrics {
            ws_events_total: self.ws_events_total.load(Ordering::Relaxed),
            agents_connected: self.agents_connected,
            room_id: self.room_id.clone(),
            per_agent: std::collections::BTreeMap::new(),
        }
    }
}

impl Default for BandLiveState {
    fn default() -> Self {
        Self::new()
    }
}

impl BandLiveState {
    /// New empty state with a 1024-event broadcast buffer.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            registry: Mutex::new(None),
            tx,
        }
    }

    /// Spawn the 6-agent fleet for `room_id`.
    pub async fn start_room(
        &self,
        room_id: &str,
    ) -> Result<FleetMetrics, themis_band_client::fleet::FleetError> {
        let shim_path = locate_run_agent_shim()?;
        let python_bin =
            std::env::var("THEMIS_BAND_PYTHON").unwrap_or_else(|_| "python3".to_string());
        let fleet =
            themis_band_client::fleet::BandFleet::spawn_all(&python_bin, &shim_path, room_id)?;
        let ws_events_total = Arc::new(AtomicU64::new(0));
        let public_url = fleet.public_url.clone();
        let registry = FanoutRegistry {
            room_id: room_id.to_string(),
            public_url: public_url.clone(),
            agents_connected: fleet.agents_connected(),
            ws_events_total: ws_events_total.clone(),
        };
        // Move the handles into fan-out tasks.
        let handles = fleet.into_handles();
        for mut handle in handles {
            let tx = self.tx.clone();
            let counter = ws_events_total.clone();
            tokio::spawn(async move {
                while let Some(ev) = handle.recv_event().await {
                    counter.fetch_add(1, Ordering::Relaxed);
                    let _ = tx.send(ev);
                }
            });
        }
        *self.registry.lock().await = Some(registry);
        let m = self.metrics().await;
        Ok(m)
    }

    /// Snapshot the current metrics.
    pub async fn metrics(&self) -> FleetMetrics {
        let g = self.registry.lock().await;
        match g.as_ref() {
            Some(r) => r.metrics(),
            None => FleetMetrics::default(),
        }
    }
}

/// Locate the `scripts/run_agent.py` shim relative to the
/// workspace `Cargo.toml`. Resolves `../themis-band-client/scripts/
/// run_agent.py` from `CARGO_MANIFEST_DIR` (the orchestrator's
/// dir) so the binary works whether installed system-wide or run
/// via `cargo run`.
fn locate_run_agent_shim() -> Result<String, themis_band_client::fleet::FleetError> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| {
            p.join("themis-band-client")
                .join("scripts")
                .join("run_agent.py")
        });
    let path = match p {
        Some(p) => p,
        None => {
            return Err(themis_band_client::fleet::FleetError::SpawnFailed(
                "extractor".to_string(),
                "could not resolve run_agent.py path".to_string(),
            ))
        }
    };
    if !path.exists() {
        return Err(themis_band_client::fleet::FleetError::SpawnFailed(
            "extractor".to_string(),
            format!("run_agent.py not found at {}", path.display()),
        ));
    }
    path.to_str().map(|s| s.to_string()).ok_or_else(|| {
        themis_band_client::fleet::FleetError::SpawnFailed(
            "extractor".to_string(),
            "run_agent.py path is not valid UTF-8".to_string(),
        )
    })
}

/// Request body for `POST /band/start-room`. Optional
/// `room_id`; if absent the server generates a fresh UUID v4.
#[derive(Debug, Deserialize, Default)]
pub struct StartRoomRequest {
    /// Optional chatroom UUID. If absent, a new UUID v4 is minted.
    #[serde(default)]
    pub room_id: Option<String>,
}

/// `POST /band/start-room` — spawns the 6-agent fleet. Returns
/// the public room URL + the spawned fleet metrics.
pub async fn post_band_start_room(
    State(state): State<Arc<crate::http::AppState>>,
    Json(req): Json<StartRoomRequest>,
) -> Response {
    let room_id = req
        .room_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let live = match state.band_live.as_ref() {
        Some(l) => l,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "band_live state not wired in this build"})),
            )
                .into_response();
        }
    };
    match live.start_room(&room_id).await {
        Ok(metrics) => {
            let public_url = format!("https://app.band.ai/rooms/{room_id}");
            (
                StatusCode::OK,
                Json(json!({
                    "room_id": room_id,
                    "public_url": public_url,
                    "metrics": metrics,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("start_room: {e}")})),
        )
            .into_response(),
    }
}

/// `GET /metrics/band` — JSON `{ ws_events_total, agents_connected, room_id }`.
pub async fn get_metrics_band(State(state): State<Arc<crate::http::AppState>>) -> Response {
    match state.band_live.as_ref() {
        Some(live) => {
            let m = live.metrics().await;
            Json(json!({
                "ws_events_total": m.ws_events_total,
                "agents_connected": m.agents_connected,
                "room_id": m.room_id,
                "per_agent": m.per_agent,
            }))
            .into_response()
        }
        None => Json(json!({
            "ws_events_total": 0,
            "agents_connected": 0,
            "room_id": "",
            "per_agent": {},
        }))
        .into_response(),
    }
}

/// `GET /band-live` — SSE stream of `BandSocketEvent`s from the
/// 6-agent fleet.
pub async fn get_band_live_sse(State(state): State<Arc<crate::http::AppState>>) -> Response {
    let rx = match state.band_live.as_ref() {
        Some(live) => live.tx.subscribe(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "band_live not wired"})),
            )
                .into_response();
        }
    };
    let stream = BroadcastStream::new(rx).filter_map(|res| match res {
        Ok(ev) => {
            let json = serde_json::to_string(&ev).unwrap_or_default();
            Some(Ok::<_, std::convert::Infallible>(
                axum::response::sse::Event::default()
                    .event("band_event")
                    .data(json),
            ))
        }
        Err(_) => None,
    });
    Sse::new(stream)
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(std::time::Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_state_metrics_are_zero() {
        let s = BandLiveState::new();
        let m = s.metrics().await;
        assert_eq!(m.ws_events_total, 0);
        assert_eq!(m.agents_connected, 0);
        assert_eq!(m.room_id, "");
    }

    #[test]
    fn locate_run_agent_shim_works() {
        let p = locate_run_agent_shim();
        assert!(p.is_ok(), "shim path resolution: {:?}", p.err());
    }
}
