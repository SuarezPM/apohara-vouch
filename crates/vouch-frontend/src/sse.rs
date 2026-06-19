//! SSE handler + Evidence Packet download endpoint (S-10).
//!
//! `GET /events` — Server-Sent Events stream of `cost-log.csv` rows.
//! On connect we read the existing CSV (if any), replay every row as
//! an SSE event, then tail the file for new rows (poll loop at
//! 500ms). The handler uses `tokio_stream::wrappers::BroadcastStream`
//! so multiple browser tabs all get the same stream.
//!
//! `GET /evidence/:case_id` — returns the in-memory cached PDF or
//! the deterministic stub (AC-10.5).

use std::convert::Infallible;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
};
use futures_core::Stream;
use futures_util::stream::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tracing::{info, warn};

use crate::cost_calculator::RateTable;
use crate::cost_log_schema::CostLogRow;
use crate::evidence_cache::{stub_pdf, EvidenceCache};

/// Application state shared by all routes.
#[derive(Clone)]
pub struct AppState {
    /// Path to `cost-log.csv` (Python `append_cost_log` target).
    pub cost_log_path: PathBuf,
    /// Loaded rate table (defaults if no TOML shipped).
    pub rate_table: RateTable,
    /// In-memory Evidence Packet PDF cache.
    pub evidence_cache: EvidenceCache,
    /// Fan-out broadcast channel (created lazily on first tail task).
    tail_tx: Arc<Option<broadcast::Sender<CostLogRow>>>,
}

impl AppState {
    /// Build a new `AppState`. Spawns the CSV tail task that pushes
    /// new rows into the broadcast channel (200-buffer — covers
    /// bursty agents).
    pub fn new(
        cost_log_path: PathBuf,
        rate_table: RateTable,
        evidence_cache: EvidenceCache,
    ) -> Self {
        let (tx, _) = broadcast::channel::<CostLogRow>(256);
        let tx_clone = tx.clone();
        let path_clone = cost_log_path.clone();
        // Spawn the tail task. Errors are logged, never propagated —
        // the SSE stream itself reads the existing CSV synchronously
        // on connect so a failed tail doesn't break replays.
        tokio::spawn(async move {
            if let Err(e) = tail_cost_log(path_clone, tx_clone).await {
                warn!("cost log tail task exited: {e}");
            }
        });
        Self {
            cost_log_path,
            rate_table,
            evidence_cache,
            tail_tx: Arc::new(Some(tx)),
        }
    }

    /// Subscribe to the broadcast channel.
    fn subscribe(&self) -> Option<broadcast::Receiver<CostLogRow>> {
        self.tail_tx.as_ref().as_ref().map(|tx| tx.subscribe())
    }
}

/// SSE handler. Replays the existing CSV, then streams new rows.
pub async fn sse_handler(
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, Response> {
    // 1. Replay existing CSV rows (if file exists).
    let initial = read_existing_rows(&state.cost_log_path).await;

    // 2. Subscribe to broadcast for new rows.
    let rx = state.subscribe();

    let initial_stream = futures_util::stream::iter(initial.into_iter().map(|r| {
        let data = serde_json::to_string(&SsePayload::from(r)).unwrap_or_default();
        Ok::<_, Infallible>(Event::default().event("cost-log").data(data))
    }));

    let live_stream: Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>> = match rx {
        Some(rx) => {
            let stream = BroadcastStream::new(rx).filter_map(|res| async move {
                let row = match res {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("broadcast lag: {e}");
                        return None;
                    }
                };
                let data = serde_json::to_string(&SsePayload::from(row)).unwrap_or_default();
                Some(Ok::<_, Infallible>(
                    Event::default().event("cost-log").data(data),
                ))
            });
            Box::pin(stream)
        }
        None => Box::pin(futures_util::stream::empty()),
    };

    let combined = initial_stream.chain(live_stream);
    Ok(Sse::new(combined).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

/// SSE payload — what the browser sees.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SsePayload {
    /// The schema-validated row (full struct, JSON-serialised).
    pub row: CostLogRow,
    /// Pre-computed USD cost (mirrors `row.cost_usd`, but the browser
    /// may also want to re-compute from `rate_table` — both are
    /// exposed for cross-check).
    pub cost_usd: f64,
    /// Whether the row represents non-zero spend (used by the cost
    /// panel's "live spend" tick).
    pub nonzero: bool,
}

impl From<CostLogRow> for SsePayload {
    fn from(row: CostLogRow) -> Self {
        let cost_usd = row.cost_usd;
        Self {
            row,
            cost_usd,
            nonzero: cost_usd > 0.0,
        }
    }
}

/// Evidence Packet download (AC-10.5). Returns the cached PDF or the
/// stub. The response carries `Content-Type: application/pdf` and a
/// `Content-Disposition` filename hint.
pub async fn evidence_download(
    Path(case_id): Path<String>,
    State(state): State<AppState>,
) -> Response {
    let bytes = state
        .evidence_cache
        .get(&case_id)
        .unwrap_or_else(|| stub_pdf(&case_id));

    info!(case_id, "evidence downloaded ({} bytes)", bytes.len());

    let mut resp = (StatusCode::OK, bytes).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        "application/pdf".parse().unwrap(),
    );
    resp.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        format!("inline; filename=\"evidence-{case_id}.pdf\"")
            .parse()
            .unwrap(),
    );
    resp
}

/// Read existing rows from the cost-log CSV. Used by the SSE handler
/// to replay the file content on connect.
async fn read_existing_rows(path: &std::path::Path) -> Vec<CostLogRow> {
    match tokio::fs::read_to_string(path).await {
        Ok(raw) => parse_csv(&raw),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            warn!("cost log read failed for {path:?}: {e}");
            Vec::new()
        }
    }
}

/// Parse a CSV string into rows. Header line is skipped if present.
pub fn parse_csv(raw: &str) -> Vec<CostLogRow> {
    let mut out = Vec::new();
    let mut lines = raw.lines();
    // Skip header if it matches the canonical HEADERS line.
    if let Some(first) = lines.next() {
        if first.split(',').count() == CostLogRow::HEADERS.len()
            && first.trim_start().starts_with("timestamp,")
        {
            // header — skip
        } else {
            // body — parse it
            if let Ok(row) = CostLogRow::from_csv_line(first) {
                out.push(row);
            }
        }
    }
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(row) = CostLogRow::from_csv_line(line) {
            out.push(row);
        }
    }
    out
}

/// Tail the cost-log CSV forever, pushing new rows into the
/// broadcast channel. Polls at 500ms intervals.
async fn tail_cost_log(
    path: PathBuf,
    tx: broadcast::Sender<CostLogRow>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::time::sleep;

    let mut last_len: u64 = match tokio::fs::metadata(&path).await {
        Ok(m) => m.len(),
        Err(_) => 0,
    };
    let mut last_mtime: Option<std::time::SystemTime> = None;

    loop {
        sleep(Duration::from_millis(500)).await;

        let meta = match tokio::fs::metadata(&path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                warn!("tail metadata error: {e}");
                continue;
            }
        };
        let mtime: std::time::SystemTime = match meta.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if last_mtime.is_some() && last_mtime == Some(mtime) && meta.len() == last_len {
            continue; // unchanged
        }
        last_mtime = Some(mtime);
        last_len = meta.len();

        // Read the entire file. CSV is tiny (KB) so this is cheap.
        let raw = match tokio::fs::read_to_string(&path).await {
            Ok(r) => r,
            Err(e) => {
                warn!("tail read error: {e}");
                continue;
            }
        };
        let rows = parse_csv(&raw);
        for row in rows {
            // Broadcast may have no receivers — that's fine.
            let _ = tx.send(row);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_skips_header_and_parses_rows() {
        let raw = "timestamp,agent,provider,model,tokens_in,tokens_out,cached_input_tokens,cost_usd\n2026-06-18T12:34:56Z,fraud-auditor,aiml,claude-sonnet-4-6,1500,420,1200,0.010500\n";
        let rows = parse_csv(raw);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].agent, "fraud-auditor");
        assert_eq!(rows[0].tokens_in, 1500);
    }

    #[test]
    fn parse_csv_handles_no_header() {
        let raw = "2026-06-18T12:34:56Z,legal-policy-checker,aiml,claude-sonnet-4-6,800,200,400,0.003000\n";
        let rows = parse_csv(raw);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].agent, "legal-policy-checker");
    }

    #[test]
    fn parse_csv_skips_blank_lines() {
        let raw = "\n\n2026-06-18T12:34:56Z,fraud-auditor,aiml,claude-sonnet-4-6,1500,420,1200,0.010500\n\n";
        let rows = parse_csv(raw);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn parse_csv_returns_empty_for_empty_input() {
        let rows = parse_csv("");
        assert!(rows.is_empty());
    }

    #[test]
    fn sse_payload_from_row_captures_nonzero_flag() {
        let row = CostLogRow::sample_row();
        let p = SsePayload::from(row.clone());
        assert!(p.nonzero);
        assert_eq!(p.cost_usd, row.cost_usd);
    }

    #[test]
    fn sse_payload_marks_zero_cost_as_zero() {
        let mut row = CostLogRow::sample_row();
        row.cost_usd = 0.0;
        let p = SsePayload::from(row);
        assert!(!p.nonzero);
    }

    #[tokio::test]
    async fn appstate_new_creates_a_subscribe_channel() {
        let cache = EvidenceCache::new();
        let table = RateTable::defaults();
        let state = AppState::new(PathBuf::from("/tmp/does-not-exist.csv"), table, cache);
        // The tail task is spawned; we can still subscribe (channel
        // exists even if the file doesn't).
        let _rx = state.subscribe();
    }
}
