//! SSE stream integration test (AC-10.1).
//!
//! Boots the Axum app on an ephemeral port, hits `/events`, and
//! asserts the response is a 200 with the right `Content-Type`. The
//! test writes a single row to the cost log first, so the SSE
//! handler replays it on connect.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::time::timeout;
use vouch_frontend::cost_calculator::RateTable;
use vouch_frontend::cost_log_schema::CostLogRow;
use vouch_frontend::evidence_cache::EvidenceCache;
use vouch_frontend::sse::{sse_handler, AppState};

async fn spawn_app() -> (SocketAddr, AppState, tempfile::TempDir) {
    let dir = tempdir().expect("tempdir");
    let csv_path = dir.path().join("cost-log.csv");
    // Pre-write one row so the SSE handler has something to replay.
    let header =
        "timestamp,agent,provider,model,tokens_in,tokens_out,cached_input_tokens,cost_usd\n";
    let row = "2026-06-18T12:00:00Z,fraud-auditor,aiml,claude-sonnet-4-6,1500,420,1200,0.010500\n";
    std::fs::write(&csv_path, header.to_string() + row).unwrap();

    let state = AppState::new(csv_path, RateTable::defaults(), EvidenceCache::new());

    let app = Router::new()
        .route("/events", get(sse_handler))
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Yield so the server starts accepting.
    tokio::time::sleep(Duration::from_millis(100)).await;
    (addr, state, dir)
}

#[tokio::test]
async fn sse_endpoint_returns_event_stream_content_type() {
    let (addr, _state, _dir) = spawn_app().await;
    let url = format!("http://{addr}/events");

    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("connect");
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/event-stream"),
        "expected text/event-stream, got {ct:?}"
    );
}

#[tokio::test]
async fn sse_endpoint_replays_existing_row_on_connect() {
    let (addr, _state, _dir) = spawn_app().await;
    let url = format!("http://{addr}/events");

    let client = reqwest::Client::new();
    // Disable the request-level timeout; SSE streams stay open
    // forever. We use a wall-clock `tokio::time::timeout` below.
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .expect("connect");

    use futures_util::StreamExt;

    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    let found = timeout(Duration::from_secs(15), async {
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(_) => break,
            };
            buf.extend_from_slice(&chunk);
            let s = String::from_utf8_lossy(&buf);
            if s.contains("event: cost-log") && s.contains("fraud-auditor") {
                return true;
            }
            if buf.len() > 64 * 1024 {
                return false;
            }
        }
        false
    })
    .await
    .unwrap_or(false);

    assert!(
        found,
        "expected replayed cost-log event with fraud-auditor within 15s; got ({} bytes):\n{}",
        buf.len(),
        String::from_utf8_lossy(&buf)
    );
}

#[tokio::test]
async fn cost_log_row_round_trips_via_csv() {
    // Sanity: the row the SSE replays was parsed from the CSV.
    let row = CostLogRow::sample_row();
    let line = row.to_csv_row();
    let parsed = CostLogRow::from_csv_line(&line).expect("parse");
    assert_eq!(parsed, row);
}

// Avoid the unused-import warning for Infallible (kept for the
// `convert::Infallible` doc comment; the function is in scope via
// the trait bounds above).
const _: fn() = || {
    let _: Infallible = todo!();
};

// PathBuf import smoke (used in future tests).
#[allow(dead_code)]
fn _path_buf_smoke() -> PathBuf {
    PathBuf::from("x")
}
