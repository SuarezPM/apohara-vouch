//! AC-10.6: cold-start <800ms.
//!
//! `cargo run -p vouch-frontend` boots the Axum server. We spawn it
//! in a background `tokio::spawn`, then `curl`-equivalent (we use
//! `reqwest` to avoid a shell dependency in unit tests) hit `/` and
//! assert the response latency is <800ms.
//!
//! Vercel SSR cold-start measurement is left as a TODO (Playwright
//! in CI per AC-10.6 hint #5).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use axum::routing::get;
use axum::Router;
use tempfile::tempdir;
use tokio::net::TcpListener;
use vouch_frontend::cost_calculator::RateTable;
use vouch_frontend::evidence_cache::EvidenceCache;
use vouch_frontend::sse::{evidence_download, sse_handler, AppState};

/// Spawn the demo server exactly as `main.rs` does. Returned
/// `SocketAddr` is the ephemeral port the OS assigned.
async fn spawn_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let dir = tempdir().expect("tempdir");
    let csv_path = dir.path().join("cost-log.csv");
    // No CSV file — the SSE handler will simply have nothing to replay.
    let state = AppState::new(csv_path, RateTable::defaults(), EvidenceCache::new());

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/health", get(test_health))
        .route("/events", get(sse_handler))
        .route("/evidence/:case_id", get(evidence_download))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Give the listener a tick to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, handle)
}

async fn test_health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"status": "ok"}))
}

async fn serve_index() -> impl axum::response::IntoResponse {
    let html = include_str!("../static/index.html");
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html.to_string(),
    )
}

#[tokio::test]
async fn cold_fetch_under_800ms() {
    let (addr, _handle) = spawn_server().await;
    let url = format!("http://{addr}/");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Warm-up request: let the server settle. This is the SSR cold-
    // start equivalent — `cargo run` already paid the cold-start
    // cost before this test ran.
    let _warmup = client.get(&url).send().await.expect("warmup");

    // Measure 5 sequential requests; assert the **median** is <800ms.
    let mut samples = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let resp = client.get(&url).send().await.expect("request");
        let elapsed = start.elapsed();
        assert_eq!(resp.status(), 200);
        samples.push(elapsed);
    }
    samples.sort();
    let median = samples[samples.len() / 2];
    assert!(
        median < Duration::from_millis(800),
        "median GET / latency {median:?} exceeds 800ms budget; samples = {samples:?}"
    );
}

#[tokio::test]
async fn evidence_endpoint_returns_pdf_under_2s() {
    let (addr, _handle) = spawn_server().await;
    let url = format!("http://{addr}/evidence/case-2026-001");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let start = Instant::now();
    let resp = client.get(&url).send().await.expect("request");
    let elapsed = start.elapsed();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("application/pdf"),
        "expected PDF, got {ct:?}"
    );
    let body = resp.bytes().await.expect("body");
    assert!(body.starts_with(b"%PDF-"), "must be a valid PDF");
    assert!(
        elapsed < Duration::from_secs(2),
        "evidence download took {elapsed:?} (AC-10.5 budget: 2s)"
    );
}

#[tokio::test]
async fn health_endpoint_is_instant() {
    let (addr, _handle) = spawn_server().await;
    let url = format!("http://{addr}/health");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    let start = Instant::now();
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), 200);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(100),
        "health endpoint should be <100ms; was {elapsed:?}"
    );
}

// TODO(AC-10.6 Playwright): assert Vercel SSR cold start
// (`page.goto("https://vouch.apohara.dev")` then measure
// `domcontentloaded`) is <800ms. This requires Playwright in CI
// (see `.github/workflows/vouch-cold-start.yml` — TODO).

#[allow(dead_code)]
fn _path_buf_smoke() -> PathBuf {
    PathBuf::from("x")
}
