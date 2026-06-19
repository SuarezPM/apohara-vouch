//! vouch-frontend — Demo UI server for vouch.apohara.dev (S-10).
//!
//! Axum 0.7 server that exposes:
//! * `GET /` — 3-panel vanilla HTML page (transcript | cost | EU AI Act compliance)
//! * `GET /events` — Server-Sent Events stream of `cost-log.csv` rows
//! * `GET /evidence/:case_id` — C2PA-signed Evidence Packet PDF (in-memory cached)
//! * `GET /static/*` — JS / CSS / favicon
//! * `GET /health` — healthcheck
//!
//! Cold start target: <800ms (AC-10.6).
//!
//! This crate is parallel to `themis-frontend` (a different crate name; do
//! NOT touch `themis-frontend/`).

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use axum::response::IntoResponse;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use vouch_frontend::{cost_calculator, cost_log_schema, evidence_cache, sse};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Tracing (best-effort; if the subscriber is already set elsewhere we
    // simply skip).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();

    // Bind address. 0.0.0.0:7879 is the demo port (per S-10 spec).
    let bind: SocketAddr = std::env::var("VOUCH_FRONTEND_BIND")
        .unwrap_or_else(|_| "0.0.0.0:7879".to_string())
        .parse()
        .context("VOUCH_FRONTEND_BIND must be a valid socket address")?;

    // Static dir lives next to the binary for Vercel-style deploys, but the
    // dev/CI path uses `<crate>/static`.
    let static_dir: PathBuf = std::env::var("VOUCH_FRONTEND_STATIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // CARGO_MANIFEST_DIR is set at compile time; we ship the
            // folder at <crate>/static/ so the resolve is deterministic.
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static")
        });

    // Cost log path (read by the SSE handler). Defaults to ./cost-log.csv
    // so the demo works out of the box; production sets
    // VOUCH_COST_LOG_PATH to the orchestrator's CSV file.
    let cost_log_path: PathBuf = std::env::var("VOUCH_COST_LOG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("cost-log.csv"));

    // Load rate table (defaults if file missing). Fail loud on parse errors.
    let rate_table =
        cost_calculator::RateTable::load_or_default().context("loading cost rate table")?;

    // In-memory evidence cache (case_id -> bytes). The production wiring
    // populates this via the orchestrator's render_memo_pdf callback;
    // for local demos, the cache stays empty and `/evidence/:case_id`
    // returns a deterministic stub PDF.
    let evidence_cache = evidence_cache::EvidenceCache::new();

    let state = sse::AppState::new(cost_log_path.clone(), rate_table, evidence_cache);

    // Build router. Static files served via tower-http ServeDir so the
    // HTML page can reference /static/app.js without a custom handler.
    let app = axum::Router::new()
        .route("/", axum::routing::get(serve_index))
        .route("/health", axum::routing::get(health))
        .route("/events", axum::routing::get(sse::sse_handler))
        .route(
            "/evidence/:case_id",
            axum::routing::get(sse::evidence_download),
        )
        .route("/rates", axum::routing::get(rate_table_handler))
        .route(
            "/cost_log_schema",
            axum::routing::get(cost_log_schema_handler),
        )
        .nest_service("/static", ServeDir::new(&static_dir))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding to {bind}"))?;

    tracing::info!(
        %bind,
        ?static_dir,
        ?cost_log_path,
        "vouch-frontend listening (S-10)"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum::serve error")?;

    Ok(())
}

/// Serve the embedded `index.html` from the static dir.
async fn serve_index(
    axum::extract::State(_state): axum::extract::State<sse::AppState>,
) -> impl axum::response::IntoResponse {
    // Read fresh from disk each request so HTML edits show up without
    // a server restart (cheap — the file is <5KB).
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("static/index.html");
    match tokio::fs::read_to_string(&p).await {
        Ok(html) => axum::response::Html(html).into_response(),
        Err(e) => (
            axum::http::StatusCode::NOT_FOUND,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            )],
            format!("index.html missing at {p:?}: {e}"),
        )
            .into_response(),
    }
}

/// `GET /health` — liveness check.
async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "vouch-frontend",
        "version": env!("CARGO_PKG_VERSION"),
        "endpoints": ["/", "/events", "/evidence/:case_id", "/static/*", "/rates", "/cost_log_schema", "/health"],
    }))
}

/// `GET /rates` — surface the loaded rate table (used by AC-10.8 drift test
/// + the cost panel live readout).
async fn rate_table_handler(
    axum::extract::State(state): axum::extract::State<sse::AppState>,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::to_value(&state.rate_table).unwrap_or_default())
}

/// `GET /cost_log_schema` — return the canonical CSV header list
/// (used by AC-10.7 schema test).
async fn cost_log_schema_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "headers": cost_log_schema::CostLogRow::HEADERS,
        "sample": cost_log_schema::CostLogRow::sample_row(),
    }))
}

/// Graceful shutdown on SIGINT / SIGTERM.
async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                let _ = s.recv().await;
            }
            Err(_) => {
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("vouch-frontend: shutdown signal received");
}

// ---------------------------------------------------------------------------
// (no extension trait needed; axum::response::Html handles the HTML case)
// ---------------------------------------------------------------------------
