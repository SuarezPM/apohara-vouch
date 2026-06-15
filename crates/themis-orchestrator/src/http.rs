//! HTTP layer for themis-orchestrator.
//!
//! * `GET /`           — serves the themis-frontend index.html
//! * `GET /compliance` — serves the compliance dashboard HTML
//! * `GET /static/*`    — serves tokens.css, app.css, app.js
//! * `GET /events`      — SSE stream of EventBus events
//! * `POST /invoices`   — starts a process_invoice run
//! * `GET /compliance-report/:run_id` — returns the ComplianceReport JSON
//!
//! The orchestrator owns an `Arc<AppState>` with: the EventBus, the
//! orchestrator (for POST /invoices), the ComplianceService, and
//! the in-memory run store (run_id → ComplianceReport).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use dashmap::DashMap;
use serde::Deserialize;
use serde_json::json;
use themis_compliance::service::ComplianceReport;
use themis_evidence::packet::SealedPacket;
use themis_frontend::{APP_CSS, APP_JS, COMPLIANCE_HTML, INDEX_HTML, TOKENS_CSS};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

use crate::events::{Event, EventBus};
use crate::orchestrator::Orchestrator;
use crate::packet::SignedPacket;
use crate::pdf;

/// Shared application state held by every axum handler.
#[derive(Clone)]
pub struct AppState {
    /// The orchestrator wrapped in a tokio mutex so its guard is `Send`
    /// (axum 0.7 runs handlers on a multi-threaded runtime; `std::sync::MutexGuard`
    /// is `!Send` and would poison the future).
    pub orchestrator: std::sync::Arc<tokio::sync::Mutex<Orchestrator>>,
    /// The event bus (for SSE), wrapped in Arc so AppState can be Clone.
    pub event_bus: std::sync::Arc<EventBus>,
    /// The compliance service (instantiated once at startup), Arc-wrapped.
    pub compliance: std::sync::Arc<themis_compliance::service::ComplianceService>,
    /// Per-run-id → ComplianceReport (populated after process_invoice).
    pub reports: DashMap<uuid::Uuid, ComplianceReport>,
    /// Per-packet-id → SignedPacket (populated after process_invoice
    /// so the PDF endpoint can render it). Keyed by packet_id (not
    /// run_id) so the PDF is reachable from the demo URL the
    /// frontend hands to the judge.
    pub packets: DashMap<uuid::Uuid, SignedPacket>,
    /// Per-packet-id → SealedPacket (populated when the orchestrator
    /// is built with an evidence service — the `SealedPacket` is the
    /// shape that `themis-verify` consumes). The `/packets/:id/json`
    /// endpoint serves this directly. Empty when the binary is built
    /// without the evidence wiring (mock-only path).
    pub sealed: DashMap<uuid::Uuid, SealedPacket>,
}

/// Build the axum Router with all routes.
///
/// `AppState` is wrapped in `Arc` before being installed as the axum
/// `State` extractor. `Arc<AppState>` is `Clone` (cheap pointer clone),
/// satisfies axum's `S: Clone + Send + Sync` bound, and crucially
/// `Router::clone()` shares the same `Arc<AppState>` (vs. cloning the
/// `AppState` which would duplicate the `DashMap` and break the
/// POST→GET state hand-off in tests).
pub fn build_router(state: AppState) -> Router {
    let state = Arc::new(state);
    // 4 MiB body limit on the POST /invoices endpoint.
    // `RequestBodyLimitLayer` from tower-http rejects with 413
    // when the body exceeds the cap, preventing multi-GB uploads
    // from exhausting memory on the public demo. The default
    // axum body limit (2 MiB) is also enforced; we set it
    // explicitly to 4 MiB to match the spec's "small JSON +
    // base64-encoded raw invoice" envelope.
    const BODY_LIMIT: usize = 4 * 1024 * 1024;
    let invoices_route = Router::new()
        .route("/invoices", post(post_invoices))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(BODY_LIMIT));
    Router::new()
        .route("/", get(get_index))
        .route("/compliance", get(get_compliance_dashboard))
        .route("/static/tokens.css", get(get_tokens_css))
        .route("/static/app.css", get(get_app_css))
        .route("/static/app.js", get(get_app_js))
        .route("/events", get(get_events_sse))
        .merge(invoices_route)
        .route(
            "/compliance-report/:run_id",
            get(get_compliance_report_json),
        )
        .route("/packets/:packet_id/pdf", get(get_packet_pdf))
        .route("/packets/:packet_id/json", get(get_packet_json))
        .with_state(state)
}

// --- Handlers ---

async fn get_index() -> Response {
    html_response(INDEX_HTML)
}

async fn get_compliance_dashboard() -> Response {
    html_response(COMPLIANCE_HTML)
}

async fn get_tokens_css() -> Response {
    css_response(TOKENS_CSS)
}

async fn get_app_css() -> Response {
    css_response(APP_CSS)
}

async fn get_app_js() -> Response {
    js_response(APP_JS)
}

async fn get_events_sse(
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<axum::response::sse::Event, Infallible>>> {
    let rx = state.event_bus.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|res| {
        // Drop Lagged + Closed events (subscriber can't keep up).
        match res {
            Ok(event) => {
                let json = serde_json::to_string(&event).unwrap_or_default();
                let sse = axum::response::sse::Event::default()
                    .event(event.type_str())
                    .data(json);
                Some(Ok(sse))
            }
            Err(_) => None,
        }
    });
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

/// Request body for `POST /invoices` — kicks off a `process_invoice` run.
#[derive(Debug, Deserialize)]
pub struct PostInvoiceRequest {
    /// Tenant id (e.g. "stark", "wayne").
    pub tenant_id: String,
    /// Invoice id.
    pub invoice_id: String,
    /// Base64-encoded raw invoice bytes.
    #[serde(default)]
    pub raw_b64: String,
}

async fn post_invoices(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PostInvoiceRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let raw = base64_decode(&req.raw_b64).unwrap_or_default();
    let run_id = uuid::Uuid::new_v4();
    state.event_bus.publish(Event::AgentStarted {
        run_id,
        agent: "extractor".to_string(),
    });
    let (packet, sealed) = {
        let orch = state.orchestrator.lock().await;
        if orch.has_evidence() {
            match orch
                .process_invoice_sealed(&req.tenant_id, &req.invoice_id, raw)
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("{e:?}")})),
                    ));
                }
            }
        } else {
            match orch
                .process_invoice(&req.tenant_id, &req.invoice_id, raw)
                .await
            {
                Ok(p) => (p, None),
                Err(e) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("{e:?}")})),
                    ));
                }
            }
        }
    };
    let compliance_packet = themis_compliance::framework::EvidencePacket::new(
        packet.packet.tenant_id.clone(),
        packet.packet.invoice_id.clone(),
        packet.packet.agent_decisions.clone(),
        packet.packet.bbaaar_outcome,
    );
    let report = state.compliance.report(&compliance_packet);
    state.reports.insert(run_id, report.clone());
    state
        .packets
        .insert(packet.packet.packet_id, packet.clone());
    if let Some(s) = sealed {
        // Key by the SignedPacket's packet_id (the id the
        // frontend already knows), not the SealedPacket's
        // internal id (which is a fresh UUIDv4 minted by
        // EvidenceService::seal).
        state.sealed.insert(packet.packet.packet_id, s);
    }
    state.event_bus.publish(Event::EvidenceSealed {
        run_id,
        packet_id: packet.packet.packet_id,
    });
    state.event_bus.publish(Event::RunFinished { run_id });
    Ok(Json(json!({
        "run_id": run_id,
        "packet_id": packet.packet.packet_id,
        "compliance": report,
    })))
}

async fn get_compliance_report_json(
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<uuid::Uuid>,
) -> Response {
    match state.reports.get(&run_id) {
        Some(r) => Json(r.value().clone()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "run_id not found"})),
        )
            .into_response(),
    }
}

// --- Helpers ---

fn html_response(s: &str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(s.to_string()))
        .unwrap()
}

fn css_response(s: &str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/css; charset=utf-8")
        .body(Body::from(s.to_string()))
        .unwrap()
}

fn js_response(s: &str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )
        .body(Body::from(s.to_string()))
        .unwrap()
}

fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s)
}

/// `GET /packets/:packet_id/pdf` — render the sealed packet as PDF
/// bytes. Used by the frontend's "Download PDF" button to satisfy
/// AC12 (PRC PDF download <2s).
async fn get_packet_pdf(
    State(state): State<Arc<AppState>>,
    Path(packet_id): Path<uuid::Uuid>,
) -> Result<Response, (StatusCode, String)> {
    let packet = state.packets.get(&packet_id).ok_or((
        StatusCode::NOT_FOUND,
        format!("packet {packet_id} not found"),
    ))?;
    let bytes = pdf::render_packet_pdf(&packet).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("PDF render: {e}"),
        )
    })?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(
            header::CONTENT_DISPOSITION,
            format!(
                "attachment; filename=\"themis-{}-{}.pdf\"",
                packet.packet.tenant_id, packet.packet.invoice_id
            ),
        )
        .body(Body::from(bytes))
        .unwrap())
}

/// `GET /packets/:packet_id/json` — return the strict `SealedPacket`
/// JSON that `themis-verify` consumes. The frontend's "Download JSON"
/// button hits this endpoint. Returns 404 if the binary was built
/// without the evidence service (mock-only path) or if the packet
/// is unknown.
async fn get_packet_json(
    State(state): State<Arc<AppState>>,
    Path(packet_id): Path<uuid::Uuid>,
) -> Result<Response, (StatusCode, String)> {
    let sealed = state.sealed.get(&packet_id).ok_or((
        StatusCode::NOT_FOUND,
        format!("sealed packet {packet_id} not found"),
    ))?;
    let bytes = serde_json::to_vec_pretty(&*sealed).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("serialize SealedPacket: {e}"),
        )
    })?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::CONTENT_DISPOSITION,
            format!(
                "attachment; filename=\"themis-{}-{}.json\"",
                sealed.tenant_id, sealed.invoice_id
            ),
        )
        .body(Body::from(bytes))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::room::MockBandRoom;
    use crate::tenants::TenantRegistry;
    use axum::body::to_bytes;
    use axum::http::Request;
    use std::collections::HashMap;
    use std::sync::Arc;
    use themis_agents::traits::Agent;
    use tower::util::ServiceExt;

    /// Stub agent that returns a canned decision.
    struct StubAgent(&'static str, themis_agents::decision::DecisionType);
    #[async_trait::async_trait]
    impl Agent for StubAgent {
        fn name(&self) -> &'static str {
            self.0
        }
        async fn process(
            &self,
            ctx: themis_agents::traits::AgentContext,
        ) -> Result<themis_agents::decision::AgentDecision, themis_agents::decision::AgentError>
        {
            Ok(themis_agents::decision::AgentDecision {
                agent_id: self.0.to_string(),
                tenant_id: ctx.tenant_id,
                invoice_id: ctx.invoice_id,
                decision_type: self.1,
                confidence: 0.9,
                reasoning: "ok".to_string(),
                timestamp_ms: 0,
                payload: serde_json::json!({"outcome": "approve"}),
            })
        }
    }

    fn build_state() -> AppState {
        let rooms: Arc<dyn crate::room::BandRoom> = MockBandRoom::new().into_arc();
        let tenants = Arc::new(TenantRegistry::with_default_tenants());
        let mut agents: HashMap<String, Arc<dyn Agent>> = HashMap::new();
        for (n, dt) in [
            (
                "extractor",
                themis_agents::decision::DecisionType::Extracted,
            ),
            (
                "po_matcher",
                themis_agents::decision::DecisionType::PoMatched,
            ),
            (
                "fraud_auditor",
                themis_agents::decision::DecisionType::FraudAssessed,
            ),
            (
                "gaap_classifier",
                themis_agents::decision::DecisionType::GaapClassified,
            ),
            (
                "provenance_signer",
                themis_agents::decision::DecisionType::ProvenanceSigned,
            ),
            (
                "demo_narrator",
                themis_agents::decision::DecisionType::Narrated,
            ),
            (
                "regression_tester",
                themis_agents::decision::DecisionType::RegressionResult,
            ),
            (
                "audit_watchdog",
                themis_agents::decision::DecisionType::WatchdogAlert,
            ),
        ] {
            agents.insert(n.to_string(), Arc::new(StubAgent(n, dt)));
        }
        let orch = crate::orchestrator::Orchestrator::new(
            rooms,
            agents,
            crate::router::LlmBackendRouter::with_default_routing(HashMap::new()),
            tenants,
        );
        AppState {
            orchestrator: std::sync::Arc::new(tokio::sync::Mutex::new(orch)),
            event_bus: std::sync::Arc::new(EventBus::new(64)),
            compliance: std::sync::Arc::new(themis_compliance::service::ComplianceService::new()),
            reports: DashMap::new(),
            packets: DashMap::new(),
            sealed: DashMap::new(),
        }
    }

    #[tokio::test]
    async fn get_index_serves_frontend_html() {
        let state = build_state();
        let app = build_router(state);
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("text/html"));
        let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let s = String::from_utf8_lossy(&body);
        assert!(s.contains("THEMIS"));
    }

    #[tokio::test]
    async fn get_static_assets_serve_correct_content_type() {
        let state = build_state();
        let app = build_router(state);
        for (path, expected_type) in [
            ("/static/tokens.css", "text/css"),
            ("/static/app.css", "text/css"),
            ("/static/app.js", "application/javascript"),
        ] {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "path={path}");
            let ct = resp
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap();
            assert!(ct.starts_with(expected_type), "path={path} ct={ct}");
        }
    }

    #[tokio::test]
    async fn post_invoices_returns_200_with_run_id_and_packet_id() {
        let state = build_state();
        let app = build_router(state.clone());
        let body = serde_json::json!({
            "tenant_id": "stark",
            "invoice_id": "inv-001",
            "raw_b64": "",
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/invoices")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Handler returns Ok(Json(...)) → 200 OK with the body.
        // (Originally this test expected 202 Accepted; the contract is now 200.)
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v.get("run_id").is_some());
        assert!(v.get("packet_id").is_some());
        assert!(v.get("compliance").is_some());
    }

    #[tokio::test]
    async fn post_invoices_publishes_events_to_eventbus() {
        let state = build_state();
        let mut rx = state.event_bus.subscribe();
        let body =
            serde_json::json!({"tenant_id": "stark", "invoice_id": "inv-001", "raw_b64": ""});
        let app = build_router(state.clone());
        let _ = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/invoices")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Drain the bus; expect at least AgentStarted + EvidenceSealed + RunFinished.
        let mut started = false;
        let mut sealed = false;
        let mut finished = false;
        for _ in 0..8 {
            if let Ok(ev) = rx.try_recv() {
                match ev {
                    Event::AgentStarted { .. } => started = true,
                    Event::EvidenceSealed { .. } => sealed = true,
                    Event::RunFinished { .. } => finished = true,
                    _ => {}
                }
            } else {
                break;
            }
        }
        assert!(started);
        assert!(sealed);
        assert!(finished);
    }

    #[tokio::test]
    async fn get_compliance_report_returns_404_for_unknown_run() {
        let state = build_state();
        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/compliance-report/{}", uuid::Uuid::new_v4()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_compliance_report_returns_200_after_post() {
        let state = build_state();
        let app = build_router(state.clone());
        // First POST to populate a report.
        let body =
            serde_json::json!({"tenant_id": "stark", "invoice_id": "inv-001", "raw_b64": ""});
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/invoices")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        let run_id = v["run_id"].as_str().unwrap();
        // Then GET the report.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/compliance-report/{run_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
