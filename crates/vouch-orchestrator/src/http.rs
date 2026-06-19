//! POST /seal — the Evidence Layer HTTP endpoint.
//!
//! AC-3.2: JSON request `{ case_id, agent_outputs: [...],
//! hash_chain_link }` → JSON response
//! `{ hash, signature_hex, c2pa_manifest }`. The handler:
//!
//! 1. Validates the request shape.
//! 2. Looks up (or derives) the Ed25519 signer for the tenant.
//! 3. Appends a BLAKE3 chain entry.
//! 4. Signs the canonical JSON payload.
//! 5. Builds a C2PA manifest and returns the response.
//!
//! Idempotent in the sense that the same request payload always
//! produces the same response payload (deterministic signing).

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{C2paManifest, Chain, SignerService, EU_AI_ACT_ART12_FIELDS};

/// Maximum request body size (4 MiB).
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// POST /seal request payload. AC-3.2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealRequest {
    /// Case identifier (correlates to a specific invoice + tenant).
    pub case_id: String,
    /// Tenant identifier (the Ed25519 key owner).
    pub tenant_id: String,
    /// One decision per agent that contributed.
    pub agent_outputs: Vec<AgentOutputHttp>,
    /// Optional explicit hash-chain link (the BLAKE3 root of
    /// the chain the packet extends). When None, the server
    /// generates a fresh chain.
    #[serde(default)]
    pub hash_chain_link: Option<String>,
    /// Reference database (e.g. "stanford-invoicenet-50").
    #[serde(default = "default_reference_database")]
    pub reference_database: String,
    /// Policy version (e.g. "apohara-vouch-1").
    #[serde(default = "default_policy_version")]
    pub policy_version: String,
    /// Optional natural person id.
    #[serde(default)]
    pub natural_person_id: Option<String>,
}

fn default_reference_database() -> String {
    "stanford-invoicenet-50".to_string()
}

fn default_policy_version() -> String {
    "apohara-vouch-1".to_string()
}

/// One agent's contribution to the seal request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentOutputHttp {
    /// Agent id (e.g. "fraud-auditor").
    pub agent_id: String,
    /// Agent's verdict: "approve" | "halt" | "review_required".
    pub verdict: String,
    /// Human-readable summary.
    pub summary: String,
    /// Optional risk score (0.0..=1.0).
    #[serde(default)]
    pub risk_score: Option<f32>,
}

/// POST /seal response payload. AC-3.2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealResponse {
    /// BLAKE3 hash of the canonical JSON payload, hex.
    pub hash: String,
    /// Ed25519 signature of the canonical JSON payload, hex.
    pub signature_hex: String,
    /// Public key of the signer (hex), for offline verification.
    pub public_key_hex: String,
    /// Decision id (UUID).
    pub decision_id: String,
    /// C2PA manifest over the sealed payload.
    pub c2pa_manifest: C2paManifest,
    /// Server-side timestamp (ISO 8601 UTC).
    pub sealed_at: String,
    /// Chain root after this append (hex; deterministic).
    pub chain_root: String,
}

/// Errors from /seal handling.
#[derive(Debug, Error)]
pub enum SealError {
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("signer error: {0}")]
    Signer(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for SealError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            SealError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            SealError::MissingField(m) => (StatusCode::BAD_REQUEST, (*m).to_string()),
            SealError::Signer(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
            SealError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
        };
        (status, Json(serde_json::json!({"error": msg}))).into_response()
    }
}

/// Per-tenant chain state held by the AppState. Each tenant
/// has its own `Mutex<Chain>` so concurrent appends across
/// tenants don't serialize on a single lock.
#[derive(Debug, Default)]
pub struct ChainRegistry {
    chains: std::sync::Mutex<std::collections::HashMap<String, std::sync::Mutex<Chain>>>,
}

impl ChainRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `payload` to the chain for `tenant_id` (creating
    /// the chain if absent). Returns the chain root after append.
    pub fn append(&self, tenant_id: &str, payload: &str) -> Result<String, ChainRegistryError> {
        let mut map = self.chains.lock().expect("chains poisoned");
        let entry = map
            .entry(tenant_id.to_string())
            .or_insert_with(|| std::sync::Mutex::new(Chain::new()));
        #[allow(clippy::mut_mutex_lock)] // chain.append needs &mut self
        let mut chain = entry.lock().expect("chain poisoned");
        chain
            .append(payload)
            .map_err(|e| ChainRegistryError::Append(format!("{e:?}")))?;
        Ok(chain.root())
    }

    /// Length of the chain for `tenant_id` (0 if absent).
    pub fn len(&self, tenant_id: &str) -> usize {
        let map = self.chains.lock().expect("chains poisoned");
        map.get(tenant_id)
            .map(|c| c.lock().expect("chain poisoned").len())
            .unwrap_or(0)
    }

    /// Verify the chain for `tenant_id`.
    pub fn verify(&self, tenant_id: &str) -> Result<(), ChainRegistryError> {
        let map = self.chains.lock().expect("chains poisoned");
        match map.get(tenant_id) {
            Some(c) => c
                .lock()
                .expect("chain poisoned")
                .verify()
                .map_err(|e| ChainRegistryError::Verify(format!("{e:?}"))),
            None => Ok(()),
        }
    }
}

/// Errors from chain-registry operations.
#[derive(Debug, Error)]
pub enum ChainRegistryError {
    #[error("append failed: {0}")]
    Append(String),
    #[error("verify failed: {0}")]
    Verify(String),
}

/// Application state shared by all routes.
#[derive(Clone)]
pub struct AppState {
    /// Per-tenant BLAKE3 chains.
    pub chains: Arc<ChainRegistry>,
}

impl AppState {
    /// New empty state.
    pub fn new() -> Self {
        Self {
            chains: Arc::new(ChainRegistry::new()),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Healthcheck handler.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "vouch-orchestrator",
        "version": env!("CARGO_PKG_VERSION"),
        "endpoints": ["POST /seal"],
    }))
}

/// POST /seal handler. AC-3.2.
async fn seal(
    State(state): State<AppState>,
    Json(req): Json<SealRequest>,
) -> Result<Json<SealResponse>, SealError> {
    // Validate.
    if req.case_id.is_empty() {
        return Err(SealError::MissingField("case_id"));
    }
    if req.tenant_id.is_empty() {
        return Err(SealError::MissingField("tenant_id"));
    }
    if req.agent_outputs.is_empty() {
        return Err(SealError::MissingField("agent_outputs"));
    }
    // Build the canonical JSON payload (deterministic ordering).
    let canonical_payload = serde_json::json!({
        "case_id": req.case_id,
        "tenant_id": req.tenant_id,
        "agent_outputs": req.agent_outputs,
        "hash_chain_link": req.hash_chain_link,
        "reference_database": req.reference_database,
        "policy_version": req.policy_version,
        "natural_person_id": req.natural_person_id,
        "sealed_at": Utc::now().to_rfc3339(),
        "eu_ai_act_art12_fields": EU_AI_ACT_ART12_FIELDS,
    });
    let canonical_bytes = serde_json::to_vec(&canonical_payload)
        .map_err(|e| SealError::Internal(format!("serialize: {e}")))?;

    // BLAKE3 hash.
    let hash = blake3::hash(&canonical_bytes);
    let hash_hex = hash.to_hex().to_string();

    // Ed25519 sign.
    let signer = SignerService::for_tenant(&req.tenant_id)
        .map_err(|e| SealError::Signer(format!("{e:?}")))?;
    let signature_hex = signer.sign_hex(&canonical_bytes);
    let public_key_hex = signer.public_key_hex();

    // Chain append.
    let chain_root = state
        .chains
        .append(&req.tenant_id, &hash_hex)
        .map_err(|e| SealError::Internal(format!("chain: {e}")))?;

    // C2PA manifest.
    let decision_id = Uuid::new_v4().to_string();
    let c2pa_manifest = C2paManifest::build(
        "vouch-orchestrator",
        &signature_hex,
        req.hash_chain_link.clone(),
    );

    Ok(Json(SealResponse {
        hash: hash_hex,
        signature_hex,
        public_key_hex,
        decision_id,
        c2pa_manifest,
        sealed_at: Utc::now().to_rfc3339(),
        chain_root,
    }))
}

/// Build the Axum router with `/health` + `POST /seal`.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/seal", post(seal))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> SealRequest {
        SealRequest {
            case_id: "case-001".into(),
            tenant_id: "stark".into(),
            agent_outputs: vec![AgentOutputHttp {
                agent_id: "fraud-auditor".into(),
                verdict: "halt".into(),
                summary: "secret detected".into(),
                risk_score: Some(0.92),
            }],
            hash_chain_link: None,
            reference_database: "stanford-invoicenet-50".into(),
            policy_version: "apohara-vouch-1".into(),
            natural_person_id: None,
        }
    }

    #[test]
    fn seal_request_round_trips_json() {
        let req = sample_request();
        let s = serde_json::to_string(&req).unwrap();
        let back: SealRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn seal_response_round_trips_json() {
        let resp = SealResponse {
            hash: "abc".into(),
            signature_hex: "deadbeef".repeat(16),
            public_key_hex: "00".repeat(32),
            decision_id: Uuid::new_v4().to_string(),
            c2pa_manifest: C2paManifest::build("vouch-orchestrator", "sig", None),
            sealed_at: Utc::now().to_rfc3339(),
            chain_root: "0".repeat(64),
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: SealResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn chain_registry_isolates_tenants() {
        let reg = ChainRegistry::new();
        reg.append("stark", "a").unwrap();
        reg.append("stark", "b").unwrap();
        reg.append("wayne", "x").unwrap();
        assert_eq!(reg.len("stark"), 2);
        assert_eq!(reg.len("wayne"), 1);
        reg.verify("stark").unwrap();
    }

    #[test]
    fn router_builds_with_default_state() {
        let state = AppState::new();
        let _router = build_router(state);
    }

    #[tokio::test]
    async fn seal_handler_returns_400_on_empty_case_id() {
        let state = AppState::new();
        let mut req = sample_request();
        req.case_id = String::new();
        let result = seal(State(state), Json(req)).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SealError::MissingField("case_id")
        ));
    }
}
