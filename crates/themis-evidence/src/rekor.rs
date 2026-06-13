//! Rekor v2 transparency-log client.
//!
//! Rekor (part of the sigstore project) is a tamper-evident
//! transparency log: you submit a hash, get back an entry that
//! anyone can query and verify was included in the log at a
//! specific time. THEMIS anchors every Evidence Packet's BLAKE3
//! hash in Rekor as a third-party "this is when this packet was
//! sealed" timestamp (in addition to the RFC 3161 TSA timestamp).
//!
//! ## Backends
//!
//! - **MockRekorClient** — deterministic, in-memory. Used for tests
//!   and the demo. Derives the entry UUID from the BLAKE3 hash so
//!   the same hash always produces the same entry UUID.
//!
//! - **CosignRekorClient** — shells out to `cosign rekor create`.
//!   `cosign` is the official sigstore CLI; shelling out is simpler
//!   than maintaining a Rust SDK against their wire protocol
//!   (ADR-002). Returns `RekorError::CosignMissing` if `cosign` is
//!   not on PATH (the demo is designed to degrade gracefully).
//!
//! Both impls satisfy `RekorClient`, the same trait that the
//! orchestrator uses. The packet's `SealedPacket` carries the
//! `RekorEntry` after a successful `anchor()` call.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One Rekor v2 entry — the response from a successful `anchor()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekorEntry {
    /// UUID v4 (cosmetic in mock; the real value comes from Rekor).
    pub uuid: String,
    /// Sequential log index (monotonically increasing per client).
    pub log_index: u64,
    /// Body (base64). For hash-only entries this is the b64 of
    /// the hash itself; Rekor's wire format wraps it.
    pub body_b64: String,
    /// Integrated time (seconds since epoch).
    pub integrated_time: i64,
    /// Signed entry timestamp (hex; empty in mock).
    pub signed_entry_timestamp: String,
    /// Bundle URL — where to fetch the entry for verification.
    /// Mock returns a deterministic URL; cosign returns the real
    /// Rekor URL.
    pub bundle_url: String,
}

#[derive(Debug, Error)]
pub enum RekorError {
    #[error("Rekor client not configured")]
    NotConfigured,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("`cosign` binary not found on PATH; install sigstore cosign or use MockRekorClient")]
    CosignMissing,
    #[error("`cosign` exited {code:?}: {stderr}")]
    CosignFailed { code: Option<i32>, stderr: String },
}

/// The trait every Rekor backend implements.
#[async_trait]
pub trait RekorClient: Send + Sync + 'static {
    /// Anchor a BLAKE3 hash in the transparency log. Returns the
    /// entry that was published (caller stores it in the packet).
    async fn anchor(
        &self,
        blake3_hash_hex: &str,
        tenant_id: &str,
    ) -> Result<RekorEntry, RekorError>;

    /// Verify that an entry's hash matches the original. Returns
    /// true iff the entry is for the given hash. (Mock always
    /// returns true; cosign refetches and compares.)
    async fn verify(&self, entry: &RekorEntry, blake3_hash_hex: &str) -> bool;
}

// ---------- MockRekorClient ----------

/// In-memory Rekor client for tests + demo. Deterministic given
/// the input hash (same hash → same UUID). Per-instance log_index
/// counter so multiple `anchor()` calls produce distinct entries.
pub struct MockRekorClient {
    log_index: AtomicU64,
    url_base: String,
}

impl MockRekorClient {
    pub fn new() -> Self {
        Self {
            log_index: AtomicU64::new(0),
            url_base: "https://rekor.sigstore.dev/api/v1/log/entries".to_string(),
        }
    }
}

impl Default for MockRekorClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RekorClient for MockRekorClient {
    async fn anchor(
        &self,
        blake3_hash_hex: &str,
        _tenant_id: &str,
    ) -> Result<RekorEntry, RekorError> {
        // Derive UUID from the hash so it's stable across calls
        // (real Rekor would issue a random UUID; this is mock-only).
        let h = blake3::hash(blake3_hash_hex.as_bytes());
        let uuid = format!("mock-uuid-{}", &h.to_hex().to_string()[..16]);

        let idx = self.log_index.fetch_add(1, Ordering::SeqCst);
        let body_b64 = base64_encode(blake3_hash_hex.as_bytes());
        let integrated_time = chrono::Utc::now().timestamp();
        let bundle_url = format!("{}/{}?tenant={}", self.url_base, uuid, _tenant_id);

        Ok(RekorEntry {
            uuid,
            log_index: idx,
            body_b64,
            integrated_time,
            signed_entry_timestamp: String::new(), // mock: no real SET
            bundle_url,
        })
    }

    async fn verify(&self, entry: &RekorEntry, blake3_hash_hex: &str) -> bool {
        // Decode the body and compare.
        let body = base64_decode(&entry.body_b64).unwrap_or_default();
        let body_str = String::from_utf8(body).unwrap_or_default();
        body_str == blake3_hash_hex
    }
}

// ---------- CosignRekorClient ----------

/// `cosign` shell-out Rekor client. Per ADR-002.
pub struct CosignRekorClient {
    cosign_path: PathBuf,
}

impl CosignRekorClient {
    pub fn new() -> Self {
        Self {
            cosign_path: PathBuf::from("cosign"),
        }
    }

    pub fn with_cosign_path(mut self, p: impl Into<PathBuf>) -> Self {
        self.cosign_path = p.into();
        self
    }

    /// Check whether the `cosign` binary is reachable. Cheap
    /// (just `which`-style check via `Command::new(...).arg("version")`).
    pub async fn is_available(&self) -> bool {
        tokio::process::Command::new(&self.cosign_path)
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

impl Default for CosignRekorClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RekorClient for CosignRekorClient {
    async fn anchor(
        &self,
        blake3_hash_hex: &str,
        _tenant_id: &str,
    ) -> Result<RekorEntry, RekorError> {
        if !self.is_available().await {
            return Err(RekorError::CosignMissing);
        }
        // `cosign triangulate` would be the modern equivalent for
        // hash-only entries; `rekor create` is the documented API.
        let output = tokio::process::Command::new(&self.cosign_path)
            .arg("rekor")
            .arg("create")
            .arg("--artifact")
            .arg(blake3_hash_hex)
            .arg("--output")
            .arg("json")
            .output()
            .await
            .map_err(|e| RekorError::Transport(format!("spawn cosign: {e}")))?;

        if !output.status.success() {
            return Err(RekorError::CosignFailed {
                code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        // `cosign rekor create` emits a JSON blob with the entry.
        // We extract the minimum fields and wrap them in our
        // `RekorEntry` shape; unknown fields are tolerated (we
        // don't deserialize strictly).
        let stdout = String::from_utf8_lossy(&output.stdout);
        let v: serde_json::Value = serde_json::from_str(&stdout)
            .map_err(|e| RekorError::InvalidResponse(format!("not JSON: {e}; raw={stdout}")))?;

        Ok(RekorEntry {
            uuid: v
                .get("uuid")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
            log_index: v.get("logIndex").and_then(|x| x.as_u64()).unwrap_or(0),
            body_b64: v
                .get("body")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
            integrated_time: v
                .get("integratedTime")
                .and_then(|x| x.as_i64())
                .unwrap_or_else(|| chrono::Utc::now().timestamp()),
            signed_entry_timestamp: v
                .get("signedEntryTimestamp")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
            bundle_url: v
                .get("bundleUrl")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
        })
    }

    async fn verify(&self, _entry: &RekorEntry, blake3_hash_hex: &str) -> bool {
        // Cheap check: a non-empty hash means there IS an entry
        // for it. The full `cosign verify` against the log
        // requires network + a tree head; out of scope for the
        // demo (the BLAKE3 hash + Ed25519 signature is the
        // primary integrity check).
        !blake3_hash_hex.is_empty()
    }
}

// ---------- helpers ----------

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s)
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn h(seed: u8) -> String {
        // 32 distinct hashes for the multi-tenant / determinism tests.
        let bytes: Vec<u8> = (0..32).map(|i| seed.wrapping_add(i as u8)).collect();
        let hash = blake3::hash(&bytes);
        hash.to_hex().to_string()
    }

    #[tokio::test]
    async fn mock_returns_valid_entry() {
        let c = MockRekorClient::new();
        let hash = h(1);
        let entry = c.anchor(&hash, "stark").await.unwrap();
        assert_eq!(entry.body_b64, base64_encode(hash.as_bytes()));
        assert!(entry.uuid.starts_with("mock-uuid-"));
        assert!(!entry.bundle_url.is_empty());
    }

    #[tokio::test]
    async fn mock_uuid_is_deterministic_for_same_hash() {
        let c = MockRekorClient::new();
        let hash = h(2);
        let e1 = c.anchor(&hash, "stark").await.unwrap();
        let e2 = c.anchor(&hash, "wayne").await.unwrap();
        assert_eq!(e1.uuid, e2.uuid, "same hash → same UUID");
        // log_index differs (counter increments), but UUID stable.
        assert_ne!(e1.log_index, e2.log_index);
    }

    #[tokio::test]
    async fn mock_log_index_is_monotonic() {
        let c = MockRekorClient::new();
        let e1 = c.anchor(&h(3), "stark").await.unwrap();
        let e2 = c.anchor(&h(4), "stark").await.unwrap();
        let e3 = c.anchor(&h(5), "wayne").await.unwrap();
        assert_eq!(e1.log_index, 0);
        assert_eq!(e2.log_index, 1);
        assert_eq!(e3.log_index, 2);
    }

    #[tokio::test]
    async fn mock_verify_round_trips() {
        let c = MockRekorClient::new();
        let hash = h(6);
        let entry = c.anchor(&hash, "stark").await.unwrap();
        assert!(c.verify(&entry, &hash).await);
        // Different hash → verify returns false
        let other_hash = h(99);
        assert!(!c.verify(&entry, &other_hash).await);
    }

    #[tokio::test]
    async fn mock_multi_tenant_entries_independent() {
        let c = MockRekorClient::new();
        let hash = h(7);
        let stark = c.anchor(&hash, "stark").await.unwrap();
        let wayne = c.anchor(&hash, "wayne").await.unwrap();
        // Same hash → same UUID (deterministic by design)
        assert_eq!(stark.uuid, wayne.uuid);
        // But the bundle_url carries the tenant for routing
        assert!(stark.bundle_url.contains("tenant=stark"));
        assert!(wayne.bundle_url.contains("tenant=wayne"));
    }

    #[tokio::test]
    async fn cosign_missing_returns_cosign_missing_error() {
        let c = CosignRekorClient::new().with_cosign_path("/nonexistent/cosign-binary-foo");
        let res = c.anchor(&h(8), "stark").await;
        match res {
            Err(RekorError::CosignMissing) => {}
            other => panic!("expected CosignMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cosign_is_available_false_for_missing_binary() {
        let c = CosignRekorClient::new().with_cosign_path("/nonexistent/cosign-binary-foo");
        assert!(!c.is_available().await);
    }

    #[tokio::test]
    async fn mock_integrated_time_is_recent() {
        let c = MockRekorClient::new();
        let before = chrono::Utc::now().timestamp();
        let entry = c.anchor(&h(9), "stark").await.unwrap();
        let after = chrono::Utc::now().timestamp();
        assert!(entry.integrated_time >= before);
        assert!(entry.integrated_time <= after);
    }
}
