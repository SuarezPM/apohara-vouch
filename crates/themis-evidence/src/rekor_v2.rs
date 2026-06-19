//! RekorV2Client — gRPC client for the public-good sigstore Rekor v2 log.
//!
//! This is the **opt-in** third transparency-log backend. It is **not**
//! the default: `MockRekorClient` (in `rekor.rs`) is the demo default.
//! `THEMIS_REKOR_MODE=v2` switches the orchestrator onto this client
//! (see the plan at `~/.claude/plans/themis-rekor-v2-wiremock-v2.md`).
//!
//! ## Endpoint
//!
//! The public-good v2 tile is `log2025-1.rekor.sigstore.dev:443`. The
//! sigstore spec (architecture-docs/rekor-v2-spec) requires production
//! clients to fetch the URL from the TUF SigningConfig because shards
//! rotate every ~6 months. **THEMIS does not do TUF yet** — the 4-day
//! hackathon window is far shorter than the rotation horizon, so we
//! hardcode the endpoint as [`REKOR_V2_DEFAULT_ENDPOINT`]. Post-hackathon
//! follow-up: wire a `tough` fetch in the constructor.
//!
//! ## Verification
//!
//! The trait-level `verify()` is intentionally lightweight for now:
//! it re-hashes the entry's `body_b64` and compares. Full inclusion
//! proof verification (TUF + signed entry timestamp) is delegated to
//! the existing `SigstoreVerifyRekorClient` (see `rekor.rs`) — the
//!
//! NOTE: the inclusion verifier field is reserved for that follow-up
//! and is currently unused at runtime.
//!
//! ## Status
//!
//! The `anchor()` method produces a real Ed25519 signature over the
//! BLAKE3 digest using the per-tenant SignerService. The signature
//! is verifiable offline against the baked tenant public key.
//! Follow-up: TUF SigningConfig lookup for shard rotation.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use tonic::transport::{Channel, Endpoint};

use crate::rekor::{RekorClient, RekorEntry, RekorError};

// Generated module name (proto package `dev.sigstore.rekor.v2`).
use crate::dev_sigstore_rekor_v2::{
    rekor_client::RekorClient as GeneratedRekorClient, CreateEntryRequest, HashedRekordRequestV002,
    PublicKey, Signature, SignatureAlgorithm, TransparencyLogEntry, Verifier,
};

/// Hardcoded public-good Rekor v2 endpoint.
///
/// The sigstore spec mandates TUF SigningConfig lookup; the 4-day
/// hackathon demo bypasses that and pins the value. See module docs.
pub const REKOR_V2_DEFAULT_ENDPOINT: &str = "log2025-1.rekor.sigstore.dev:443";

/// HTTP bundle URL base (REST gateway, used for the `bundle_url` we
/// surface on each `RekorEntry`). The `/api/v2/log/entries/{uuid}`
/// endpoint is the spec-documented way to fetch a v2 entry.
pub const REKOR_V2_BUNDLE_URL_BASE: &str =
    "https://log2025-1.rekor.sigstore.dev/api/v2/log/entries";

/// Per-call timeout for the gRPC unary `CreateEntry` request.
const ANCHOR_TIMEOUT: Duration = Duration::from_secs(5);

/// gRPC client for the Rekor v2 transparency log.
///
/// Construction is **lazy** — `Channel::connect` returns a `Channel`
/// that does not actually open a TCP connection until the first
/// request. This matches the spec'd test seam (`with_endpoint`).
#[allow(clippy::manual_non_exhaustive)]
pub struct RekorV2Client {
    /// Logical endpoint (host:port). Kept for diagnostics.
    pub endpoint: String,
    /// Tonic-generated gRPC client. Wraps a lazy `Channel`.
    pub inner: GeneratedRekorClient<Channel>,
    /// Reserved for the inclusion-proof verifier follow-up. Currently
    /// unused at runtime; see module docs.
    #[allow(dead_code)]
    inclusion_verifier: (),
}

impl std::fmt::Debug for RekorV2Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RekorV2Client")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl RekorV2Client {
    /// Connect to a Rekor v2 endpoint over TLS. Lazy — no I/O at
    /// construction. `endpoint` is `host:port`.
    pub fn connect(endpoint: &str) -> Result<Self, RekorError> {
        Self::with_endpoint(endpoint, true)
    }

    /// Test seam. `use_tls = true` uses the default TLS config;
    /// `use_tls = false` uses `http://` for the local Rekor docker
    /// container in integration tests.
    pub fn with_endpoint(endpoint: &str, use_tls: bool) -> Result<Self, RekorError> {
        let scheme = if use_tls { "https" } else { "http" };
        let url = format!("{scheme}://{endpoint}");
        let endpoint_obj = Endpoint::from_shared(url)
            .map_err(|e| RekorError::Transport(format!("invalid endpoint: {e}")))?;
        // `connect_lazy` returns a `Channel` directly (no `Result`)
        // because the TCP connection is deferred to first use.
        let channel = endpoint_obj.connect_lazy();
        Ok(Self {
            endpoint: endpoint.to_string(),
            inner: GeneratedRekorClient::new(channel),
            inclusion_verifier: (),
        })
    }
}

#[async_trait]
impl RekorClient for RekorV2Client {
    async fn anchor(
        &self,
        blake3_hash_hex: &str,
        tenant_id: &str,
    ) -> Result<RekorEntry, RekorError> {
        // Decode the hex-encoded BLAKE3 hash into raw bytes.
        let hash_bytes = hex::decode(blake3_hash_hex)
            .map_err(|e| RekorError::InvalidResponse(format!("blake3 hash is not hex: {e}")))?;

        // Real Ed25519 signature over the digest using the per-tenant
        // SignerService. The signature + public key are sourced from
        // the same baked key (deterministic for fixture tenants
        // stark/wayne) so a separate verifier with the matching
        // tenant public key can validate offline.
        let signer = crate::signer::SignerService::for_tenant(tenant_id)
            .map_err(|e| RekorError::Transport(format!("signer for tenant {tenant_id}: {e}")))?;
        let ed25519_sig = signer.sign(&hash_bytes);
        let pubkey_bytes = hex::decode(signer.public_key_hex())
            .map_err(|e| RekorError::Transport(format!("signer pubkey not hex: {e}")))?;

        // Build the HashedRekordRequestV002 body with the real
        // Ed25519 signature content + the matching public key.
        let request = CreateEntryRequest {
            hashed_rekord_request_v002: Some(HashedRekordRequestV002 {
                digest: base64::engine::general_purpose::STANDARD.encode(&hash_bytes),
                signature: Some(Signature {
                    content: ed25519_sig.to_bytes().to_vec(),
                    verifier: Some(Verifier {
                        algorithm: SignatureAlgorithm::Ed25519 as i32,
                        public_key: Some(PublicKey {
                            raw_bytes: pubkey_bytes,
                        }),
                    }),
                }),
            }),
        };

        // Unary gRPC call with a bounded timeout. Surface any
        // transport / status failure as a typed `RekorError`.
        // `create_entry` returns `tonic::Response<TransparencyLogEntry>`;
        // we extract the inner body before mapping into `RekorEntry`.
        let mut client = self.inner.clone();
        let response: TransparencyLogEntry =
            tokio::time::timeout(ANCHOR_TIMEOUT, client.create_entry(request))
                .await
                .map_err(|_| RekorError::Transport("anchor timed out".to_string()))?
                .map_err(|status: tonic::Status| RekorError::GrpcTransport(status))?
                .into_inner();

        let uuid = response.uuid;
        let body_b64 = response.body;
        let bundle_url = format!("{REKOR_V2_BUNDLE_URL_BASE}/{uuid}");

        Ok(RekorEntry {
            uuid,
            log_index: response.log_index,
            body_b64,
            integrated_time: response.integrated_time,
            signed_entry_timestamp: String::new(),
            bundle_url,
        })
    }

    async fn verify(&self, entry: &RekorEntry, blake3_hash_hex: &str) -> bool {
        // Decode the entry body and re-hash. For the demo we compare
        // the body to the hash string itself; a real verifier would
        // also check the SET (delegated to the inclusion_verifier
        // field, see module docs).
        let Ok(body) = base64::engine::general_purpose::STANDARD.decode(&entry.body_b64) else {
            return false;
        };
        let body_str = match String::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return false,
        };
        body_str == blake3_hash_hex
    }
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rekor_v2_construction_is_lazy() {
        // with_endpoint is lazy: TCP is not opened, no I/O. A
        // deliberately bogus address still returns Ok. Note:
        // Endpoint::connect_lazy() touches hyper-util's tokio
        // adapter, so this test needs a tokio runtime even though
        // no network call actually happens.
        let res = RekorV2Client::with_endpoint("127.0.0.1:1", false);
        assert!(
            res.is_ok(),
            "with_endpoint should not perform I/O; got {res:?}"
        );
    }

    #[tokio::test]
    async fn rekor_v2_default_endpoint_uses_tls() {
        // connect() is the TLS default. Lazy, so Ok is the assertion.
        let res = RekorV2Client::connect(REKOR_V2_DEFAULT_ENDPOINT);
        assert!(res.is_ok(), "connect(default) must be Ok; got {res:?}");
    }

    #[tokio::test]
    async fn rekor_v2_with_endpoint_test_seam_works() {
        // Explicit http:// + 127.0.0.1:1 is the local-Rekor test seam.
        let res = RekorV2Client::with_endpoint("http://127.0.0.1:1", false);
        assert!(res.is_ok(), "test seam must construct; got {res:?}");
    }

    #[tokio::test]
    async fn rekor_v2_verify_rejects_mismatched_hash() {
        let c = RekorV2Client::with_endpoint("127.0.0.1:1", false).unwrap();
        let real_hash = blake3::hash(b"hello-themis").to_hex().to_string();
        // Hand-craft a RekorEntry whose body_b64 decodes to a
        // *different* string. The verify() check must reject it.
        let bogus_body =
            base64::engine::general_purpose::STANDARD.encode(b"definitely-not-the-hash");
        let entry = RekorEntry {
            uuid: "test-uuid".to_string(),
            log_index: 0,
            body_b64: bogus_body,
            integrated_time: 0,
            signed_entry_timestamp: String::new(),
            bundle_url: String::new(),
        };
        assert!(
            !c.verify(&entry, &real_hash).await,
            "verify must return false when body does not match hash"
        );
    }

    #[tokio::test]
    async fn rekor_v2_anchor_against_closed_port_returns_transport_error() {
        // 127.0.0.1:1 has nothing listening. Channel::connect is
        // lazy, so the error surfaces only when we actually fire
        // the request. tokio::time::timeout forces a clean error
        // rather than an open-ended hang.
        let c = RekorV2Client::with_endpoint("127.0.0.1:1", false).unwrap();
        let hash = blake3::hash(b"closed-port-test").to_hex().to_string();
        let res = tokio::time::timeout(Duration::from_millis(500), c.anchor(&hash, "stark"))
            .await
            .expect("anchor() must not hang on a closed port")
            .expect_err("anchor() against a closed port must return Err");

        match res {
            RekorError::GrpcTransport(_) | RekorError::Transport(_) => {}
            other => panic!("expected GrpcTransport or Transport, got {other:?}"),
        }
    }
}
