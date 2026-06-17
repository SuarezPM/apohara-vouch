//! Integration test for US-A4: a sealed packet with a Rekor entry
//! round-trips through serde_json and the `rekor_entry` field is
//! preserved on the wire.
//!
//! This test lives in the orchestrator crate (rather than the
//! evidence crate's own `tests/`) because the orchestrator's
//! `process_invoice_sealed` is the production caller. The unit
//! test for the seal method itself lives in
//! `crates/themis-evidence/src/packet.rs::tests`.

use std::sync::Arc;

use themis_evidence::packet::EvidenceService;
use themis_evidence::rekor::{MockRekorClient, RekorClient, RekorEntry};
use themis_evidence::timestamp::{MockTimestampAuthority, TimestampAuthority};
use themis_orchestrator::test_support::{
    build_orchestrator_with_evidence, fixtures_dir, DemoInvoice,
};

#[allow(unused_imports)]
use async_trait::async_trait;

fn tsa() -> Arc<dyn TimestampAuthority> {
    Arc::new(MockTimestampAuthority::new("https://mock.tsa.local"))
}

fn load_fixture(name: &str) -> DemoInvoice {
    let path = fixtures_dir().join(name);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("failed to parse fixture {}: {e}", path.display()))
}

/// Build a 2-tenant evidence-service map (stark + wayne) backed
/// by the per-tenant baked Ed25519 seeds. Mirrors the production
/// binary's wiring in `themis-orchestrator.rs::main`.
fn evidence_map() -> std::collections::HashMap<String, EvidenceService> {
    let mut m = std::collections::HashMap::new();
    for tenant in ["stark", "wayne"] {
        let svc = EvidenceService::for_tenant(tenant, tsa())
            .expect("baked tenant must have a key");
        m.insert(tenant.to_string(), svc);
    }
    m
}

#[tokio::test]
async fn sealed_packet_with_rekor_entry_round_trips_through_json() {
    let mut svc = EvidenceService::from_seed("stark", [0xA1; 32], tsa());
    let rekor = MockRekorClient::new();

    let payload = r#"{"invoice_id":"inv-rekor-1","tenant":"stark","vendor":"ACME","amount_cents":4242}"#;
    let hash_hex = blake3::hash(payload.as_bytes()).to_hex().to_string();
    let entry = rekor.anchor(&hash_hex, "stark").await.unwrap();

    let sealed = svc.seal("inv-rekor-1", payload, Some(entry)).await.unwrap();

    // The field is populated.
    let carried = sealed
        .rekor_entry
        .as_ref()
        .expect("rekor_entry should be Some");
    assert!(!carried.uuid.is_empty());
    assert!(!carried.bundle_url.is_empty());

    // Round-trip through JSON — the field must survive serialization.
    let json = serde_json::to_string(&sealed).expect("serialize");
    assert!(
        json.contains("\"rekor_entry\""),
        "serialized packet must include rekor_entry key (got: {json})"
    );

    let parsed: themis_evidence::packet::SealedPacket =
        serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed.rekor_entry.as_ref().unwrap().uuid, carried.uuid);
    assert_eq!(parsed.rekor_entry.as_ref().unwrap().log_index, carried.log_index);
}

/// US-A5: `process_invoice_sealed` propagates the inner
/// `process_invoice`'s Rekor entry into the `SealedPacket`. With
/// a `MockRekorClient` wired in, the run produces a `SealedPacket`
/// whose `rekor_entry` is `Some`.
#[tokio::test]
async fn process_invoice_sealed_passes_rekor_entry_to_seal() {
    // Use an APPROVED fixture so the run completes (HALT fixtures
    // short-circuit before sealing).
    let f = load_fixture("wayne-001.json");
    let rekor: Arc<dyn RekorClient> = Arc::new(MockRekorClient::new());
    let orch = build_orchestrator_with_evidence(&f, None, Some(rekor), evidence_map());

    let (_signed, sealed) = orch
        .process_invoice_sealed("wayne", "wayne-001", br#"{"vendor":"ACME"}"#.to_vec())
        .await
        .expect("sealed run succeeds with mock rekor + mock tsa");
    let sealed = sealed.expect("orchestrator was built with evidence map");
    assert!(
        sealed.rekor_entry.is_some(),
        "process_invoice_sealed must propagate the inner Rekor entry to the SealedPacket"
    );
}

/// US-A5 graceful degradation: when no Rekor client is wired,
/// `process_invoice_sealed` still completes and the
/// `SealedPacket.rekor_entry` is `None`.
#[tokio::test]
async fn process_invoice_sealed_graceful_degrade_when_anchor_returns_none() {
    let f = load_fixture("wayne-001.json");
    let orch = build_orchestrator_with_evidence(&f, None, None, evidence_map());

    let (_signed, sealed) = orch
        .process_invoice_sealed("wayne", "wayne-001", br#"{"vendor":"ACME"}"#.to_vec())
        .await
        .expect("sealed run must succeed even without a Rekor client");
    let sealed = sealed.expect("orchestrator was built with evidence map");
    assert!(
        sealed.rekor_entry.is_none(),
        "rekor_entry must be None when no Rekor client is configured"
    );
}

// --- US-A6: v2 path integration tests ---
//
// The v2 Rekor backend is the production transparency-log wire-up
// (see ADR 0010). These tests cover the three acceptance scenarios
// for the sealed-packet / v2 path:
//
//   1. graceful degradation on a transport error (default CI)
//   2. propagation of a successful v2 anchor into the SealedPacket
//      (default CI; uses an in-process RekorClient stub)
//   3. end-to-end round-trip against a local Rekor v2 docker
//      container (`#[ignore]`; manual only)
//
// ENV_LOCK serializes the env-mutating tests (cargo test runs in
// parallel; std::env is process-global). Mirrors the pattern in
// `llm_backend::tests` and `rekor_backend::tests`.
use std::sync::Mutex;
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Test stub for the v2 anchor path. Returns a pre-canned
/// `RekorEntry` from `anchor()`, lets the `verify()` half of
/// the trait be a no-op pass-through. Constructed inline in each
/// test that needs it.
struct StubRekorClient {
    entry: RekorEntry,
}

impl std::fmt::Debug for StubRekorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StubRekorClient")
            .field("entry_uuid", &self.entry.uuid)
            .finish()
    }
}

#[async_trait]
impl RekorClient for StubRekorClient {
    async fn anchor(
        &self,
        _blake3_hash_hex: &str,
        _tenant_id: &str,
    ) -> Result<RekorEntry, themis_evidence::rekor::RekorError> {
        Ok(self.entry.clone())
    }
    async fn verify(&self, _entry: &RekorEntry, _blake3_hash_hex: &str) -> bool {
        true
    }
}

/// US-A6 Test 1: v2 path with a closed port. The orchestrator
/// should gracefully degrade — the run succeeds, and the
/// `SealedPacket.rekor_entry` is `None`. The gRPC `anchor()` call
/// fails (transport error) and `anchor_in_rekor` swallows it.
#[tokio::test]
async fn rekor_v2_path_graceful_degradation_on_grpc_error() {
    // The orchestrator is built with a `RekorV2Client` pointing
    // at a closed port (`http://127.0.0.1:1` → no listener).
    // `connect_lazy` succeeds, so construction is OK; the error
    // surfaces only when the unary `create_entry` request lands.
    let v2: Arc<dyn RekorClient> = Arc::new(
        themis_evidence::rekor_v2::RekorV2Client::with_endpoint("127.0.0.1:1", false)
            .expect("v2 client construction is lazy (no I/O)"),
    );

    // Use an APPROVED fixture so the run completes; HALT fixtures
    // short-circuit before sealing.
    let f = load_fixture("wayne-001.json");
    let orch = build_orchestrator_with_evidence(&f, None, Some(v2), evidence_map());

    let (signed, sealed) = orch
        .process_invoice_sealed("wayne", "wayne-001", br#"{"vendor":"ACME"}"#.to_vec())
        .await
        .expect("sealed run must succeed even when v2 Rekor is unreachable");

    // The run itself never panics or errors — graceful
    // degradation. The inner SignedPacket and SealedPacket are
    // both produced, but neither carries a rekor_entry.
    assert!(
        signed.rekor_entry.is_none(),
        "SignedPacket.rekor_entry must be None when the v2 anchor fails"
    );
    let sealed = sealed.expect("orchestrator was built with evidence map");
    assert!(
        sealed.rekor_entry.is_none(),
        "SealedPacket.rekor_entry must be None when the v2 anchor fails (graceful degradation)"
    );
}

/// US-A6 Test 2: v2 path with a successful anchor. We use a
/// `StubRekorClient` returning a deterministic `RekorEntry` —
/// the same wire shape a real v2 server would surface (uuid +
/// bundle_url). The orchestrator's `process_invoice_sealed` is
/// the only behavior under test; the gRPC client itself is
/// covered by the 5 unit tests in `rekor_v2::tests`.
#[tokio::test]
async fn rekor_v2_path_propagates_to_sealed_packet() {
    // A deterministic synthetic entry — what a real v2 server
    // would return. UUID is the sigstore v2 format (32 hex
    // chars), bundle_url follows the v2 REST gateway shape.
    let synthetic = RekorEntry {
        uuid: "a".repeat(64),
        log_index: 42,
        body_b64: String::new(),
        integrated_time: 1_700_000_000,
        signed_entry_timestamp: String::new(),
        bundle_url: format!(
            "{}/{}",
            themis_evidence::rekor_v2::REKOR_V2_BUNDLE_URL_BASE,
            "a".repeat(64)
        ),
    };
    let stub: Arc<dyn RekorClient> = Arc::new(StubRekorClient {
        entry: synthetic.clone(),
    });

    let f = load_fixture("wayne-001.json");
    let orch = build_orchestrator_with_evidence(&f, None, Some(stub), evidence_map());

    let (signed, sealed) = orch
        .process_invoice_sealed("wayne", "wayne-001", br#"{"vendor":"ACME"}"#.to_vec())
        .await
        .expect("sealed run succeeds with stub Rekor client");

    // The SignedPacket carries the entry (produced inside
    // `process_invoice` via `anchor_in_rekor`).
    let signed_entry = signed
        .rekor_entry
        .as_ref()
        .expect("SignedPacket.rekor_entry must be Some with a successful v2 anchor");
    assert_eq!(signed_entry.uuid, synthetic.uuid, "uuid propagates");
    assert_eq!(signed_entry.log_index, 42, "log_index propagates");

    // The SealedPacket carries the *same* entry (propagated
    // by `process_invoice_sealed` from the SignedPacket).
    let sealed = sealed.expect("orchestrator was built with evidence map");
    let sealed_entry = sealed
        .rekor_entry
        .as_ref()
        .expect("SealedPacket.rekor_entry must be Some when SignedPacket has it");
    assert_eq!(
        sealed_entry.uuid, signed_entry.uuid,
        "SealedPacket.uuid matches SignedPacket.uuid"
    );
    assert_eq!(
        sealed_entry.bundle_url, synthetic.bundle_url,
        "bundle_url follows the v2 REST gateway shape"
    );
    assert!(
        sealed_entry
            .bundle_url
            .starts_with(themis_evidence::rekor_v2::REKOR_V2_BUNDLE_URL_BASE),
        "bundle_url must point at the v2 REST gateway (got: {})",
        sealed_entry.bundle_url
    );
}

/// US-A6 Test 3: end-to-end against a local Rekor v2 container.
/// Manual only — run with:
///   docker run -d --rm -p 8080:8080 \
///     ghcr.io/sigstore/rekor-server:v2.0.0-beta
///   cargo test -p themis-orchestrator --test sealed_packet_rekor \
///     rekor_v2_path_against_local_rekor_populates_entry -- --ignored --nocapture
#[ignore = "requires a local Rekor v2 docker container (see comment)"]
#[tokio::test]
async fn rekor_v2_path_against_local_rekor_populates_entry() {
    // Point the env-gated selector at a local Rekor v2 server.
    // The lazy `connect_lazy` succeeds; the actual unary call
    // exercises the live gRPC plumbing. We set the env vars
    // under the ENV_LOCK guard, then drop it before the await
    // (clippy `await_holding_lock`).
    let client = {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("THEMIS_REKOR_MODE", "v2");
            std::env::set_var("THEMIS_REKOR_ENDPOINT", "127.0.0.1:8080");
        }
        let c = themis_orchestrator::rekor_backend::build_rekor_client();
        assert!(
            format!("{c:?}").contains("RekorV2Client"),
            "env-gated selector should produce a RekorV2Client"
        );
        c
    };

    let f = load_fixture("wayne-001.json");
    let orch = build_orchestrator_with_evidence(&f, None, Some(client), evidence_map());

    let (_signed, sealed) = orch
        .process_invoice_sealed("wayne", "wayne-001", br#"{"vendor":"ACME"}"#.to_vec())
        .await
        .expect("sealed run against a local Rekor v2 must succeed");

    let sealed = sealed.expect("orchestrator was built with evidence map");
    let entry = sealed
        .rekor_entry
        .as_ref()
        .expect("SealedPacket.rekor_entry must be Some when the v2 anchor succeeds");
    // The local Rekor v2 server may use a different base URL
    // (e.g. http://127.0.0.1:8080); we only assert the *shape*
    // matches the v2 spec, not the specific host.
    assert!(
        entry.bundle_url.contains("/api/v2/log/entries/"),
        "bundle_url must contain the v2 REST path (got: {})",
        entry.bundle_url
    );

    // Restore the env so the next test starts from a clean slate.
    let _g = ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::remove_var("THEMIS_REKOR_MODE");
        std::env::remove_var("THEMIS_REKOR_ENDPOINT");
    }
}
