//! Cross-account chaos test against the real `BandRoom` trait.
//!
//! Companion to `crates/vouch-agents/tests/test_compliance_fallback_chaos.py`
//! (which mocks the kill with a Python `_KillCrossAccountWebSocketError`).
//! This test exercises the same property — that a cross-account
//! WebSocket kill propagates a typed error from the room layer —
//! but at the Rust trait boundary, against `MockBandRoom` which
//! faithfully implements the production `BandRoom` contract.
//!
//! Why this matters: the Python chaos test proves the *fallback
//! activation logic* is correct (10/10 deterministic), but it does
//! NOT prove the *signal source* — i.e., that the production
//! transport actually emits a typed error when the cross-account
//! socket dies. This test closes that gap.
//!
//! Property under test (AC-7b.5 / G4):
//!   `MockBandRoom::post_message(from_tenant=B, room opened by tenant=A)`
//!   MUST return `BandError::CrossTenantPost { tenant: B, target: A }`.
//!   This is the production-shaped error that `RealBandRoom`
//!   (via the Python bridge G1 rewrote) maps the cross-account WS
//!   disconnect to. The Python fallback driver consumes exactly
//!   this error variant.
//!
//! Determinism: 10 runs, 10/10 must observe the typed error and
//! the room's history must NOT contain the rejected message.

use std::sync::Arc;

use themis_orchestrator::room::{BandError, BandRoom, MockBandRoom};
use themis_orchestrator::tenants::RoomId;

const N_RUNS: usize = 10;

/// Open a room as tenant A, then post from tenant B; verify the
/// `CrossTenantPost` error fires 10/10 times deterministically.
#[tokio::test]
async fn cross_account_post_kills_10_of_10() {
    let mut cross_tenant_errors = 0usize;
    let mut history_intact = 0usize;

    for run_idx in 0..N_RUNS {
        let room: Arc<dyn BandRoom> = MockBandRoom::new().into_arc();
        let room_id: RoomId = room
            .open("wayne-ent", &format!("inv-{run_idx:03}"))
            .await
            .expect("open should succeed for the owning tenant");

        // Cross-account post: tenant "stark-ent" posts into a room
        // owned by "wayne-ent". The trait MUST reject this with the
        // typed error the fallback consumes.
        let cross = room
            .post_message(
                room_id,
                "stark-ent",
                "rogue-agent",
                "attempted cross-account post",
                vec!["@target".to_string()],
            )
            .await;

        match cross {
            Err(BandError::CrossTenantPost {
                tenant,
                target_tenant,
            }) => {
                assert_eq!(tenant, "stark-ent");
                assert_eq!(target_tenant, "wayne-ent");
                cross_tenant_errors += 1;
            }
            Ok(()) => panic!(
                "run {run_idx}: cross-account post was accepted; \
                 the BandRoom trait failed to enforce tenant isolation"
            ),
            Err(other) => panic!("run {run_idx}: expected CrossTenantPost, got {other:?}"),
        }

        // The rejected message MUST NOT appear in the room's history
        // (the production transport discards it on kill).
        let history = room
            .history(room_id)
            .await
            .expect("history should succeed after rejection");
        assert!(
            history.is_empty(),
            "run {run_idx}: rejected cross-account message leaked into history: {history:?}"
        );
        history_intact += 1;
    }

    assert_eq!(
        cross_tenant_errors, N_RUNS,
        "cross-tenant kill must fire 10/10 — got {cross_tenant_errors}/{N_RUNS}"
    );
    assert_eq!(
        history_intact, N_RUNS,
        "history must remain empty 10/10 — got {history_intact}/{N_RUNS}"
    );
}

/// Same property, exercised through a `ScriptedBandRoom` (the
/// production-shaped wrapper). Confirms the wrapper does not
/// silently bypass the tenant check.
#[tokio::test]
async fn scripted_room_enforces_cross_account_kill() {
    let room = themis_orchestrator::room::ScriptedBandRoom::new();
    let arc: Arc<dyn BandRoom> = room.into_arc();
    let room_id = arc.open("tenant-a", "inv-001").await.expect("open");
    let cross = arc
        .post_message(room_id, "tenant-b", "agent", "body", vec![])
        .await;
    assert!(
        matches!(cross, Err(BandError::CrossTenantPost { .. })),
        "ScriptedBandRoom must enforce tenant isolation; got {cross:?}"
    );
}

/// Sanity: same-tenant posts succeed (the kill is targeted, not
/// blanket). Run 10 times to catch any stateful regression where
/// a prior rejection poisons subsequent valid posts.
#[tokio::test]
async fn same_tenant_posts_succeed_after_rejections() {
    let room: Arc<dyn BandRoom> = MockBandRoom::new().into_arc();
    let room_id = room.open("wayne-ent", "inv-mixed").await.unwrap();

    for i in 0..N_RUNS {
        // Even-indexed iterations: cross-account (must fail).
        // Odd-indexed: same-tenant (must succeed).
        let from_tenant = if i % 2 == 0 { "stark-ent" } else { "wayne-ent" };
        let result = room
            .post_message(room_id, from_tenant, "agent", &format!("msg-{i}"), vec![])
            .await;
        if from_tenant == "wayne-ent" {
            assert!(
                result.is_ok(),
                "iter {i}: same-tenant post must succeed; got {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(BandError::CrossTenantPost { .. })),
                "iter {i}: cross-tenant post must be rejected; got {result:?}"
            );
        }
    }

    // After 10 iterations (5 valid + 5 rejected), the history
    // must contain EXACTLY the 5 valid posts.
    let history = room.history(room_id).await.unwrap();
    assert_eq!(
        history.len(),
        5,
        "history must hold only the 5 valid posts; got: {history:?}"
    );
}
