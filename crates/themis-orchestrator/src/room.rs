//! BandRoom trait + MockBandRoom for tests.
//!
//! The trait is what the orchestrator uses to talk to Band. In
//! production it's the subprocess wrapper around the Band Python
//! SDK (in `themis-band-client`); for tests we ship an in-memory
//! `MockBandRoom` that records every message and enforces the
//! cross-tenant guard.

use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use thiserror::Error;

use crate::tenants::{RoomId, TenantError};

/// A single message in a Band room.
#[derive(Debug, Clone, PartialEq)]
pub struct BandMessage {
    /// The agent that sent the message.
    pub from: String,
    /// The message body (plain text or JSON).
    pub body: String,
    /// Other agents mentioned in the message (Band's @mention
    /// routing primitive).
    pub mentions: Vec<String>,
    /// Unix epoch ms when the message was posted.
    pub ts_ms: i64,
}

/// Band-side errors.
#[derive(Debug, Error)]
pub enum BandError {
    /// Unknown room id.
    #[error("unknown room: {0}")]
    UnknownRoom(RoomId),
    /// Cross-tenant post_message attempt.
    #[error("cross-tenant post denied: tenant={tenant} tried to post to {target_tenant}'s room")]
    CrossTenantPost {
        /// The tenant that attempted the post.
        tenant: String,
        /// The tenant that owns the room.
        target_tenant: String,
    },
    /// Other (e.g. Python subprocess died). Unused by Mock.
    #[error("band transport error: {0}")]
    Transport(String),
}

impl From<TenantError> for BandError {
    fn from(e: TenantError) -> Self {
        match e {
            TenantError::UnknownTenant(_) => BandError::Transport(format!("tenant: {e}")),
            TenantError::CrossTenantAccess { tenant, target_tenant } => {
                BandError::CrossTenantPost { tenant, target_tenant }
            }
        }
    }
}

/// The trait the orchestrator uses to talk to Band. Backed in
/// production by `themis-band-client` (subprocess wrapper); in
/// tests by `MockBandRoom`.
#[async_trait]
pub trait BandRoom: Send + Sync + 'static {
    /// Open a room (or reuse an existing one) for the given tenant.
    async fn open(
        &self,
        tenant_id: &str,
        invoice_id: &str,
    ) -> Result<RoomId, BandError>;

    /// Post a message to a room. Returns the message id.
    async fn post_message(
        &self,
        room: RoomId,
        from_tenant: &str,
        from_agent: &str,
        body: &str,
        mentions: Vec<String>,
    ) -> Result<(), BandError>;

    /// Read the full history of a room.
    async fn history(&self, room: RoomId) -> Result<Vec<BandMessage>, BandError>;

    /// Close a room (no-op in Mock; in production it deletes the
    /// room from Band's servers).
    async fn close(&self, room: RoomId) -> Result<(), BandError>;
}

/// In-memory Band client for tests. Uses a `DashMap<RoomId, Room>`.
#[derive(Debug, Default)]
pub struct MockBandRoom {
    rooms: DashMap<RoomId, MockRoom>,
}

/// In-memory room state. `owner_tenant` is the tenant that opened
/// the room; `from_tenant` on every post_message must match.
#[derive(Debug)]
struct MockRoom {
    owner_tenant: String,
    history: Vec<BandMessage>,
}

impl MockBandRoom {
    /// New empty mock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap in an `Arc<dyn BandRoom>` for use in the orchestrator.
    pub fn into_arc(self) -> Arc<dyn BandRoom> {
        Arc::new(self)
    }

    /// Number of rooms currently held.
    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }
}

#[async_trait]
impl BandRoom for MockBandRoom {
    async fn open(&self, tenant_id: &str, invoice_id: &str) -> Result<RoomId, BandError> {
        // Deterministic room id from (tenant, invoice) for test
        // idempotency. Production would call Band SDK which
        // deduplicates server-side.
        let namespace = uuid::Uuid::NAMESPACE_OID;
        let room_id = RoomId(uuid::Uuid::new_v5(
            &namespace,
            format!("{tenant_id}:{invoice_id}").as_bytes(),
        ));
        self.rooms
            .entry(room_id)
            .or_insert_with(|| MockRoom {
                owner_tenant: tenant_id.to_string(),
                history: Vec::new(),
            });
        Ok(room_id)
    }

    async fn post_message(
        &self,
        room: RoomId,
        from_tenant: &str,
        from_agent: &str,
        body: &str,
        mentions: Vec<String>,
    ) -> Result<(), BandError> {
        let mut entry = self
            .rooms
            .get_mut(&room)
            .ok_or(BandError::UnknownRoom(room))?;
        if entry.owner_tenant != from_tenant {
            return Err(BandError::CrossTenantPost {
                tenant: from_tenant.to_string(),
                target_tenant: entry.owner_tenant.clone(),
            });
        }
        entry.history.push(BandMessage {
            from: from_agent.to_string(),
            body: body.to_string(),
            mentions,
            ts_ms: chrono::Utc::now().timestamp_millis(),
        });
        Ok(())
    }

    async fn history(&self, room: RoomId) -> Result<Vec<BandMessage>, BandError> {
        let entry = self.rooms.get(&room).ok_or(BandError::UnknownRoom(room))?;
        Ok(entry.history.clone())
    }

    async fn close(&self, _room: RoomId) -> Result<(), BandError> {
        // No-op for the mock — production would call Band SDK.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_creates_a_new_room() {
        let m = MockBandRoom::new();
        let room = m.open("stark", "inv-001").await.unwrap();
        assert_eq!(m.room_count(), 1);
        // Deterministic: same (tenant, invoice) returns same id.
        let room2 = m.open("stark", "inv-001").await.unwrap();
        assert_eq!(room, room2);
        // Different invoice → different room.
        let room3 = m.open("stark", "inv-002").await.unwrap();
        assert_ne!(room, room3);
    }

    #[tokio::test]
    async fn post_message_accumulates_history() {
        let m = MockBandRoom::new();
        let room = m.open("stark", "inv-001").await.unwrap();
        m.post_message(room, "stark", "extractor", "parsed", vec!["po_matcher".to_string()])
            .await
            .unwrap();
        m.post_message(room, "stark", "po_matcher", "matched", vec!["fraud_auditor".to_string()])
            .await
            .unwrap();
        let h = m.history(room).await.unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].from, "extractor");
        assert_eq!(h[1].from, "po_matcher");
    }

    #[tokio::test]
    async fn cross_tenant_post_is_rejected() {
        let m = MockBandRoom::new();
        let room = m.open("stark", "inv-001").await.unwrap();
        // wayne tries to post to stark's room.
        let err = m
            .post_message(room, "wayne", "extractor", "x", vec![])
            .await
            .unwrap_err();
        assert!(matches!(err, BandError::CrossTenantPost { .. }));
        // The message is NOT in history.
        let h = m.history(room).await.unwrap();
        assert!(h.is_empty());
    }

    #[tokio::test]
    async fn history_unknown_room_returns_error() {
        let m = MockBandRoom::new();
        let err = m.history(RoomId::new()).await.unwrap_err();
        assert!(matches!(err, BandError::UnknownRoom(_)));
    }

    #[tokio::test]
    async fn close_is_a_noop() {
        let m = MockBandRoom::new();
        let room = m.open("stark", "inv-001").await.unwrap();
        m.close(room).await.unwrap();
        // The room is still readable.
        assert!(m.history(room).await.is_ok());
    }

    #[tokio::test]
    async fn mentions_propagate_to_history() {
        let m = MockBandRoom::new();
        let room = m.open("stark", "inv-001").await.unwrap();
        m.post_message(
            room,
            "stark",
            "extractor",
            "extracted",
            vec!["po_matcher".to_string(), "fraud_auditor".to_string()],
        )
        .await
        .unwrap();
        let h = m.history(room).await.unwrap();
        assert_eq!(h[0].mentions, vec!["po_matcher", "fraud_auditor"]);
    }
}
