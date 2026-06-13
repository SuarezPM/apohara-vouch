//! BandClient trait + MockBandClient for tests.
//!
//! Production: `PythonBandBridge` (in `python_bridge.rs`) implements
//! this trait by talking to a persistent `python -m band_sdk` child
//! process over JSON lines. Tests: `MockBandClient` is in-memory.

use async_trait::async_trait;
use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::error::BandError;
use crate::types::{AgentId, Message, MessageId, RoomId};

/// The trait the orchestrator uses to talk to Band.
#[async_trait]
pub trait BandClient: Send + Sync + 'static {
    /// Create (or reuse) a Band room. Returns the room id.
    async fn create_room(&self, task_id: Option<&str>) -> Result<RoomId, BandError>;

    /// Read the full history of a room.
    async fn get_history(&self, room: &RoomId) -> Result<Vec<Message>, BandError>;

    /// Post a message to a room. Returns the message id assigned
    /// by Band.
    async fn post_message(
        &self,
        room: &RoomId,
        body: &str,
        mentions: Vec<AgentId>,
    ) -> Result<MessageId, BandError>;

    /// Subscribe to real-time @mention events. Returns a channel
    /// that the orchestrator can poll or `.recv()` on.
    async fn watch_mentions(&self, room: &RoomId) -> Result<mpsc::Receiver<Message>, BandError>;
}

/// In-memory mock for tests. DashMap-backed rooms + per-room
/// broadcast channels for `watch_mentions`.
#[derive(Debug, Default)]
pub struct MockBandClient {
    rooms: DashMap<RoomId, MockRoom>,
}

#[derive(Debug, Default)]
struct MockRoom {
    history: Vec<Message>,
    subscribers: Vec<mpsc::Sender<Message>>,
}

impl MockBandClient {
    /// New empty mock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total messages across all rooms (for tests).
    pub fn total_messages(&self) -> usize {
        self.rooms.iter().map(|r| r.value().history.len()).sum()
    }
}

#[async_trait]
impl BandClient for MockBandClient {
    async fn create_room(&self, task_id: Option<&str>) -> Result<RoomId, BandError> {
        let id = match task_id {
            Some(t) => format!("room:{t}"),
            None => format!("room:{}", uuid::Uuid::new_v4()),
        };
        let room_id = RoomId::new(id);
        self.rooms.entry(room_id.clone()).or_default();
        Ok(room_id)
    }

    async fn get_history(&self, room: &RoomId) -> Result<Vec<Message>, BandError> {
        let entry = self
            .rooms
            .get(room)
            .ok_or_else(|| BandError::Transport(format!("unknown room {room}")))?;
        Ok(entry.value().history.clone())
    }

    async fn post_message(
        &self,
        room: &RoomId,
        body: &str,
        mentions: Vec<AgentId>,
    ) -> Result<MessageId, BandError> {
        let mut entry = self
            .rooms
            .get_mut(room)
            .ok_or_else(|| BandError::Transport(format!("unknown room {room}")))?;
        let msg = Message {
            from: AgentId::new("orchestrator"),
            body: body.to_string(),
            mentions,
            ts_ms: chrono::Utc::now().timestamp_millis(),
        };
        let id = MessageId::new(uuid::Uuid::new_v4().to_string());
        entry.value_mut().history.push(msg.clone());
        // Broadcast to subscribers.
        for tx in &entry.value().subscribers {
            let _ = tx.try_send(msg.clone());
        }
        Ok(id)
    }

    async fn watch_mentions(&self, room: &RoomId) -> Result<mpsc::Receiver<Message>, BandError> {
        let mut entry = self
            .rooms
            .get_mut(room)
            .ok_or_else(|| BandError::Transport(format!("unknown room {room}")))?;
        let (tx, rx) = mpsc::channel(64);
        entry.value_mut().subscribers.push(tx);
        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_create_room_is_idempotent_per_task_id() {
        let c = MockBandClient::new();
        let a = c.create_room(Some("inv-001")).await.unwrap();
        let b = c.create_room(Some("inv-001")).await.unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn mock_post_message_accumulates_history() {
        let c = MockBandClient::new();
        let room = c.create_room(Some("inv-001")).await.unwrap();
        c.post_message(&room, "hello", vec![]).await.unwrap();
        c.post_message(&room, "world", vec![]).await.unwrap();
        let h = c.get_history(&room).await.unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(c.total_messages(), 2);
    }

    #[tokio::test]
    async fn mock_watch_mentions_receives_broadcasts() {
        let c = MockBandClient::new();
        let room = c.create_room(Some("inv-001")).await.unwrap();
        let mut rx = c.watch_mentions(&room).await.unwrap();
        c.post_message(&room, "first", vec![]).await.unwrap();
        c.post_message(&room, "second", vec![]).await.unwrap();
        let m1 = rx.recv().await.unwrap();
        let m2 = rx.recv().await.unwrap();
        assert_eq!(m1.body, "first");
        assert_eq!(m2.body, "second");
    }

    #[tokio::test]
    async fn mock_unknown_room_returns_error() {
        let c = MockBandClient::new();
        let err = c.get_history(&RoomId::new("nope")).await.unwrap_err();
        assert!(matches!(err, BandError::Transport(_)));
    }
}
