//! WebSocket event subscriber.
//!
//! Production: `tokio-tungstenite` connects to Band's WS endpoint
//! and yields `BandEvent`s. Tests: `MockWsEventStream` yields canned
//! events from a Vec.

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::types::{AgentId, RoomId};

/// A real-time Band event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BandEvent {
    /// Someone @mentioned an agent in a room.
    MentionReceived {
        /// The room the mention happened in.
        room: RoomId,
        /// The agent that sent the message.
        from: AgentId,
        /// The message body.
        body: String,
        /// Unix epoch ms.
        ts_ms: i64,
    },
    /// The WebSocket disconnected.
    WsDisconnected,
}

/// Trait the orchestrator uses to consume Band's WebSocket stream.
#[async_trait]
pub trait WsEventStream: Send + Sync + 'static {
    /// Wait for the next event. Returns `None` when the stream is
    /// closed (or the WS disconnected permanently).
    async fn next_event(&self) -> Option<BandEvent>;
}

/// In-memory event stream for tests.
pub struct MockWsEventStream {
    events: std::sync::Mutex<std::collections::VecDeque<BandEvent>>,
}

impl MockWsEventStream {
    /// New mock with the given canned events.
    pub fn new(events: Vec<BandEvent>) -> Self {
        Self {
            events: std::sync::Mutex::new(events.into()),
        }
    }

    /// Empty mock (will return `None` immediately).
    pub fn empty() -> Self {
        Self::new(vec![])
    }
}

#[async_trait]
impl WsEventStream for MockWsEventStream {
    async fn next_event(&self) -> Option<BandEvent> {
        let mut g = self.events.lock().unwrap();
        g.pop_front()
    }
}

/// Passthrough router: forwards every event from the source stream
/// to a `mpsc::Receiver`. Used by the orchestrator to fan events
/// out to multiple consumers (BAAAR, Audit Watchdog, etc.).
pub async fn mention_router(
    stream: std::sync::Arc<dyn WsEventStream>,
) -> mpsc::Receiver<BandEvent> {
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        while let Some(event) = stream.next_event().await {
            if tx.send(event).await.is_err() {
                break;
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_yields_events_in_order() {
        let stream = MockWsEventStream::new(vec![
            BandEvent::MentionReceived {
                room: RoomId::new("r1"),
                from: AgentId::new("a"),
                body: "first".to_string(),
                ts_ms: 1,
            },
            BandEvent::MentionReceived {
                room: RoomId::new("r1"),
                from: AgentId::new("b"),
                body: "second".to_string(),
                ts_ms: 2,
            },
        ]);
        let e1 = stream.next_event().await.unwrap();
        let e2 = stream.next_event().await.unwrap();
        assert!(matches!(e1, BandEvent::MentionReceived { .. }));
        assert!(matches!(e2, BandEvent::MentionReceived { .. }));
    }

    #[tokio::test]
    async fn empty_mock_returns_none() {
        let stream = MockWsEventStream::empty();
        assert!(stream.next_event().await.is_none());
    }

    #[tokio::test]
    async fn mention_router_receives_all_events() {
        let stream = std::sync::Arc::new(MockWsEventStream::new(vec![
            BandEvent::MentionReceived {
                room: RoomId::new("r1"),
                from: AgentId::new("a"),
                body: "x".to_string(),
                ts_ms: 1,
            },
            BandEvent::WsDisconnected,
        ]));
        let mut rx = mention_router(stream).await;
        let e1 = rx.recv().await.unwrap();
        assert!(matches!(e1, BandEvent::MentionReceived { .. }));
        let e2 = rx.recv().await.unwrap();
        assert_eq!(e2, BandEvent::WsDisconnected);
    }
}
