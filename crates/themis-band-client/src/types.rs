//! Types for the Band client: room, message, agent identifiers.

use serde::{Deserialize, Serialize};

/// Opaque Band room identifier (string for human-readability).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoomId(pub String);

impl RoomId {
    /// New room id from a string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for RoomId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Opaque message identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

impl MessageId {
    /// New message id from a string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// Opaque agent identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl AgentId {
    /// New agent id from a string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A single Band message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// The agent that sent the message.
    pub from: AgentId,
    /// The message body (plain text or JSON).
    pub body: String,
    /// Other agents mentioned in the message (Band's @mention routing).
    pub mentions: Vec<AgentId>,
    /// Unix epoch ms when the message was posted.
    pub ts_ms: i64,
}
