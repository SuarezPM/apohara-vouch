//! themis-band-client — Band SDK wrapper for THEMIS.
//!
//! Subprocess wrapper around the Band Python SDK 0.2.11. Persistent
//! child process per Band room, JSON over stdin/stdout for control
//! plane (`create_room`, `get_history`, `post_message`), `tokio-tungstenite`
//! for WebSocket @mention events. The `BandClient` trait lets the
//! orchestrator swap in `MockBandClient` for tests without network.
//!
//! Backoff strategy on reconnect: exponential 50ms→100ms→200ms→...→30s
//! with ±20% jitter, idempotent UUIDs on outgoing messages, best-effort
//! session resume via `get_history` re-read.
//!
//! Real impl arrives in the follow-up sprint (Phase A of the plan).
//! This crate exists to anchor the workspace layout for US-001.

#![warn(missing_docs)]

/// Crate version + name. Used by US-001 acceptance test.
pub fn version() -> &'static str {
    "themis-band-client"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-band-client");
    }
}
