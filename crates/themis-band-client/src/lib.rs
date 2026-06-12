//! themis-band-client — Band client wrapper for THEMIS.
//!
//! Subprocess wrapper around the Band Python SDK. Persistent child
//! process per Band room, JSON over stdin/stdout for control
//! plane (`create_room`, `get_history`, `post_message`), WebSocket
//! for real-time @mention events.
//!
//! Production wire is documented in the plan's ADR-001; this
//! skeleton ships the trait + types + mock + Python subprocess
//! bridge + WS event stream. The actual `band-sdk[langgraph]==0.2.11`
//! integration is a follow-up sprint.

#![warn(missing_docs)]

/// Crate version + name.
pub fn version() -> &'static str {
    "themis-band-client"
}

pub mod client;
pub mod error;
pub mod python_bridge;
pub mod types;
pub mod ws;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-band-client");
    }
}
