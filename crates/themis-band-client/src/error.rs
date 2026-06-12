//! Error envelope for the Band client.

use thiserror::Error;

/// Band-side errors.
#[derive(Debug, Error)]
pub enum BandError {
    /// The Python subprocess exited unexpectedly.
    #[error("python exit: {0}")]
    PythonExit(String),
    /// The WebSocket connection dropped.
    #[error("websocket disconnected")]
    WsDisconnect,
    /// The Band API rate-limited us.
    #[error("rate limited: retry after {retry_after_ms}ms")]
    RateLimited {
        /// Milliseconds to wait before retrying.
        retry_after_ms: u64,
    },
    /// Generic transport error (IO, parse, etc.).
    #[error("transport: {0}")]
    Transport(String),
}
