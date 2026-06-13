//! RFC 3161 timestamp — trait + mock TSA.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp {
    pub time: i64,
    pub accuracy_ms: i64,
    pub tsa_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampResponse {
    pub time: i64,
    pub accuracy_ms: i64,
    pub raw_der: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum TsError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("timeout after {0:?}")]
    Timeout(Duration),
}

#[async_trait]
pub trait TimestampAuthority: Send + Sync + 'static {
    async fn stamp(&self, hash_hex: &str) -> Result<TimestampResponse, TsError>;
    fn verify(&self, response: &TimestampResponse, hash_hex: &str) -> bool;
    fn url(&self) -> &str;
}

pub struct MockTimestampAuthority {
    url: String,
}

impl MockTimestampAuthority {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

#[async_trait]
impl TimestampAuthority for MockTimestampAuthority {
    async fn stamp(&self, _hash_hex: &str) -> Result<TimestampResponse, TsError> {
        Ok(TimestampResponse {
            time: chrono::Utc::now().timestamp(),
            accuracy_ms: 1000,
            raw_der: Vec::new(),
        })
    }
    fn verify(&self, _response: &TimestampResponse, _hash_hex: &str) -> bool {
        true
    }
    fn url(&self) -> &str {
        &self.url
    }
}

impl std::fmt::Debug for MockTimestampAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockTimestampAuthority")
            .field("url", &self.url)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_returns_current_time_within_one_second() {
        let tsa = MockTimestampAuthority::new("https://mock.tsa.local");
        let before = chrono::Utc::now().timestamp();
        let resp = tsa.stamp("deadbeef").await.unwrap();
        let after = chrono::Utc::now().timestamp();
        assert!(resp.time >= before);
        assert!(resp.time <= after);
    }

    #[tokio::test]
    async fn mock_accuracy_is_1000_ms() {
        let tsa = MockTimestampAuthority::new("https://mock.tsa.local");
        let resp = tsa.stamp("x").await.unwrap();
        assert_eq!(resp.accuracy_ms, 1000);
    }

    #[test]
    fn mock_verify_returns_true() {
        let tsa = MockTimestampAuthority::new("https://mock.tsa.local");
        let resp = TimestampResponse {
            time: 1_700_000_000,
            accuracy_ms: 1000,
            raw_der: Vec::new(),
        };
        assert!(tsa.verify(&resp, "x"));
    }

    #[test]
    fn mock_url_returns_constructor_arg() {
        let tsa = MockTimestampAuthority::new("https://freetsa.org");
        assert_eq!(tsa.url(), "https://freetsa.org");
    }
}
