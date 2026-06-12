//! themis-compressor — token-compression crate for THEMIS.
//!
//! Rust port of the LLMLingua-2 algorithm (ACL 2024, Microsoft,
//! xlm-roberta-large-meetingbank token-classifier). No PyO3 bindings,
//! no Python sidecar. The compression coordinator orchestrates 4
//! strategies (apc_reuse, compress_and_reuse, compress, passthrough)
//! adapted from Apohara Context Forge's `compression/coordinator.py`.
//!
//! Three variants (short ≤512 words, medium ≤2048, long >2048) with
//! auto-select by word count. The port uses word length as a proxy
//! for the perplexity score — a real model integration is a follow-up
//! sprint (US-003 documents the placeholder explicitly).

#![warn(missing_docs)]

/// Crate version + name. Used by US-001 acceptance test.
pub fn version() -> &'static str {
    "themis-compressor"
}

pub mod classifier;
pub mod coordinator;
pub mod variant;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-compressor");
    }
}
