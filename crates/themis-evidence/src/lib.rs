//! themis-evidence — cryptographic Evidence Packet for THEMIS.
//!
//! Ed25519 signing (`ed25519-dalek`), BLAKE3 hash chain, RFC 3161
//! timestamp (FreeTSA), Rekor v2 anchoring. Multi-tenant key
//! isolation: 2 fictitious companies (Stark / Wayne) with distinct
//! keypairs, baked at compile time via `include_bytes!` to survive
//! Vercel's ephemeral filesystem.
//!
//! The `themis-verify` binary replaces `openssl dgst -sha512` for
//! Ed25519 signatures (openssl does not list ed25519 in its digest
//! registry, so the spec's original verify command was incorrect).
//!
//! Real impl arrives in the follow-up sprint (Phase C of the plan).
//! This crate exists to anchor the workspace layout for US-001.

#![warn(missing_docs)]

/// Crate version + name. Used by US-001 acceptance test.
pub fn version() -> &'static str {
    "themis-evidence"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-evidence");
    }
}
