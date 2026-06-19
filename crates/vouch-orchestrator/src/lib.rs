//! vouch-orchestrator — HTTP `/seal` endpoint + room lifecycle.
//!
//! AC-3.1, AC-3.2: thin re-export of `themis-orchestrator` plus
//! a stable `vouch-*` HTTP surface (`POST /seal`). The handler
//! takes a `SealRequest`, runs the BAAAR gate + BLAKE3 chain
//! append + Ed25519 seal, and returns a `SealResponse` carrying
//! the packet's hash, signature, and C2PA manifest.

pub mod http;

/// Crate version + name.
pub fn version() -> &'static str {
    "vouch-orchestrator"
}

pub use vouch_aibom::{to_cyclonedx_1_6, Aibom};
/// Re-exported surface for downstream crates.
pub use vouch_chain::{Chain, ChainEntry as VouchChainEntry, ChainError as VouchChainError};
pub use vouch_compliance::{
    ComplianceMap, ComplianceMapper, ComplianceReport, ComplianceService, DoraMapper,
    EuAiActMapper, Framework, NistAiRmfMapper, OwaspAgenticMapper,
};
pub use vouch_evidence::{
    C2paReceipt, EvidenceService, FreeTSAAuthority, MockTimestampAuthority, SealedPacket,
    SignerError, SignerService, TimestampAuthority,
};
pub use vouch_gate::{should_halt, GateInput, Verdict};
pub use vouch_receipt::{
    packet::{AgentOutput, EvidencePacket},
    Art12Coverage, C2paManifest, EU_AI_ACT_ART12_FIELDS,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "vouch-orchestrator");
    }
}
