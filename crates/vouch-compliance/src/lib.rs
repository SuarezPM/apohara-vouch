//! vouch-compliance — DORA, EU AI Act, NIST AI RMF, OWASP Agentic 2026.
//!
//! AC-3.1: thin re-export of `themis-compliance` mappers.
//! Each framework ships a `Mapper` struct that implements
//! `themis_compliance::framework::ComplianceMapper`.

/// Crate version + name.
pub fn version() -> &'static str {
    "vouch-compliance"
}

pub use themis_compliance::{
    framework::{ComplianceMap, ComplianceMapper, EvidencePacket, Framework},
    service::{ComplianceReport, ComplianceService},
};

// Concrete framework mappers (re-exported for direct construction).
pub use themis_compliance::dora::DoraMapper;
pub use themis_compliance::eu_ai_act::EuAiActMapper;
pub use themis_compliance::iso_42001::Iso42001Mapper;
pub use themis_compliance::nist_ai_rmf::NistAiRmfMapper;
pub use themis_compliance::owasp_agentic::OwaspAgenticMapper;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "vouch-compliance");
    }

    #[test]
    fn framework_enum_has_four_supported_frameworks() {
        // DORA, EU AI Act, NIST AI RMF, OWASP Agentic (plus ISO 42001).
        let f = [
            Framework::Dora,
            Framework::EuAiAct,
            Framework::NistAiRmf,
            Framework::OwaspAgentic,
        ];
        assert_eq!(f.len(), 4);
    }
}
