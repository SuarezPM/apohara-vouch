//! themis-compliance — DORA + EU AI Act + NIST AI RMF + OWASP Agentic 2026
//! + ISO/IEC 42001:2023 mappers on the Evidence Packet. Closes AC8
//!   (6 frameworks mapped) + AC15 (EU AI Act Art 12 ≥7/8 fields
//!   populated; we ship 8/8).

#![warn(missing_docs)]

pub mod aibom;
pub mod aiml_metrics;
pub mod dora;
pub mod eu_ai_act;
pub mod featherless_metrics;
pub mod framework;
pub mod fria;
pub mod inv15;
pub mod iso_23894;
pub mod iso_42001;
pub mod iso_5469;
pub mod nist_ai_rmf;
pub mod owasp_agentic;
pub mod qms;
pub mod sarif_merge;
pub mod service;

/// Crate version + name.
pub fn version() -> &'static str {
    "themis-compliance"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-compliance");
    }
}
