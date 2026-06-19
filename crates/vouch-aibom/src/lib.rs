//! vouch-aibom — CycloneDX 1.6 AI Bill of Materials builder.
//!
//! AC-3.1: thin re-export of `themis-compliance::aibom` with a
//! stable vouch-* surface. CycloneDX 1.6 is the only normative
//! AI-BOM format accepted by EU regulators today (per Fraunhofer
//! FKIE 2026-03 guidance); we emit JSON.

pub use themis_compliance::aibom::{Aibom, Component, Dataset, ModelCard};

/// CycloneDX 1.6 envelope. The aibom.rs builder emits the same
/// shape; this type is here for callers that want a stable
/// import path.
pub type CycloneDxEnvelope = serde_json::Value;

/// Build a CycloneDX 1.6 JSON envelope from an `Aibom`.
pub fn to_cyclonedx_1_6(aibom: &Aibom) -> serde_json::Value {
    themis_compliance::aibom::to_cyclonedx_json(aibom)
}

/// Crate version + name.
pub fn version() -> &'static str {
    "vouch-aibom"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "vouch-aibom");
    }

    #[test]
    fn aibom_builder_produces_cyclonedx_1_6_shape() {
        let aibom = themis_compliance::aibom::build();
        let json = to_cyclonedx_1_6(&aibom);
        // CycloneDX 1.6 mandatory top-level keys.
        assert!(json.get("bomFormat").is_some(), "missing bomFormat");
        assert_eq!(json["bomFormat"], "CycloneDX");
        assert!(json.get("specVersion").is_some(), "missing specVersion");
        assert_eq!(json["specVersion"], "1.6");
        assert!(json.get("version").is_some());
        assert!(json.get("components").is_some());
        assert!(json.get("metadata").is_some());
    }
}
