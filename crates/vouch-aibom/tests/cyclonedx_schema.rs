//! vouch-aibom CycloneDX 1.6 schema tests.
//!
//! AC-3.1 (aibom): the builder emits CycloneDX 1.6 with the
//! required top-level keys.

use vouch_aibom::to_cyclonedx_1_6;

#[test]
fn aibom_emits_cyclonedx_1_6_top_level_keys() {
    let aibom = themis_compliance::aibom::build();
    let json = to_cyclonedx_1_6(&aibom);
    assert_eq!(json["bomFormat"], "CycloneDX");
    assert_eq!(json["specVersion"], "1.6");
    assert!(json["version"].is_number(), "version is required");
    assert!(json["components"].is_array(), "components is required");
    assert!(json["metadata"].is_object(), "metadata is required");
}

#[test]
fn aibom_survives_json_round_trip() {
    let aibom = themis_compliance::aibom::build();
    let json = to_cyclonedx_1_6(&aibom);
    let s = serde_json::to_string(&json).unwrap();
    let back: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(back, json);
}
