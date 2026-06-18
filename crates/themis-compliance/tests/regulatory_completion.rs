//! Integration tests for the regulatory completion mappers
//! (Story C-16a).
//!
//! Three new mappers, all of them live in `themis-compliance`:
//!   - `fria` — EU AI Act Art 27 Fundamental Rights Impact Assessment
//!   - `aibom` — CycloneDX 1.6 AI Bill of Materials
//!   - `qms` — EU AI Act Art 17 Quality Management System
//!
//! These tests run end-to-end: derive/build the artifact, then
//! verify both the structured shape and the JSON serialization
//! shape. The critic amendment in the plan requires the AIBOM
//! `modelCard` and `datasets.provenance` to be verified explicitly.

use themis_compliance::aibom::{self, Aibom};
use themis_compliance::fria::{self, Fria, FriaElement, FriaReport};
use themis_compliance::qms::{self, QmsReport, STANDARD_SOPS};

#[test]
fn fria_full_flow() {
    // Build a representative input. The risk_score matches what
    // the BAAAR gate evaluates; tenant + use case are the standard
    // ones from the orchestrator's pre-orchestration context.
    let input = Fria {
        risk_score: 0.37,
        tenant_id: "stark".to_string(),
        use_case: "buyer-side AP invoice fraud detection".to_string(),
    };
    let report: FriaReport = fria::derive(&input);

    // All 5 Art 27 elements are populated, in regulation order.
    assert_eq!(report.elements.len(), 5);
    assert_eq!(report.elements[0].0, FriaElement::RiskAssessment);
    assert_eq!(report.elements[1].0, FriaElement::DataQuality);
    assert_eq!(report.elements[2].0, FriaElement::HumanOversight);
    assert_eq!(report.elements[3].0, FriaElement::TechnicalRobustness);
    assert_eq!(report.elements[4].0, FriaElement::FundamentalRights);

    // Every analysis string is non-empty.
    for (i, (_, text)) in report.elements.iter().enumerate() {
        assert!(!text.is_empty(), "element {i} has empty analysis");
    }

    // Risk score + tenant + use case propagated.
    assert!((report.risk_score - 0.37).abs() < 1e-6);
    assert_eq!(report.tenant_id, "stark");
    assert_eq!(report.use_case, "buyer-side AP invoice fraud detection");

    // JSON shape: framework tag, 5 elements with element + analysis.
    let j = fria::to_json(&report);
    assert_eq!(
        j.get("framework").and_then(|v| v.as_str()),
        Some("eu_ai_act_art_27_fria")
    );
    assert_eq!(j.get("tenant_id").and_then(|v| v.as_str()), Some("stark"));
    let score = j.get("risk_score").and_then(|v| v.as_f64()).unwrap();
    assert!(
        (score - 0.37).abs() < 1e-5,
        "risk_score in JSON must be 0.37, got {score}"
    );
    let arr = j
        .get("elements")
        .and_then(|v| v.as_array())
        .expect("elements must be an array");
    assert_eq!(arr.len(), 5);
    for (i, e) in arr.iter().enumerate() {
        assert!(e.get("element").is_some(), "entry {i} missing element");
        assert!(e.get("analysis").is_some(), "entry {i} missing analysis");
    }
}

#[test]
fn aibom_full_flow() {
    let a: Aibom = aibom::build();

    // 7 application crates + 5 ML model components = 12 total.
    let apps: Vec<&themis_compliance::aibom::Component> = a
        .components
        .iter()
        .filter(|c| c.component_type == "application")
        .collect();
    let models: Vec<&themis_compliance::aibom::Component> = a
        .components
        .iter()
        .filter(|c| c.component_type == "machine-learning-model")
        .collect();
    assert_eq!(apps.len(), 7, "7 application crates required");
    assert_eq!(models.len(), 5, "5 ML models required");
    assert_eq!(a.components.len(), 12);

    // CycloneDX 1.6 spec compliance.
    let j = aibom::to_cyclonedx_json(&a);
    assert_eq!(
        j.get("bomFormat").and_then(|v| v.as_str()),
        Some("CycloneDX")
    );
    assert_eq!(j.get("specVersion").and_then(|v| v.as_str()), Some("1.6"));
    let serial = j
        .get("serialNumber")
        .and_then(|v| v.as_str())
        .expect("serialNumber must be a string");
    assert!(serial.starts_with("urn:uuid:themis-3-aibom-"));

    // The top-level components array has all 12 entries.
    let comps = j
        .get("components")
        .and_then(|v| v.as_array())
        .expect("components must be an array");
    assert_eq!(comps.len(), 12);

    // Each component has type, name, version.
    for (i, c) in comps.iter().enumerate() {
        assert!(c.get("type").is_some(), "component {i} missing type");
        assert!(c.get("name").is_some(), "component {i} missing name");
        assert!(c.get("version").is_some(), "component {i} missing version");
    }
}

#[test]
fn aibom_contains_model_card() {
    let a = aibom::build();

    // The Claude Sonnet 4.5 component must carry a modelCard.
    let claude = a
        .components
        .iter()
        .find(|c| c.name == "claude-sonnet-4-5")
        .expect("claude-sonnet-4-5 must be present in AIBOM");
    let card = claude
        .model_card
        .as_ref()
        .expect("claude-sonnet-4-5 must carry a modelCard (PRD requirement)");

    // modelParameters is a JSON object with the expected keys.
    let params = card
        .model_parameters
        .as_object()
        .expect("modelParameters must be a JSON object");
    assert!(
        params.contains_key("architecture"),
        "modelParameters must include architecture"
    );
    assert!(
        params.contains_key("context_window_tokens"),
        "modelParameters must include context_window_tokens"
    );
    assert!(
        params.contains_key("provider"),
        "modelParameters must include provider"
    );

    // intendedUse non-empty.
    assert!(
        !card.intended_use.is_empty(),
        "intendedUse must be populated"
    );

    // In CycloneDX JSON, the modelCard is rendered under the
    // `modelCard` key with the same shape.
    let j = aibom::to_cyclonedx_json(&a);
    let comps = j.get("components").and_then(|v| v.as_array()).unwrap();
    let claude_json = comps
        .iter()
        .find(|c| c.get("name").and_then(|v| v.as_str()) == Some("claude-sonnet-4-5"))
        .expect("claude-sonnet-4-5 must be in cyclonedx JSON");
    let mcard = claude_json
        .get("modelCard")
        .expect("claude-sonnet-4-5 must render a modelCard key");
    assert!(
        mcard.get("modelParameters").is_some(),
        "rendered modelCard must include modelParameters"
    );
    assert!(
        mcard.get("intendedUse").is_some(),
        "rendered modelCard must include intendedUse"
    );
}

#[test]
fn aibom_contains_datasets_provenance() {
    let a = aibom::build();

    // The InvoiceNet dataset is attached to the Claude Sonnet 4.5
    // model card. Verify both the structured `datasets` field and
    // the populated `provenance` string.
    let claude = a
        .components
        .iter()
        .find(|c| c.name == "claude-sonnet-4-5")
        .expect("claude-sonnet-4-5 must be present in AIBOM");
    assert_eq!(claude.datasets.len(), 1);
    let dataset = &claude.datasets[0];
    assert_eq!(dataset.name, "invoicenet-1k");
    assert!(
        !dataset.provenance.is_empty(),
        "datasets[].provenance must be populated (PRD requirement)"
    );
    assert!(
        dataset.provenance.contains("Stanford"),
        "provenance should reference Stanford"
    );
    assert!(!dataset.license.is_empty(), "license must be populated");

    // In the CycloneDX JSON, the dataset is rendered under
    // `components` (sub-components) with a `provenance` property.
    let j = aibom::to_cyclonedx_json(&a);
    let comps = j.get("components").and_then(|v| v.as_array()).unwrap();
    let claude_json = comps
        .iter()
        .find(|c| c.get("name").and_then(|v| v.as_str()) == Some("claude-sonnet-4-5"))
        .expect("claude-sonnet-4-5 must be in cyclonedx JSON");
    let subs = claude_json
        .get("components")
        .and_then(|v| v.as_array())
        .expect("claude-sonnet-4-5 must render a sub-components array for datasets");
    assert_eq!(
        subs.len(),
        1,
        "claude-sonnet-4-5 must have 1 dataset sub-component"
    );
    let data = &subs[0];
    assert_eq!(data.get("type").and_then(|v| v.as_str()), Some("data"));
    let props = data
        .get("properties")
        .and_then(|v| v.as_array())
        .expect("dataset must render a properties array");
    let prov = props
        .iter()
        .find(|p| p.get("name").and_then(|v| v.as_str()) == Some("provenance"))
        .expect("dataset must have a provenance property");
    assert!(
        prov.get("value")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("Stanford"),
        "rendered provenance must mention Stanford"
    );
}

#[test]
fn qms_full_flow() {
    let report: QmsReport = qms::derive();

    // 7 SOPs in regulation order.
    assert_eq!(report.sops.len(), 7);
    let ids: Vec<&str> = report.sops.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["SOP-001", "SOP-002", "SOP-003", "SOP-004", "SOP-005", "SOP-006", "SOP-007",]
    );

    // Each SOP has non-empty id, title, and last_reviewed.
    for (i, s) in report.sops.iter().enumerate() {
        assert!(!s.id.is_empty(), "SOP {i} has empty id");
        assert!(!s.title.is_empty(), "SOP {i} has empty title");
    }

    // JSON shape.
    let j = qms::to_json(&report);
    assert_eq!(
        j.get("framework").and_then(|v| v.as_str()),
        Some("eu_ai_act_art_17_qms")
    );
    assert_eq!(j.get("sop_count").and_then(|v| v.as_u64()), Some(7));
    let sops = j
        .get("sops")
        .and_then(|v| v.as_array())
        .expect("sops must be an array");
    assert_eq!(sops.len(), 7);
    for (i, s) in sops.iter().enumerate() {
        assert!(s.get("id").is_some(), "SOP {i} missing id in JSON");
        assert!(s.get("title").is_some(), "SOP {i} missing title in JSON");
        assert!(
            s.get("last_reviewed").is_some(),
            "SOP {i} missing last_reviewed in JSON"
        );
    }
}

#[test]
fn qms_references_all_sops() {
    // The STANDARD_SOPS list is the contract. Every entry must
    // appear in the derived report.
    let report = qms::derive();
    for (id, title) in STANDARD_SOPS {
        let found = report.sops.iter().find(|s| s.id == *id);
        assert!(
            found.is_some(),
            "STANDARD_SOPS entry {id} ({title}) not found in QmsReport"
        );
        let s = found.unwrap();
        assert_eq!(s.title, *title, "SOP {id} title mismatch");
    }

    // And every derived SOP is in the standard list.
    for s in &report.sops {
        assert!(
            STANDARD_SOPS.iter().any(|(id, _)| *id == s.id),
            "derived SOP {} is not in STANDARD_SOPS",
            s.id
        );
    }
}
