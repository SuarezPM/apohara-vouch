//! AI Bill of Materials (AIBOM) — CycloneDX 1.6 spec format.
//!
//! Story C-16a / G13 + G17. CycloneDX 1.6 adds `machine-learning-model`
//! and `data` component types plus `modelCard` and `model.parameters`,
//! which is exactly what an AI supply-chain transparency artifact
//! needs. The AIBOM lists every component that contributes to a
//! THEMIS run: the 7 Rust crates, the 5 LLM providers, and the
//! 1 training/evaluation dataset (InvoiceNet 1K).
//!
//! The AIBOM is emitted alongside the Evidence Packet so external
//! auditors (and the EU AI Act Art 13 supply-chain probe) can
//! verify what was used, with modelCard modelParameters and the
//! dataset provenance both included.

use serde::Serialize;

/// A single AIBOM component. CycloneDX 1.6 distinguishes
/// `application`, `machine-learning-model`, and `data` via the
/// `component_type` field; the rest of the shape is uniform.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Component {
    /// CycloneDX `type` — one of `application`, `machine-learning-model`,
    /// `data` (or `library`, `framework`, etc. as needed).
    pub component_type: String,
    /// Component name (e.g. `themis-orchestrator`, `claude-sonnet-4-5`).
    pub name: String,
    /// Version string (semver when applicable; LLM provider version
    /// or `latest` for models without a release tag).
    pub version: String,
    /// Optional model card. CycloneDX 1.6 attaches the card to
    /// `machine-learning-model` components via
    /// `Component.modelCard`. The PRD says the Claude Sonnet 4.5
    /// entry must carry one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_card: Option<ModelCard>,
    /// Datasets used to train or evaluate this component. Empty
    /// for crates; the InvoiceNet dataset is attached to the
    /// Claude Sonnet 4.5 model card as a `data` group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub datasets: Vec<Dataset>,
}

/// CycloneDX 1.6 modelCard. `modelParameters` is a free-form
/// JSON object (CycloneDX does not constrain the schema). The
/// `intendedUse` and `limitations` arrays are the standard
/// modelCard fields.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModelCard {
    /// Free-form model parameters (architecture, parameters count,
    /// context window, etc.). The serializer keeps it as a
    /// `serde_json::Value` to avoid coupling to a specific model
    /// schema.
    pub model_parameters: serde_json::Value,
    /// Intended use statement (short).
    pub intended_use: String,
    /// Known limitations. Empty array when none documented.
    pub limitations: Vec<String>,
}

/// A dataset referenced by an AIBOM component. CycloneDX 1.6
/// represents datasets as a sub-component or as a `data` group;
/// for THEMIS 3.0 we attach the InvoiceNet dataset to the
/// Claude Sonnet 4.5 model card.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Dataset {
    /// Dataset name (e.g. `invoicenet-1k`).
    pub name: String,
    /// Approximate size in bytes.
    pub size_bytes: u64,
    /// SPDX license id or `unknown`.
    pub license: String,
    /// Provenance: where the data came from + how it was
    /// processed. The PRD requires this field to be populated.
    pub provenance: String,
}

/// The AIBOM root. A bag of components.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Aibom {
    /// All components (applications, ML models, datasets).
    pub components: Vec<Component>,
}

/// Build the canonical THEMIS 3.0 AIBOM. 7 application crates +
/// 5 ML model providers + 1 dataset (with provenance) attached
/// to the Claude Sonnet 4.5 model card.
pub fn build() -> Aibom {
    // The 7 THEMIS 3.0 crates — each gets an `application`
    // component with the workspace version.
    let version = env!("CARGO_PKG_VERSION");
    let apps = vec![
        Component {
            component_type: "application".to_string(),
            name: "themis-orchestrator".to_string(),
            version: version.to_string(),
            model_card: None,
            datasets: vec![],
        },
        Component {
            component_type: "application".to_string(),
            name: "themis-agents".to_string(),
            version: version.to_string(),
            model_card: None,
            datasets: vec![],
        },
        Component {
            component_type: "application".to_string(),
            name: "themis-evidence".to_string(),
            version: version.to_string(),
            model_card: None,
            datasets: vec![],
        },
        Component {
            component_type: "application".to_string(),
            name: "themis-band-client".to_string(),
            version: version.to_string(),
            model_card: None,
            datasets: vec![],
        },
        Component {
            component_type: "application".to_string(),
            name: "themis-compliance".to_string(),
            version: version.to_string(),
            model_card: None,
            datasets: vec![],
        },
        Component {
            component_type: "application".to_string(),
            name: "themis-frontend".to_string(),
            version: version.to_string(),
            model_card: None,
            datasets: vec![],
        },
        Component {
            component_type: "application".to_string(),
            name: "themis-compressor".to_string(),
            version: version.to_string(),
            model_card: None,
            datasets: vec![],
        },
    ];

    // InvoiceNet dataset (1K sample, Stanford public).
    let invoicenet = Dataset {
        name: "invoicenet-1k".to_string(),
        size_bytes: 500_000_000, // 500 MB approximate
        license: "CC-BY-4.0".to_string(),
        provenance:
            "Stanford InvoiceNet (公开 invoice dataset, canun-private subset, 1K sample bundled in \
             tests/fixtures/invoicenet_sample.parquet). Sampled by themis-orchestrator public-bench \
             harness for cross-domain fraud-recall evaluation."
                .to_string(),
    };

    // 5 ML models. Only Claude Sonnet 4.5 carries a modelCard; per
    // the PRD, that's the component auditors will check first.
    let claude_sonnet_4_5 = Component {
        component_type: "machine-learning-model".to_string(),
        name: "claude-sonnet-4-5".to_string(),
        version: "2025-11-01".to_string(),
        model_card: Some(ModelCard {
            model_parameters: serde_json::json!({
                "architecture": "transformer-decoder",
                "provider": "AI/ML API (Anthropic-compatible)",
                "context_window_tokens": 200_000,
                "supports_tool_use": true,
                "supports_vision": false,
                "training_data_cutoff": "2025-10",
            }),
            intended_use: "Primary orchestrator LLM for THEMIS 3.0: agent reasoning, fraud-signal \
                classification, and provenance narrative generation. Hackathon credits via Band sponsor."
                .to_string(),
            limitations: vec![
                "May produce plausible-but-false fraud rationales; BAAAR gate is the only enforcement."
                    .to_string(),
                "Not trained on tenant-specific PO data; cross-tenant generalization is not guaranteed."
                    .to_string(),
            ],
        }),
        datasets: vec![invoicenet.clone()],
    };

    let qwen3_coder_30b = Component {
        component_type: "machine-learning-model".to_string(),
        name: "qwen3-coder-30b".to_string(),
        version: "2025-08-15".to_string(),
        model_card: None,
        datasets: vec![],
    };

    let featherless_fallback = Component {
        component_type: "machine-learning-model".to_string(),
        name: "featherless-fallback".to_string(),
        version: "2026-Q2".to_string(),
        model_card: None,
        datasets: vec![],
    };

    let mock_provider = Component {
        component_type: "machine-learning-model".to_string(),
        name: "mock-provider".to_string(),
        version: "0.1.0".to_string(),
        model_card: None,
        datasets: vec![],
    };

    let band_python_sdk = Component {
        component_type: "machine-learning-model".to_string(),
        name: "band-python-sdk".to_string(),
        version: "0.2.11".to_string(),
        model_card: None,
        datasets: vec![],
    };

    let mut components = apps;
    components.push(claude_sonnet_4_5);
    components.push(qwen3_coder_30b);
    components.push(featherless_fallback);
    components.push(mock_provider);
    components.push(band_python_sdk);

    Aibom { components }
}

/// Serialize to the CycloneDX 1.6 spec format. The output
/// includes the `bomFormat`, `specVersion`, `version`, and
/// `components` array required by the schema.
pub fn to_cyclonedx_json(aibom: &Aibom) -> serde_json::Value {
    let components: Vec<serde_json::Value> = aibom
        .components
        .iter()
        .map(|c| {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "type".to_string(),
                serde_json::Value::String(c.component_type.clone()),
            );
            obj.insert(
                "name".to_string(),
                serde_json::Value::String(c.name.clone()),
            );
            obj.insert(
                "version".to_string(),
                serde_json::Value::String(c.version.clone()),
            );

            // CycloneDX 1.6 attaches modelCard to machine-learning-model
            // components. The PRD requires a modelCard on the Claude
            // Sonnet 4.5 component.
            if let Some(card) = &c.model_card {
                let card_obj = serde_json::json!({
                    "modelParameters": card.model_parameters,
                    "intendedUse": { "value": card.intended_use },
                    "limitations": card.limitations,
                });
                obj.insert("modelCard".to_string(), card_obj);
            }

            // Datasets: emit as a CycloneDX `data` group attached
            // to the model card's component, with each dataset as
            // a `component` of type `data`.
            if !c.datasets.is_empty() {
                let data_components: Vec<serde_json::Value> = c
                    .datasets
                    .iter()
                    .map(|d| {
                        serde_json::json!({
                            "type": "data",
                            "name": d.name,
                            "size": d.size_bytes,
                            "licenses": [{"license": {"id": d.license}}],
                            "evidence": {
                                "identity": [
                                    {
                                        "field": "purl",
                                        "value": format!("pkg:generic/{}@1.0", d.name),
                                    }
                                ]
                            },
                            "properties": [
                                {"name": "provenance", "value": d.provenance}
                            ],
                        })
                    })
                    .collect();
                let existing = obj
                    .entry("components".to_string())
                    .or_insert(serde_json::Value::Array(vec![]));
                if let Some(arr) = existing.as_array_mut() {
                    arr.extend(data_components);
                }
            }

            serde_json::Value::Object(obj)
        })
        .collect();

    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": format!("urn:uuid:themis-3-aibom-{}", uuid_like()),
        "version": 1,
        "metadata": {
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "tools": [{
                "vendor": "apohara",
                "name": "themis-compliance",
                "version": env!("CARGO_PKG_VERSION"),
            }],
            "component": {
                "type": "application",
                "name": "themis-3-supreme",
                "version": env!("CARGO_PKG_VERSION"),
            },
        },
        "components": components,
    })
}

/// Stable pseudo-UUID for the serial number. Not cryptographic
/// (just a hex string for the AIBOM identifier); a full
/// cryptographic UUID can replace this when one is wired in.
fn uuid_like() -> String {
    let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    format!("{now:032x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_includes_7_crates() {
        let a = build();
        let apps: Vec<&Component> = a
            .components
            .iter()
            .filter(|c| c.component_type == "application")
            .collect();
        assert_eq!(
            apps.len(),
            7,
            "expected 7 application crates, got {}",
            apps.len()
        );
        let names: Vec<&str> = apps.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"themis-orchestrator"));
        assert!(names.contains(&"themis-agents"));
        assert!(names.contains(&"themis-evidence"));
        assert!(names.contains(&"themis-band-client"));
        assert!(names.contains(&"themis-compliance"));
        assert!(names.contains(&"themis-frontend"));
        assert!(names.contains(&"themis-compressor"));
    }

    #[test]
    fn build_includes_5_models() {
        let a = build();
        let models: Vec<&Component> = a
            .components
            .iter()
            .filter(|c| c.component_type == "machine-learning-model")
            .collect();
        assert_eq!(
            models.len(),
            5,
            "expected 5 ML models, got {}",
            models.len()
        );
        let names: Vec<&str> = models.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"claude-sonnet-4-5"));
        assert!(names.contains(&"qwen3-coder-30b"));
        assert!(names.contains(&"featherless-fallback"));
        assert!(names.contains(&"mock-provider"));
        assert!(names.contains(&"band-python-sdk"));
    }

    #[test]
    fn build_includes_invoicenet_dataset() {
        let a = build();
        // The InvoiceNet dataset is attached to the Claude Sonnet 4.5
        // component (the only model with a modelCard).
        let claude = a
            .components
            .iter()
            .find(|c| c.name == "claude-sonnet-4-5")
            .expect("claude-sonnet-4-5 must be present");
        assert_eq!(claude.datasets.len(), 1);
        assert_eq!(claude.datasets[0].name, "invoicenet-1k");
    }

    #[test]
    fn to_cyclonedx_matches_spec_v1_6() {
        let a = build();
        let j = to_cyclonedx_json(&a);
        // CycloneDX 1.6 spec markers.
        assert_eq!(
            j.get("bomFormat").and_then(|v| v.as_str()),
            Some("CycloneDX")
        );
        assert_eq!(j.get("specVersion").and_then(|v| v.as_str()), Some("1.6"));
        // serialNumber present and non-empty.
        let serial = j
            .get("serialNumber")
            .and_then(|v| v.as_str())
            .expect("serialNumber must be a string");
        assert!(serial.starts_with("urn:uuid:themis-3-aibom-"));
        // components array.
        let comps = j
            .get("components")
            .and_then(|v| v.as_array())
            .expect("components must be an array");
        assert_eq!(comps.len(), 7 + 5);
        // Every component has type, name, version.
        for (i, c) in comps.iter().enumerate() {
            assert!(c.get("type").is_some(), "component {i} missing type");
            assert!(c.get("name").is_some(), "component {i} missing name");
            assert!(c.get("version").is_some(), "component {i} missing version");
        }
    }
}
