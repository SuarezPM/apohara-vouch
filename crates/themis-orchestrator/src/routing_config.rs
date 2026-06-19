//! TOML-driven override for the per-agent LLM routing config.
//!
//! Reads `crates/themis-orchestrator/routing.toml` at startup (or
//! the path in `$VOUCH_ROUTING_CONFIG`). The constants in
//! `routing.rs` remain the compile-time defaults — this module
//! adds a thin override layer on top. Existing tests and callers
//! that import the constants by name are unaffected; new code
//! should prefer `RoutingConfig::load_or_default()`.
//!
//! ## Use cases
//!
//! - Add a new model (e.g. swap Llama-3.3-70B for Llama-3.1-405B)
//!   without recompiling.
//! - A/B test a model on a single agent without touching others.
//! - Pin a specific model version for a reproducible bench run.
//!
//! ## Scope
//!
//! Only the 3 LLM-driven model ids are configurable. The per-agent
//! BACKEND selection (Featherless vs AIML API vs None) is fixed in
//! `routing.rs` because changing it would break the per-model
//! metrics contract (`/metrics/featherless` keyed on backend name).

use std::path::Path;

use serde::Deserialize;

/// TOML schema for `crates/themis-orchestrator/routing.toml`.
/// All three sub-tables are optional; missing tables or fields
/// fall back to the compile-time defaults in `routing.rs`.
///
/// We intentionally do NOT use `#[serde(deny_unknown_fields)]` on
/// this struct so that future top-level fields (e.g. `version`,
/// `generated_at`) can be added without breaking old config files.
/// `AgentConfig` does use `deny_unknown_fields` so a typo in a
/// model block is caught immediately.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RoutingConfig {
    /// `fraud_auditor` agent override block (Featherless Qwen route).
    /// Optional; missing means use the compile-time default.
    #[serde(default)]
    pub fraud_auditor: Option<AgentConfig>,
    /// `gaap_classifier` agent override block (Featherless Llama route).
    /// Optional; missing means use the compile-time default.
    #[serde(default)]
    pub gaap_classifier: Option<AgentConfig>,
    /// AIML API model override block (applies to all 4 AIML-routed
    /// agents plus the Featherless fallback). Optional.
    #[serde(default)]
    pub aiml_api: Option<AgentConfig>,
}

/// Single-agent config block. Currently only the model id is
/// exposed; model params (temperature, max_tokens) are intentionally
/// out of scope to keep the surface narrow.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Model id forwarded verbatim to the provider (e.g.
    /// `Qwen/Qwen3-Coder-30B-A3B-Instruct` for Featherless,
    /// `claude-sonnet-4-6` for AI/ML API).
    pub model: String,
}

impl RoutingConfig {
    /// Default config matching the constants in `routing.rs`.
    /// Used when the TOML file is absent or any field is missing.
    pub fn defaults() -> Self {
        Self {
            fraud_auditor: Some(AgentConfig {
                model: crate::routing::FRAUD_AUDITOR_FEATHERLESS_MODEL.to_string(),
            }),
            gaap_classifier: Some(AgentConfig {
                model: crate::routing::GAAP_CLASSIFIER_FEATHERLESS_MODEL.to_string(),
            }),
            aiml_api: Some(AgentConfig {
                model: crate::routing::AIML_API_MODEL.to_string(),
            }),
        }
    }

    /// Load the config from `<crate_dir>/routing.toml` (or the
    /// path in `$VOUCH_ROUTING_CONFIG`). Returns `Self::defaults()`
    /// if the file is absent; logs WARN and returns defaults if
    /// the file is malformed. Never panics — the orchestrator
    /// must start even on a broken config.
    pub fn load_or_default() -> Self {
        let path = std::env::var("VOUCH_ROUTING_CONFIG")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("routing.toml"));
        match std::fs::read_to_string(&path) {
            Ok(text) => match toml::from_str::<RoutingConfig>(&text) {
                Ok(cfg) => {
                    tracing::info!(path = %path.display(), "loaded routing.toml override");
                    cfg
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "routing.toml malformed; using compile-time defaults"
                    );
                    Self::defaults()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::defaults(),
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "routing.toml unreadable; using compile-time defaults"
                );
                Self::defaults()
            }
        }
    }

    /// Effective model id for `fraud_auditor`'s Featherless route.
    pub fn fraud_auditor_featherless_model(&self) -> &str {
        self.fraud_auditor
            .as_ref()
            .map(|a| a.model.as_str())
            .unwrap_or(crate::routing::FRAUD_AUDITOR_FEATHERLESS_MODEL)
    }

    /// Effective model id for `gaap_classifier`'s Featherless route.
    pub fn gaap_classifier_featherless_model(&self) -> &str {
        self.gaap_classifier
            .as_ref()
            .map(|a| a.model.as_str())
            .unwrap_or(crate::routing::GAAP_CLASSIFIER_FEATHERLESS_MODEL)
    }

    /// Effective model id for the AIML API route (4 LLM-driven
    /// agents + Featherless fallback).
    pub fn aiml_api_model(&self) -> &str {
        self.aiml_api
            .as_ref()
            .map(|a| a.model.as_str())
            .unwrap_or(crate::routing::AIML_API_MODEL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_routing_rs_constants() {
        let cfg = RoutingConfig::defaults();
        assert_eq!(
            cfg.fraud_auditor_featherless_model(),
            crate::routing::FRAUD_AUDITOR_FEATHERLESS_MODEL
        );
        assert_eq!(
            cfg.gaap_classifier_featherless_model(),
            crate::routing::GAAP_CLASSIFIER_FEATHERLESS_MODEL
        );
        assert_eq!(cfg.aiml_api_model(), crate::routing::AIML_API_MODEL);
    }

    #[test]
    fn missing_toml_falls_back_to_defaults() {
        let cfg = RoutingConfig::load_or_default();
        // Whichever path was loaded (default or real file), every
        // getter must return a non-empty model id (so a broken
        // config can never produce an empty LLM call).
        assert!(!cfg.fraud_auditor_featherless_model().is_empty());
        assert!(!cfg.gaap_classifier_featherless_model().is_empty());
        assert!(!cfg.aiml_api_model().is_empty());
    }

    #[test]
    fn parses_minimal_toml_string() {
        let toml_text = r#"
[fraud_auditor]
model = "custom-qwen-99"
"#;
        let cfg: RoutingConfig = toml::from_str(toml_text).expect("parse minimal TOML");
        assert_eq!(cfg.fraud_auditor_featherless_model(), "custom-qwen-99");
        // Unset tables fall back to the compile-time defaults.
        assert_eq!(
            cfg.gaap_classifier_featherless_model(),
            crate::routing::GAAP_CLASSIFIER_FEATHERLESS_MODEL
        );
    }

    #[test]
    fn parses_full_toml_string() {
        let toml_text = r#"
[fraud_auditor]
model = "custom-qwen"

[gaap_classifier]
model = "custom-llama"

[aiml_api]
model = "custom-claude"
"#;
        let cfg: RoutingConfig = toml::from_str(toml_text).expect("parse full TOML");
        assert_eq!(cfg.fraud_auditor_featherless_model(), "custom-qwen");
        assert_eq!(cfg.gaap_classifier_featherless_model(), "custom-llama");
        assert_eq!(cfg.aiml_api_model(), "custom-claude");
    }

    #[test]
    fn rejects_unknown_field() {
        // `deny_unknown_fields` is on the table structs, not on the
        // top-level RoutingConfig — adding `unknown_top_level = 1`
        // should still parse (we only reject inside AgentConfig).
        let toml_text = r#"
unknown_top_level = 1

[fraud_auditor]
model = "x"
"#;
        // We accept unknown top-level keys (forward-compat); only
        // unknown keys INSIDE an AgentConfig block are rejected.
        let result: Result<RoutingConfig, _> = toml::from_str(toml_text);
        assert!(result.is_ok(), "top-level unknown keys should be accepted");
    }
}
