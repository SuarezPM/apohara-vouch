//! EU AI Act Article 50 transparency banner — mandatory from
//! 2-aug-2026 with NO delay (Omnibus excluded). Renders as the
//! first SSE event on every connect so the judge / regulator sees
//! the AI disclosure before any agent output.
//!
//! Article 49 mock EU registration id is exposed as a public
//! constant so the Evidence Packet (C-10) and the compliance
//! dashboard can embed it without re-declaring the string.
//!
//! This crate stays leaf-level (no external deps). The JSON
//! shape used by the SSE handler is built in the orchestrator
//! crate (`art50::build_ai_disclosure_event`), which already
//! depends on `serde_json`.

/// Mock EU AI Act database registration id. The EU database for
/// Annex III high-risk AI systems opens 2027-12-02; until then
/// THEMIS carries this placeholder id so downstream artefacts
/// (Evidence Packet, C2PA manifest, compliance dashboard) can
/// embed a stable, audit-ready identifier. Once the database
/// opens, swap this constant for the real EU-issued id.
pub const EU_REGISTRATION_ID: &str = "EU-AI-ACT-2026-THEMIS-MOCK";

/// Full banner HTML, inline-CSS, gold-on-navy per the THEMIS
/// palette (bg #0a0e1a, accent #d4a017). No external assets.
pub const AI_DISCLOSURE_BANNER_HTML: &str = r#"<div class="ai-disclosure" role="banner" aria-label="EU AI Act Article 50 transparency notice">
  <span class="ai-disclosure__icon" aria-hidden="true">i</span>
  <span class="ai-disclosure__text">
    <strong>AI-Generated Content</strong> &mdash; This output was produced by an AI system subject to
    <a href="https://eur-lex.europa.eu/eli/reg/2024/1689/oj" target="_blank" rel="noopener">EU AI Act Art 50 (transparency)</a>.
    C2PA-signed receipt available.
    <span class="ai-disclosure__reg">EU AI Act registration: <code>EU-AI-ACT-2026-THEMIS-MOCK</code>
      <em>(registration activates 2027-12-02 when EU database opens for Annex III)</em></span>
  </span>
</div>
<style>
  .ai-disclosure {
    padding: 0.75rem 1rem;
    background: #0a0e1a;
    color: #d4a017;
    border-left: 4px solid #d4a017;
    font-family: system-ui, -apple-system, Segoe UI, sans-serif;
    font-size: 14px;
    line-height: 1.45;
  }
  .ai-disclosure a { color: #d4a017; text-decoration: underline; }
  .ai-disclosure code { font-family: ui-monospace, Menlo, Consolas, monospace; color: #f9fafb; background: #1f2937; padding: 0 4px; border-radius: 3px; }
  .ai-disclosure__reg { display: block; margin-top: 0.25rem; font-size: 12px; opacity: 0.9; }
  .ai-disclosure__icon { display: inline-block; width: 1.25rem; height: 1.25rem; line-height: 1.25rem; text-align: center; border: 1px solid #d4a017; border-radius: 50%; margin-right: 0.5rem; font-weight: bold; }
</style>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_html_contains_art_50_reference() {
        assert!(AI_DISCLOSURE_BANNER_HTML.contains("Art 50"));
    }

    #[test]
    fn banner_html_contains_registration_id() {
        assert!(AI_DISCLOSURE_BANNER_HTML.contains(EU_REGISTRATION_ID));
    }

    #[test]
    fn banner_html_uses_themis_palette() {
        assert!(AI_DISCLOSURE_BANNER_HTML.contains("#0a0e1a"));
        assert!(AI_DISCLOSURE_BANNER_HTML.contains("#d4a017"));
    }
}

