//! themis-frontend — demo UI for themis.apohara.dev.
//!
//! The actual UI lives in `static/` (HTML + CSS + JS) and is
//! embedded into the `themis-orchestrator` binary via
//! `include_dir!`. This crate exists so the workspace has a
//! first-class home for the assets and so a future `cargo build
//! -p themis-frontend --release` can ship a static-only deploy
//! (Vercel) without needing the orchestrator binary.

#![warn(missing_docs)]

/// EU AI Act Article 50 banner + Article 49 mock EU registration
/// id. The banner is rendered as the first SSE event on every
/// connection so the regulator / judge sees the AI disclosure
/// before any agent output.
pub mod art50_banner;

/// Crate version + name.
pub fn version() -> &'static str {
    "themis-frontend"
}

/// Re-export the static asset paths. The orchestrator's
/// `main.rs` does `include_dir!("../themis-frontend/static")` and
/// serves each file at `/static/<name>`.
pub const STATIC_DIR: &str = "static";

/// The index.html shipped at the demo URL root.
pub const INDEX_HTML: &str = include_str!("../static/index.html");

/// The compliance dashboard at `/compliance`.
pub const COMPLIANCE_HTML: &str = include_str!("../static/compliance.html");

/// The token CSS (referenced by both pages).
pub const TOKENS_CSS: &str = include_str!("../static/tokens.css");

/// The application CSS (referenced by both pages).
pub const APP_CSS: &str = include_str!("../static/app.css");

/// The application JS (EventSource-driven live counter, BAAAR
/// overlay, evidence download).
pub const APP_JS: &str = include_str!("../static/app.js");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-frontend");
    }

    #[test]
    fn index_html_starts_with_doctype() {
        assert!(INDEX_HTML.trim_start().starts_with("<!doctype html>"));
    }

    #[test]
    fn compliance_html_starts_with_doctype() {
        assert!(COMPLIANCE_HTML.trim_start().starts_with("<!doctype html>"));
    }

    #[test]
    fn tokens_css_contains_hallmark_stamp() {
        assert!(TOKENS_CSS.contains("Hallmark"));
        assert!(TOKENS_CSS.contains("Workbench"));
    }

    #[test]
    fn app_js_contains_submit_handler() {
        assert!(APP_JS.contains("submit-form"));
        assert!(APP_JS.contains("BAAAR"));
    }

    #[test]
    fn no_emoji_in_static_assets() {
        // Hallmark gate: no emoji in production UI.
        for (name, body) in [
            ("INDEX_HTML", INDEX_HTML),
            ("COMPLIANCE_HTML", COMPLIANCE_HTML),
            ("TOKENS_CSS", TOKENS_CSS),
            ("APP_CSS", APP_CSS),
            ("APP_JS", APP_JS),
        ] {
            // No emoji codepoints. Simple scan: anything above U+007F
            // is allowed in copy (the stamp says "Θ" and
            // "·") but the script-flagged emoji ranges are
            // 1F300+ (miscellaneous symbols and pictographs).
            for c in body.chars() {
                let cp = c as u32;
                assert!(
                    !(0x1F300..=0x1FAFF).contains(&cp) && !(0x2600..=0x27BF).contains(&cp),
                    "{name} contains emoji {c:?} (codepoint {cp:X})"
                );
            }
        }
    }
}
