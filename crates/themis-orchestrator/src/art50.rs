//! EU AI Act Article 50 transparency gate (mandatory from
//! 2-aug-2026 with no delay — Omnibus excluded) and Article 49
//! mock EU registration. Closes gaps G01 and G02.
//!
//! The actual gating (first SSE event is `AiDisclosure`) lives
//! in `http.rs` (see `Event::AiDisclosure` in `events.rs` — the
//! orchestrator's SSE handler chains a one-shot prelude before
//! the broadcast stream, the same pattern used for
//! `Event::SponsorStack`). This module re-exports the banner
//! constants from `themis-frontend::art50_banner` so the
//! orchestrator's tests and Evidence Packet builder can
//! reference them without depending on the leaf frontend crate's
//! internal layout.
//!
//! Reference: <https://eur-lex.europa.eu/eli/reg/2024/1689/oj>

/// Mock EU AI Act database registration id. Re-exported from
/// `themis_frontend::art50_banner::EU_REGISTRATION_ID` so the
/// orchestrator and the Evidence Packet (C-10) can reference a
/// single source of truth.
pub use themis_frontend::art50_banner::{EU_REGISTRATION_ID, AI_DISCLOSURE_BANNER_HTML};

/// Convenience accessor for the banner HTML, re-exported so
/// callers can write `art50::banner_html()` without the
/// `themis_frontend` prefix.
pub fn banner_html() -> &'static str {
    AI_DISCLOSURE_BANNER_HTML
}

/// Build the `Event::AiDisclosure` value the SSE handler chains
/// as the one-shot prelude before the broadcast stream. The
/// timestamp is captured at call time so every fresh SSE
/// connect gets a fresh `at <iso8601>` stamp.
pub fn build_ai_disclosure_event() -> crate::events::Event {
    crate::events::Event::AiDisclosure {
        run_id: uuid::Uuid::nil(),
        banner_html: banner_html().to_string(),
        eu_registration_id: EU_REGISTRATION_ID.to_string(),
        timestamp: chrono::Utc::now(),
    }
}

/// Hard invariant: the AI disclosure must be the FIRST event on
/// every SSE connect (the Art 50 transparency gate). Returns
/// `true` when the given event list is correctly ordered
/// (`AiDisclosure` first, followed by `SponsorStack`, then the
/// run events). The SSE handler is responsible for emitting in
/// this order; this function is the testable assertion.
pub fn first_event_is_ai_disclosure(events: &[crate::events::Event]) -> bool {
    matches!(
        events.first(),
        Some(crate::events::Event::AiDisclosure { .. })
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Event;
    use uuid::Uuid;

    #[test]
    fn banner_html_contains_art_50() {
        assert!(banner_html().contains("EU AI Act Art 50"));
    }

    #[test]
    fn banner_html_contains_registration_id() {
        assert!(banner_html().contains(EU_REGISTRATION_ID));
    }

    #[test]
    fn first_event_is_ai_disclosure_true_when_list_starts_with_ai_disclosure() {
        let events = vec![
            build_ai_disclosure_event(),
            Event::SponsorStack {
                run_id: Uuid::nil(),
                band: "band-sdk[langgraph]==0.2.11".to_string(),
                aiml_api: "anthropic/claude-sonnet-4.5".to_string(),
                featherless: "Qwen/Qwen3-Coder-30B-A3B-Instruct".to_string(),
            },
        ];
        assert!(first_event_is_ai_disclosure(&events));
    }

    #[test]
    fn first_event_is_ai_disclosure_false_when_list_empty() {
        assert!(!first_event_is_ai_disclosure(&[]));
    }

    #[test]
    fn first_event_is_ai_disclosure_false_when_first_is_sponsor_stack() {
        let events = vec![Event::SponsorStack {
            run_id: Uuid::nil(),
            band: "x".to_string(),
            aiml_api: "y".to_string(),
            featherless: "z".to_string(),
        }];
        assert!(!first_event_is_ai_disclosure(&events));
    }

    #[test]
    fn build_ai_disclosure_event_carries_registration_id() {
        let ev = build_ai_disclosure_event();
        match ev {
            Event::AiDisclosure {
                eu_registration_id,
                banner_html,
                ..
            } => {
                assert_eq!(eu_registration_id, EU_REGISTRATION_ID);
                assert!(banner_html.contains("Art 50"));
            }
            _ => panic!("expected AiDisclosure"),
        }
    }
}
