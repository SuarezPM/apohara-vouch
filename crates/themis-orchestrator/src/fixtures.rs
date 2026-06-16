//! Embedded demo invoice fixtures.
//!
//! The 5 Stanford InvoiceNet-shaped fixtures live in
//! `fixtures/demo-invoices/` at the repo root. We embed them at
//! compile time via `include_str!` so the production binary works
//! on read-only filesystems (Vercel, Fly, Docker scratch) without
//! needing a writable working directory.
//!
//! Used by:
//! - `GET /fixtures` (returns a `Vec<DemoFixture>` to the frontend)
//! - The bench binary (US-Bench) — runs each fixture through the
//!   orchestrator and measures token economy
//!
//! The fixture JSON shape is the orchestrator-internal `DemoInvoice`
//! (see `test_support::DemoInvoice`). We re-declare only the fields
//! the playground needs (tenant_id, invoice_id, expected_verdict,
//! expected_halt_reason, halt_reason_human) so adding a fixture
//! doesn't accidentally break the public API.

use serde::{Deserialize, Serialize};

/// Public-facing fixture metadata served by `GET /fixtures`. Keeps
/// the embedded JSON private to this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoFixture {
    /// Tenant id (e.g. "stark", "wayne").
    pub tenant_id: String,
    /// Invoice id (e.g. "stark-001").
    pub invoice_id: String,
    /// Human-readable label for the playground dropdown.
    pub label: String,
    /// Expected verdict — "HALT" or "APPROVED".
    pub expected_verdict: String,
    /// Expected halt reason when `expected_verdict == "HALT"`.
    /// Empty string otherwise.
    pub expected_halt_reason: String,
    /// Human-readable halt reason, or empty for APPROVED.
    pub halt_reason_human: String,
    /// The full fixture JSON, base64-encoded so the frontend can
    /// POST it as `raw_b64` without round-tripping.
    pub raw_b64: String,
}

/// Internal fixture shape (subset of `test_support::DemoInvoice`).
/// Re-declared locally so the public API is decoupled from the
/// bench/test types.
#[derive(Debug, Deserialize)]
struct RawFixture {
    invoice_id: String,
    tenant_id: String,
    #[serde(default)]
    expected_verdict: String,
    #[serde(default)]
    expected_halt_reason: String,
    #[serde(default)]
    halt_reason_human: Option<String>,
}

/// Build a human-readable label from the fixture, including the
/// verdict + halt reason for the dropdown option text.
fn build_label(tenant: &str, raw: &RawFixture) -> String {
    let verdict = if raw.expected_verdict == "APPROVED" {
        "APPROVED".to_string()
    } else {
        let reason = raw
            .expected_halt_reason
            .replace('_', " ")
            .to_uppercase();
        format!("HALT · {reason}")
    };
    format!(
        "{tenant} · {invoice} · {verdict}",
        invoice = raw.invoice_id,
    )
}

/// The 5 demo invoice fixtures embedded at compile time.
///
/// Order is deliberate: the APPROVED fixture (wayne-002) is first
/// in the dropdown so the default selection is a clean run; the
/// 4 HALT fixtures follow in fixture-name order. The frontend
/// reads this list once on page load.
pub const FIXTURE_FILES: &[&str] = &[
    "wayne-002.json", // APPROVED — default selection
    "stark-001.json", // HALT · RISK SCORE EXCEEDED
    "stark-002.json", // HALT · RISK SCORE EXCEEDED
    "stark-003.json", // HALT · SECRET LEAK DETECTED
    "wayne-001.json", // HALT · COHERENCE TOO LOW
];

/// Embedded raw JSON for each fixture, indexed in the same order
/// as `FIXTURE_FILES`. The `include_str!` macro embeds the file
/// contents into the binary at compile time so the demo works on
/// read-only filesystems.
fn raw_json_for(name: &str) -> &'static str {
    match name {
        "wayne-002.json" => include_str!("../../../fixtures/demo-invoices/wayne-002.json"),
        "stark-001.json" => include_str!("../../../fixtures/demo-invoices/stark-001.json"),
        "stark-002.json" => include_str!("../../../fixtures/demo-invoices/stark-002.json"),
        "stark-003.json" => include_str!("../../../fixtures/demo-invoices/stark-003.json"),
        "wayne-001.json" => include_str!("../../../fixtures/demo-invoices/wayne-001.json"),
        other => panic!("unknown demo fixture: {other}"),
    }
}

/// Load all 5 demo fixtures. Called by the `GET /fixtures` HTTP
/// handler. The result is fully owned (no references to the
/// embedded JSON) so it can be serialized straight to the wire.
pub fn load_all() -> Vec<DemoFixture> {
    use base64::Engine;
    FIXTURE_FILES
        .iter()
        .map(|name| {
            let raw_text = raw_json_for(name);
            let raw: RawFixture = serde_json::from_str(raw_text)
                .unwrap_or_else(|e| panic!("failed to parse fixture {name}: {e}"));
            let raw_b64 = base64::engine::general_purpose::STANDARD.encode(raw_text.as_bytes());
            DemoFixture {
                tenant_id: raw.tenant_id.clone(),
                invoice_id: raw.invoice_id.clone(),
                label: build_label(&raw.tenant_id, &raw),
                expected_verdict: raw.expected_verdict,
                expected_halt_reason: raw.expected_halt_reason,
                halt_reason_human: raw.halt_reason_human.unwrap_or_default(),
                raw_b64,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_all_returns_5_fixtures() {
        let fixtures = load_all();
        assert_eq!(fixtures.len(), 5, "expected exactly 5 demo fixtures");
    }

    #[test]
    fn first_fixture_is_approved() {
        let fixtures = load_all();
        assert_eq!(
            fixtures[0].expected_verdict, "APPROVED",
            "default selection (index 0) must be the APPROVED fixture"
        );
    }

    #[test]
    fn all_5_fixtures_are_well_formed() {
        let fixtures = load_all();
        // 4 HALT + 1 APPROVED, spread across 2 trust domains.
        let halts = fixtures
            .iter()
            .filter(|f| f.expected_verdict == "HALT")
            .count();
        let approves = fixtures
            .iter()
            .filter(|f| f.expected_verdict == "APPROVED")
            .count();
        assert_eq!(halts, 4, "expected 4 HALT fixtures, got {halts}");
        assert_eq!(approves, 1, "expected 1 APPROVED fixture, got {approves}");

        // Every fixture has a non-empty tenant_id, invoice_id, and raw_b64.
        for f in &fixtures {
            assert!(!f.tenant_id.is_empty(), "empty tenant_id in {}", f.invoice_id);
            assert!(!f.invoice_id.is_empty(), "empty invoice_id");
            assert!(
                !f.raw_b64.is_empty(),
                "empty raw_b64 for {}",
                f.invoice_id
            );
            // raw_b64 must decode to the fixture JSON (round-trip integrity).
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&f.raw_b64)
                .expect("raw_b64 must be valid base64");
            let s = std::str::from_utf8(&bytes).expect("decoded raw_b64 must be UTF-8");
            let parsed: RawFixture =
                serde_json::from_str(s).expect("decoded raw_b64 must be a valid RawFixture");
            assert_eq!(parsed.invoice_id, f.invoice_id);
        }
    }
}
