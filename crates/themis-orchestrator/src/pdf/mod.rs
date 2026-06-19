//! PDF rendering of a `SignedPacket`.
//!
//! Split across submodules — each one owns one page of the audit PDF:
//!
//! * [`ctx`] — shared `Ctx` (document handle + builtin fonts) and
//!   `Page` (per-page layer + cursor).
//! * [`baaar`] — BAAAR condition matrix + `BaaarReason` formatter.
//! * [`page1_summary`] — page 1 (summary + crypto + framework + QR).
//! * [`page2_audit`] — page 2 (auditor-grade compliance grid).
//! * [`stakeholders`] — pages 3-6 (CISO / CFO / GC / Broker).
//!
//! The [`render_packet_pdf`] entry point here is the only public
//! function. It owns the document lifetime and serializes the six
//! pages to an in-memory buffer.

use thiserror::Error;

use crate::packet::SignedPacket;

mod baaar;
mod ctx;
mod page1_summary;
mod page2_audit;
mod stakeholders;

pub use ctx::{Ctx, Page};

/// Errors from PDF rendering.
#[derive(Debug, Error)]
pub enum PdfError {
    /// The PDF generator failed to add a built-in font.
    #[error("font error: {0}")]
    Font(String),
    /// `printpdf` returned an error saving to the buffer.
    #[error("save error: {0}")]
    Save(String),
}

/// Render a `SignedPacket` to PDF bytes (6-page A4, built-in
/// Helvetica, deterministic given the input packet).
///
/// Pages:
///   1. Summary view (header, identifiers, BAAAR, crypto, agents,
///      framework, Rekor anchor, QR + verify hint)
///   2. Auditor-grade compliance grid + agent decision trace
///   3. CISO Executive Summary
///   4. CFO Financial Impact
///   5. General Counsel Legal Exposure
///   6. Broker Insurance Eligibility
pub fn render_packet_pdf(packet: &SignedPacket) -> Result<Vec<u8>, PdfError> {
    use printpdf::{Mm, PdfDocument};

    let (doc, page1, layer1) = PdfDocument::new(
        "Apohara VOUCH Evidence Packet",
        Mm(210.0),
        Mm(297.0),
        "Layer 1",
    );
    let font_regular = doc
        .add_builtin_font(printpdf::BuiltinFont::Helvetica)
        .map_err(|e| PdfError::Font(format!("{e:?}")))?;
    let font_bold = doc
        .add_builtin_font(printpdf::BuiltinFont::HelveticaBold)
        .map_err(|e| PdfError::Font(format!("{e:?}")))?;
    let ctx = Ctx {
        doc: &doc,
        font_regular: &font_regular,
        font_bold: &font_bold,
    };

    // Resolve the page-1 layer into a `Page` we hand to the renderer.
    let layer1 = doc.get_page(page1).get_layer(layer1);
    let mut page1_state = Page {
        layer: layer1,
        cursor_y: 280.0,
        line_h: 7.0,
    };
    page1_summary::render(&ctx, packet, &mut page1_state)?;

    let mut page2_state = ctx.add_a4_page("Layer 2");
    // Tighter line spacing on the auditor grid page.
    page2_state.line_h = 6.5;
    page2_audit::render(&ctx, packet, &mut page2_state);

    stakeholders::render(&ctx, packet);

    let mut buf: Vec<u8> = Vec::new();
    {
        let mut writer = std::io::BufWriter::new(&mut buf);
        doc.save(&mut writer)
            .map_err(|e| PdfError::Save(format!("{e:?}")))?;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use themis_agents::baaar::Outcome;
    use themis_agents::decision::{AgentDecision, DecisionType};

    fn sample_packet() -> SignedPacket {
        let decisions = vec![
            AgentDecision {
                agent_id: "extractor".to_string(),
                tenant_id: "stark".to_string(),
                invoice_id: "inv-001".to_string(),
                decision_type: DecisionType::Extracted,
                confidence: 0.9,
                reasoning: "ok".to_string(),
                timestamp_ms: 0,
                payload: serde_json::json!({}),
            },
            AgentDecision {
                agent_id: "fraud_auditor".to_string(),
                tenant_id: "stark".to_string(),
                invoice_id: "inv-001".to_string(),
                decision_type: DecisionType::FraudAssessed,
                confidence: 0.85,
                reasoning: "HALTED by BAAAR".to_string(),
                timestamp_ms: 0,
                payload: serde_json::json!({}),
            },
        ];
        let packet =
            crate::packet::EvidencePacket::new("stark", "inv-001", decisions, Outcome::Approve);
        SignedPacket::wrap(packet, "00".repeat(64), "11".repeat(32))
    }

    #[test]
    fn renders_to_non_empty_bytes() {
        let sp = sample_packet();
        let bytes = render_packet_pdf(&sp).expect("render");
        assert!(
            bytes.len() > 1024,
            "PDF should be >1KB, got {}",
            bytes.len()
        );
        // Magic bytes for a PDF file.
        assert_eq!(&bytes[..5], b"%PDF-");
    }

    #[test]
    fn renders_with_rekor_entry() {
        let mut sp = sample_packet();
        sp.rekor_entry = Some(themis_evidence::rekor::RekorEntry {
            uuid: "mock-uuid-1234567890abcdef".to_string(),
            log_index: 42,
            body_b64: "AAAA".to_string(),
            integrated_time: 1718000000,
            signed_entry_timestamp: String::new(),
            bundle_url: "https://rekor.sigstore.dev/api/v1/log/entries/abc".to_string(),
        });
        let bytes = render_packet_pdf(&sp).expect("render with rekor");
        assert!(bytes.len() > 1024);
        assert_eq!(&bytes[..5], b"%PDF-");
    }
}
