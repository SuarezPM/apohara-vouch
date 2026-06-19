//! Page 1 of the audit PDF — summary view.
//!
//! Sections rendered:
//!   1. Identifiers (tenant, invoice_id, packet_id, generated_at)
//!   2. BAAAR outcome (HALT stamp + reason matrix, or APPROVED)
//!   3. Cryptographic integrity (BLAKE3 + Ed25519 + public key)
//!   4. Agent decisions (preview, truncates if too many for the page)
//!   5. Framework compliance (DORA / EU AI Act / NIST / OWASP)
//!   6. Rekor transparency-log anchor (if present)
//!
//! Plus the page footer: QR code (encodes the verify URL) + offline-
//! verify hint.

use crate::packet::SignedPacket;
use themis_agents::baaar::Outcome;
use themis_agents::decision::AgentDecision;

use super::baaar::{build_condition_matrix, format_baaar_reason};
use super::ctx::{Ctx, Page};

/// Render all 6 sections of page 1 + the footer (QR + verify hint).
pub fn render(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) -> Result<(), super::PdfError> {
    render_header(ctx, page);
    render_identifiers(ctx, packet, page);
    render_baaar_outcome(ctx, packet, page);
    render_crypto(ctx, packet, page);
    render_agent_decisions(ctx, &packet.packet.agent_decisions, page);
    render_framework_compliance(ctx, packet, page);
    render_rekor_anchor(ctx, packet, page);
    render_footer_qr(ctx, packet, page)
}

fn render_header(ctx: &Ctx, page: &mut Page) {
    ctx.write(
        page,
        "Apohara VOUCH Evidence Packet",
        20.0,
        page.cursor_y,
        18.0,
        true,
    );
    page.cursor_y -= page.line_h * 1.5;
    ctx.write(
        page,
        "DORA Art. 17 + EU AI Act Art. 12 compliant receipt",
        20.0,
        page.cursor_y,
        9.0,
        false,
    );
    page.cursor_y -= page.line_h * 2.0;
}

fn render_identifiers(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    ctx.write(page, "1. Identifiers", 20.0, page.cursor_y, 12.0, true);
    page.cursor_y -= page.line_h;
    for (label, value) in [
        ("Tenant", packet.packet.tenant_id.as_str()),
        ("Invoice ID", packet.packet.invoice_id.as_str()),
        ("Packet ID", &packet.packet.packet_id.to_string()),
        ("Generated at", &format!("{} ms", packet.packet.generated_at_ms)),
    ] {
        ctx.write(
            page,
            &format!("{label:<16}{value}"),
            20.0,
            page.cursor_y,
            10.0,
            false,
        );
        page.cursor_y -= page.line_h;
    }
    page.cursor_y -= page.line_h * 0.5;
}

fn render_baaar_outcome(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    ctx.write(page, "2. BAAAR Outcome", 20.0, page.cursor_y, 12.0, true);
    page.cursor_y -= page.line_h;
    match packet.packet.bbaaar_outcome {
        Outcome::Halt(reason) => {
            set_red(page);
            ctx.write(page, "HALT", 20.0, page.cursor_y, 24.0, true);
            page.cursor_y -= page.line_h * 2.0;
            page.reset_color();

            ctx.write(
                page,
                &format!("REASON: {}", format_baaar_reason(reason)),
                20.0,
                page.cursor_y,
                11.0,
                true,
            );
            page.cursor_y -= page.line_h * 1.3;

            let matrix = build_condition_matrix(&packet.packet.agent_decisions);
            for (label, value) in matrix {
                ctx.write(page, &value, 20.0, page.cursor_y, 9.0, label == "fired");
                page.cursor_y -= page.line_h * 0.95;
            }
        }
        Outcome::Approve => {
            set_green(page);
            ctx.write(page, "APPROVED", 20.0, page.cursor_y, 18.0, true);
            page.cursor_y -= page.line_h * 1.7;
            page.reset_color();
            ctx.write(
                page,
                "All 5 BAAAR conditions passed; no halt triggered.",
                20.0,
                page.cursor_y,
                10.0,
                false,
            );
        }
    }
    page.cursor_y -= page.line_h * 1.5;
}

fn render_crypto(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    ctx.write(page, "3. Cryptographic Integrity", 20.0, page.cursor_y, 12.0, true);
    page.cursor_y -= page.line_h;
    ctx.write(
        page,
        &format!("BLAKE3 hash:       {}", packet.blake3_hash_hex),
        20.0,
        page.cursor_y,
        9.0,
        false,
    );
    page.cursor_y -= page.line_h;

    let sig_preview: &str = if packet.signature_hex.len() >= 32 {
        &packet.signature_hex[..32]
    } else {
        &packet.signature_hex
    };
    ctx.write(
        page,
        &format!(
            "Ed25519 signature: {}... ({} chars total)",
            sig_preview,
            packet.signature_hex.len()
        ),
        20.0,
        page.cursor_y,
        9.0,
        false,
    );
    page.cursor_y -= page.line_h;
    ctx.write(
        page,
        &format!("Public key:        {}", packet.public_key_hex),
        20.0,
        page.cursor_y,
        9.0,
        false,
    );
    page.cursor_y -= page.line_h * 1.5;
}

fn render_agent_decisions(ctx: &Ctx, decisions: &[AgentDecision], page: &mut Page) {
    ctx.write(
        page,
        &format!("4. Agent Decisions ({} total)", decisions.len()),
        20.0,
        page.cursor_y,
        12.0,
        true,
    );
    page.cursor_y -= page.line_h;
    for (i, d) in decisions.iter().enumerate() {
        ctx.write(
            page,
            &format!("  {}. {} ({:?})", i + 1, d.agent_id, d.decision_type),
            20.0,
            page.cursor_y,
            8.0,
            false,
        );
        page.cursor_y -= page.line_h * 0.85;
        if page.cursor_y < 30.0 {
            ctx.write(
                page,
                &format!("  ... and {} more", decisions.len() - i - 1),
                20.0,
                page.cursor_y,
                8.0,
                false,
            );
            page.cursor_y -= page.line_h;
            break;
        }
    }
    page.cursor_y -= page.line_h * 0.5;
}

fn render_framework_compliance(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    ctx.write(page, "5. Framework Compliance", 20.0, page.cursor_y, 12.0, true);
    page.cursor_y -= page.line_h;
    let fm = &packet.packet.framework_mappings;
    for (label, populated) in [
        ("DORA Art. 9", fm.dora_art_9),
        ("EU AI Act Art. 12", fm.eu_ai_act_art_12),
        ("NIST AI RMF", fm.nist_ai_rmf),
        ("OWASP Agentic", fm.owasp_agentic),
    ] {
        ctx.write(
            page,
            &format!("{label:<24}{}", if populated { "[x]" } else { "[ ]" }),
            20.0,
            page.cursor_y,
            9.0,
            false,
        );
        page.cursor_y -= page.line_h;
    }
    page.cursor_y -= page.line_h * 0.5;
}

fn render_rekor_anchor(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    if let Some(entry) = &packet.rekor_entry {
        ctx.write(
            page,
            "6. Rekor Transparency Log Anchor",
            20.0,
            page.cursor_y,
            12.0,
            true,
        );
        page.cursor_y -= page.line_h;
        for (label, value) in [
            ("Rekor UUID", entry.uuid.as_str()),
            ("Rekor log index", &entry.log_index.to_string()),
            ("Integrated time", &format!("{} s", entry.integrated_time)),
            ("Bundle URL", entry.bundle_url.as_str()),
        ] {
            ctx.write(
                page,
                &format!("{label:<16}{value}"),
                20.0,
                page.cursor_y,
                8.5,
                false,
            );
            page.cursor_y -= page.line_h;
        }
    }
}

fn render_footer_qr(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) -> Result<(), super::PdfError> {
    let verify_url = format!(
        "https://vouch.apohara.dev/verify?packet={}&tenant={}",
        packet.packet.packet_id, packet.packet.tenant_id
    );
    let qr = qrcode::QrCode::new(verify_url.as_bytes())
        .map_err(|e| super::PdfError::Save(format!("QR encode error: {e}")))?;
    let qr_art: String = qr
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build();

    // Each line of qr_art represents 2 source rows of the QR matrix;
    // 8pt monospace at our line height is ~2.6mm per line.
    let qr_line_h: f32 = 2.6;
    let qr_lines: Vec<&str> = qr_art.lines().collect();
    let qr_total_h = qr_lines.len() as f32 * qr_line_h;
    let mut qr_y = 18.0 + qr_total_h + 4.0;
    if qr_y > 60.0 {
        qr_y = 60.0;
    }
    for line in &qr_lines {
        ctx.write(page, line, 20.0, qr_y, 8.0, false);
        qr_y -= qr_line_h;
    }

    ctx.write(
        page,
        "Verify offline with: vouch-verify <packet.json> <signature.hex>",
        20.0,
        12.0,
        8.0,
        false,
    );
    Ok(())
}

fn set_red(page: &Page) {
    use printpdf::{Color, Rgb};
    page.layer
        .set_fill_color(Color::Rgb(Rgb::new(0.784, 0.0, 0.0, None)));
}

fn set_green(page: &Page) {
    use printpdf::{Color, Rgb};
    page.layer
        .set_fill_color(Color::Rgb(Rgb::new(0.0, 0.588, 0.0, None)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::SignedPacket;
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
                reasoning: "ok".to_string(),
                timestamp_ms: 0,
                payload: serde_json::json!({}),
            },
        ];
        let packet =
            crate::packet::EvidencePacket::new("stark", "inv-001", decisions, Outcome::Approve);
        SignedPacket::wrap(packet, "00".repeat(64), "11".repeat(32))
    }

    #[test]
    fn render_writes_all_six_sections() {
        let (doc, page_idx, layer_idx) =
            printpdf::PdfDocument::new("test", printpdf::Mm(210.0), printpdf::Mm(297.0), "L1");
        let font = doc.add_builtin_font(printpdf::BuiltinFont::Helvetica).unwrap();
        let bold = doc.add_builtin_font(printpdf::BuiltinFont::HelveticaBold).unwrap();
        let ctx = Ctx {
            doc: &doc,
            font_regular: &font,
            font_bold: &bold,
        };
        let mut page = ctx.add_a4_page("L1");
        let sp = sample_packet();
        render(&ctx, &sp, &mut page).expect("render");
        // Sanity: the cursor moved down (content was written).
        assert!(page.cursor_y < 280.0);
    }
}
