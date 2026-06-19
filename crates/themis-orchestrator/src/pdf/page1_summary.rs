//! Page 1 of the audit PDF — summary view, premium design.
//!
//! Sections rendered:
//!   - Hero band (navy with gold rule + APOHARA VOUCH brand mark)
//!   - Verdict hero (large APPROVED / HALT / REVIEW pill, color-coded)
//!   - Identifiers (tenant, invoice, packet id, generated_at) in kv rows
//!   - Cryptographic integrity (BLAKE3 + Ed25519 + pubkey in chips)
//!   - Agent decisions (compact color-coded trace)
//!   - Framework compliance (table with status symbols)
//!   - Rekor transparency-log anchor (if present)
//!   - QR code (PNG, real bitmap, bottom-right)
//!   - Footer (seal id + page number + disclaimer)

use crate::packet::SignedPacket;
use themis_agents::baaar::Outcome;
use themis_agents::decision::AgentDecision;

use super::baaar::{build_condition_matrix, format_baaar_reason};
use super::ctx::{brand, Ctx, Page};

/// Render the full page 1.
pub fn render(
    ctx: &Ctx,
    packet: &SignedPacket,
    page: &mut Page,
    seal_id: &str,
    total: u32,
) -> Result<(), super::PdfError> {
    ctx.hero_band(page, 190.0);
    render_verdict_hero(ctx, packet, page);
    render_identifiers(ctx, packet, page);
    render_crypto(ctx, packet, page);
    render_agent_decisions(ctx, &packet.packet.agent_decisions, page);
    render_framework_compliance(ctx, packet, page);
    render_rekor_anchor(ctx, packet, page);
    render_qr(ctx, packet, page)?;
    ctx.footer(page, seal_id, 1, total);
    Ok(())
}

/// Top-of-page verdict: large pill in the verdict color.
fn render_verdict_hero(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    // Mini-label uppercase (FOR-style).
    page.set_fill(brand::BLUE);
    ctx.write(page, "BAAAR OUTCOME", 20.0, page.cursor_y - 1.0, 7.5, true);
    page.cursor_y -= page.line_h * 0.7;
    page.reset_color();

    match packet.packet.bbaaar_outcome {
        Outcome::Halt(reason) => {
            ctx.verdict_hero(page, "HALT", brand::RED);
            ctx.h1(page, &format!("REASON: {}", format_baaar_reason(reason)));

            let matrix = build_condition_matrix(&packet.packet.agent_decisions);
            for (i, (label, value)) in matrix.iter().enumerate() {
                if i == 0 {
                    page.set_fill(brand::MUTED);
                    ctx.write(page, "BAAAR CONDITION MATRIX", 20.0, page.cursor_y - 1.0, 7.5, true);
                    page.cursor_y -= page.line_h * 0.6;
                    page.reset_color();
                }
                ctx.kv_row(page, label, value, i % 2 == 1);
            }
        }
        Outcome::Approve => {
            ctx.verdict_hero(page, "APPROVED", brand::GREEN);
            ctx.body(page, "All 5 BAAAR conditions passed; no halt triggered.");
        }
    }
    page.cursor_y -= page.line_h * 0.6;
}

/// Identifiers as a structured kv table.
fn render_identifiers(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    ctx.h1(page, "Identifiers");

    ctx.kv_row(page, "TENANT", &packet.packet.tenant_id, false);
    ctx.kv_row(page, "INVOICE ID", &packet.packet.invoice_id, true);
    ctx.kv_row(page, "PACKET ID", &packet.packet.packet_id.to_string(), false);
    ctx.kv_row(
        page,
        "GENERATED AT",
        &format!("{} ms", packet.packet.generated_at_ms),
        true,
    );

    page.cursor_y -= page.line_h * 0.4;
}

/// Crypto values as chip-style rows.
fn render_crypto(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    ctx.h1(page, "Cryptographic Integrity");

    ctx.crypto_field(page, "BLAKE3 HASH", &packet.blake3_hash_hex);

    let sig_preview: String = if packet.signature_hex.len() >= 24 {
        format!("{}\u{2026}", &packet.signature_hex[..24])
    } else {
        packet.signature_hex.clone()
    };
    ctx.crypto_field(
        page,
        "ED25519 SIGNATURE",
        &format!("{}  ({} chars, truncated for display)", sig_preview, packet.signature_hex.len()),
    );

    ctx.crypto_field(page, "PUBLIC KEY", &packet.public_key_hex);

    page.cursor_y -= page.line_h * 0.4;
}

/// Agent decisions as a compact numbered list with verdict color.
fn render_agent_decisions(ctx: &Ctx, decisions: &[AgentDecision], page: &mut Page) {
    ctx.h1(
        page,
        &format!("Agent Decisions ({} total)", decisions.len()),
    );

    let verdict_color = match decisions.len() {
        0 => brand::MUTED,
        _ => brand::SLATE,
    };
    for (i, d) in decisions.iter().enumerate() {
        // Stop well above the footer to avoid overlap.
        if page.cursor_y < 80.0 {
            page.set_fill(brand::MUTED);
            ctx.write(
                page,
                &format!("  ... and {} more (see JSON packet)", decisions.len() - i),
                22.0,
                page.cursor_y - 4.5,
                8.0,
                false,
            );
            page.cursor_y -= page.line_h;
            page.reset_color();
            break;
        }
        let conf_pct = (d.confidence * 100.0) as u32;
        let line = format!(
            "{:>2}.  {:<22} ({:?}, conf={}%)",
            i + 1,
            d.agent_id,
            d.decision_type,
            conf_pct
        );
        page.set_fill(verdict_color);
        ctx.write(page, &line, 22.0, page.cursor_y - 4.5, 8.5, false);
        page.cursor_y -= page.line_h * 0.9;
    }
    page.cursor_y -= page.line_h * 0.3;
    page.reset_color();
}

/// Framework compliance as a status table.
fn render_framework_compliance(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    ctx.h1(page, "Framework Compliance");

    let fm = &packet.packet.framework_mappings;
    let rows: [(&str, bool, &str); 4] = [
        (
            "DORA Art. 9",
            fm.dora_art_9,
            "ICT risk management system",
        ),
        (
            "EU AI Act Art. 12",
            fm.eu_ai_act_art_12,
            "8-field record-keeping",
        ),
        (
            "NIST AI RMF",
            fm.nist_ai_rmf,
            "Govern / Map / Measure / Manage",
        ),
        (
            "OWASP Agentic",
            fm.owasp_agentic,
            "ASI01..ASI10 threats",
        ),
    ];
    for (i, (label, populated, desc)) in rows.iter().enumerate() {
        let (symbol, status, color) = if *populated {
            ("\u{2713}", "OK", brand::GREEN)
        } else {
            ("\u{2717}", "FAIL", brand::RED)
        };
        // alternating row band
        if i % 2 == 1 {
            ctx.rect(
                page,
                20.0,
                page.cursor_y - 5.5,
                170.0,
                6.0,
                brand::BAND,
            );
        }
        ctx.status_row(page, symbol, status, &format!("{label} \u{2014} {desc}"), color);
    }
    page.cursor_y -= page.line_h * 0.3;
}

/// Rekor anchor as a chip-row block.
fn render_rekor_anchor(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    if let Some(entry) = &packet.rekor_entry {
        // Only render if there's room; the page is content-dense and
        // the Rekor section is optional.
        if page.cursor_y > 80.0 {
            ctx.h1(page, "Rekor Transparency Log Anchor");
            ctx.crypto_field(page, "REKOR UUID", &entry.uuid);
            ctx.crypto_field(
                page,
                "LOG INDEX",
                &entry.log_index.to_string(),
            );
            ctx.crypto_field(
                page,
                "INTEGRATED TIME",
                &format!("{} s", entry.integrated_time),
            );
            ctx.crypto_field(page, "BUNDLE URL", &entry.bundle_url);
        }
    }
}

/// QR code rendered as a PNG (real bitmap, scannable).
fn render_qr(
    ctx: &Ctx,
    packet: &SignedPacket,
    page: &mut Page,
) -> Result<(), super::PdfError> {
    let verify_url = format!(
        "https://vouch.apohara.dev/verify?packet={}&tenant={}",
        packet.packet.packet_id, packet.packet.tenant_id
    );
    let qr = qrcode::QrCode::new(verify_url.as_bytes())
        .map_err(|e| super::PdfError::Save(format!("QR encode error: {e}")))?;

    // Build a GrayImage (Luma8) from the QR's color matrix.
    let w = qr.width();
    let colors = qr.to_colors();
    let mut img = image::GrayImage::new(w as u32, w as u32);
    for y in 0..w {
        for x in 0..w {
            // qrcode::Color::Dark == foreground module.
            let is_dark = colors[y * w + x] == qrcode::Color::Dark;
            let luma = if is_dark { 0u8 } else { 255u8 };
            img.put_pixel(x as u32, y as u32, image::Luma([luma]));
        }
    }
    // Scale up by 8x for sharp PDF rendering at 22mm width.
    let scaled = image::imageops::resize(
        &img,
        (w as u32) * 8,
        (w as u32) * 8,
        image::imageops::Nearest,
    );
    let dyn_img = image::DynamicImage::ImageLuma8(scaled);
    let (w_px, h_px) = (dyn_img.width() as usize, dyn_img.height() as usize);
    // Build a printpdf::ImageXObject directly (greyscale, 8 bits).
    // We use the raw luma bytes — every pixel is one u8, 0 = black
    // (qrcode dark), 255 = white (qrcode light).
    let pixels: Vec<u8> = dyn_img
        .to_luma8()
        .pixels()
        .map(|p| p.0[0])
        .collect();
    let xobject = printpdf::ImageXObject {
        width: printpdf::Px(w_px),
        height: printpdf::Px(h_px),
        color_space: printpdf::ColorSpace::Greyscale,
        bits_per_component: printpdf::ColorBits::Bit8,
        interpolate: true,
        image_data: pixels,
        image_filter: None,
        clipping_bbox: None,
        smask: None,
    };
    let pdf_image: printpdf::Image = xobject.into();

    // Position the QR at bottom-right, 22mm wide. The image's
    // intrinsic size at 300dpi is (width_px * 8) pt; we scale to
    // fit 22mm (= ~62.36 pt) by setting scale_x/scale_y.
    let qr_pt = 22.0_f32 * 2.834_645_7_f32; // mm -> pt
    let pdf_w_pt = (w as f32) * 8.0_f32;
    let scale = qr_pt / pdf_w_pt;
    let transform = printpdf::ImageTransform {
        translate_x: Some(printpdf::Mm(160.0)),
        translate_y: Some(printpdf::Mm(20.0)),
        scale_x: Some(scale),
        scale_y: Some(scale),
        ..Default::default()
    };
    pdf_image.add_to_layer(page.layer.clone(), transform);

    // QR caption above the image.
    page.set_fill(brand::MUTED);
    ctx.write(page, "SCAN TO VERIFY", 162.0, 45.0, 6.5, true);
    page.reset_color();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::SignedPacket;
    use themis_agents::baaar::Outcome;
    use themis_agents::decision::{AgentDecision, DecisionType};

    fn sample_packet() -> SignedPacket {
        let decisions = vec![AgentDecision {
            agent_id: "extractor".to_string(),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: DecisionType::Extracted,
            confidence: 0.9,
            reasoning: "ok".to_string(),
            timestamp_ms: 0,
            payload: serde_json::json!({}),
        }];
        let packet =
            crate::packet::EvidencePacket::new("stark", "inv-001", decisions, Outcome::Approve);
        SignedPacket::wrap(packet, "00".repeat(64), "11".repeat(32))
    }

    #[test]
    fn render_writes_page1() {
        let (doc, _page_idx, _layer_idx) =
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
        render(&ctx, &sp, &mut page, "VOUCH-TEST", 6).expect("render");
        assert!(page.cursor_y < 280.0);
    }
}
