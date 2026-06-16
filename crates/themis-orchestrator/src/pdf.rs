//! PDF rendering of a `SignedPacket`.
//!
//! The `printpdf` crate gives us a pure-Rust PDF generator with
//! built-in fonts (no TTF file needed). We render a single A4 page
//! that surfaces the 8 EU AI Act Art. 12 fields, the BAAAR outcome,
//! the BLAKE3 hash, the Ed25519 signature (truncated), and the
//! Rekor entry (if present). Used by `GET /packets/:packet_id/pdf`
//! to satisfy AC12 (PRC PDF download <2s).
//!
//! The output is intentionally human-readable (not a formal
//! regulatory filing format). For real DORA/EU AI Act submissions,
//! a structured XBRL/JSON-PDF follow-up is in R3.

use thiserror::Error;

use themis_agents::baaar::{BaaarReason, Outcome};
use themis_agents::decision::AgentDecision;

use crate::packet::SignedPacket;

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

/// Render a `SignedPacket` to PDF bytes (single A4 page, built-in
/// Helvetica, ~12 sections, deterministic given the input packet).
pub fn render_packet_pdf(packet: &SignedPacket) -> Result<Vec<u8>, PdfError> {
    use printpdf::{BuiltinFont, Color, Mm, PdfDocument, Rgb};

    let (doc, page1, layer1) =
        PdfDocument::new("THEMIS Evidence Packet", Mm(210.0), Mm(297.0), "Layer 1");
    let layer = doc.get_page(page1).get_layer(layer1);
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| PdfError::Font(format!("{e:?}")))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| PdfError::Font(format!("{e:?}")))?;

    // Layout: top-of-page (Mm 280) downward, ~7mm per line.
    let mut y: f32 = 280.0;
    let line_h: f32 = 7.0;

    let write_line = |layer: &printpdf::PdfLayerReference,
                      text: &str,
                      x: f32,
                      y_pos: f32,
                      size: f32,
                      bold: bool| {
        if bold {
            layer.use_text(text, size, Mm(x), Mm(y_pos), &font_bold);
        } else {
            layer.use_text(text, size, Mm(x), Mm(y_pos), &font);
        }
    };

    write_line(&layer, "THEMIS Evidence Packet", 20.0, y, 18.0, true);
    y -= line_h * 1.5;
    write_line(
        &layer,
        "DORA Art. 17 + EU AI Act Art. 12 compliant receipt",
        20.0,
        y,
        9.0,
        false,
    );
    y -= line_h * 2.0;

    // --- Section 1: identifiers ---
    write_line(&layer, "1. Identifiers", 20.0, y, 12.0, true);
    y -= line_h;
    write_line(
        &layer,
        &format!("Tenant:            {}", packet.packet.tenant_id),
        20.0,
        y,
        10.0,
        false,
    );
    y -= line_h;
    write_line(
        &layer,
        &format!("Invoice ID:        {}", packet.packet.invoice_id),
        20.0,
        y,
        10.0,
        false,
    );
    y -= line_h;
    write_line(
        &layer,
        &format!("Packet ID:         {}", packet.packet.packet_id),
        20.0,
        y,
        10.0,
        false,
    );
    y -= line_h;
    write_line(
        &layer,
        &format!("Generated at:      {} ms", packet.packet.generated_at_ms),
        20.0,
        y,
        10.0,
        false,
    );
    y -= line_h * 1.5;

    // --- Section 2: BAAAR outcome ---
    write_line(&layer, "2. BAAAR Outcome", 20.0, y, 12.0, true);
    y -= line_h;
    match packet.packet.bbaaar_outcome {
        Outcome::Halt(reason) => {
            // Big red HALT stamp. Restores black after the stamp.
            layer.set_fill_color(Color::Rgb(Rgb::new(0.784, 0.0, 0.0, None)));
            write_line(&layer, "HALT", 20.0, y, 24.0, true);
            y -= line_h * 2.0;
            layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

            write_line(
                &layer,
                &format!("REASON: {}", format_baaar_reason(reason)),
                20.0,
                y,
                11.0,
                true,
            );
            y -= line_h * 1.3;

            // 5-condition matrix. We pull the live values from the
            // FraudAuditor's decision payload (best-effort — missing
            // fields render as "n/a", which is the safe default).
            let matrix = build_condition_matrix(&packet.packet.agent_decisions);
            for (label, value) in matrix {
                write_line(&layer, &value, 20.0, y, 9.0, label == "fired");
                y -= line_h * 0.95;
            }
        }
        Outcome::Approve => {
            // Green APPROVED indicator. Restores black after.
            layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.588, 0.0, None)));
            write_line(&layer, "APPROVED", 20.0, y, 18.0, true);
            y -= line_h * 1.7;
            layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
            write_line(
                &layer,
                "All 5 BAAAR conditions passed; no halt triggered.",
                20.0,
                y,
                10.0,
                false,
            );
        }
    }
    y -= line_h * 1.5;

    // --- Section 3: cryptographic integrity ---
    write_line(&layer, "3. Cryptographic Integrity", 20.0, y, 12.0, true);
    y -= line_h;
    write_line(
        &layer,
        &format!("BLAKE3 hash:       {}", packet.blake3_hash_hex),
        20.0,
        y,
        9.0,
        false,
    );
    y -= line_h;
    // Print only the first 32 chars of the signature to keep the
    // page from overflowing; the full hex is in the JSON packet.
    let sig_preview = if packet.signature_hex.len() >= 32 {
        &packet.signature_hex[..32]
    } else {
        &packet.signature_hex
    };
    write_line(
        &layer,
        &format!(
            "Ed25519 signature: {}... ({} chars total)",
            sig_preview,
            packet.signature_hex.len()
        ),
        20.0,
        y,
        9.0,
        false,
    );
    y -= line_h;
    write_line(
        &layer,
        &format!("Public key:        {}", packet.public_key_hex),
        20.0,
        y,
        9.0,
        false,
    );
    y -= line_h * 1.5;

    // --- Section 4: agent decisions ---
    write_line(
        &layer,
        &format!(
            "4. Agent Decisions ({} total)",
            packet.packet.agent_decisions.len()
        ),
        20.0,
        y,
        12.0,
        true,
    );
    y -= line_h;
    for (i, d) in packet.packet.agent_decisions.iter().enumerate() {
        write_line(
            &layer,
            &format!("  {}. {} ({:?})", i + 1, d.agent_id, d.decision_type),
            20.0,
            y,
            8.0,
            false,
        );
        y -= line_h * 0.85;
        if y < 30.0 {
            // Run out of page; stop the agent list here.
            write_line(
                &layer,
                &format!(
                    "  ... and {} more",
                    packet.packet.agent_decisions.len() - i - 1
                ),
                20.0,
                y,
                8.0,
                false,
            );
            y -= line_h;
            break;
        }
    }
    y -= line_h * 0.5;

    // --- Section 5: framework compliance ---
    write_line(&layer, "5. Framework Compliance", 20.0, y, 12.0, true);
    y -= line_h;
    let fm = &packet.packet.framework_mappings;
    write_line(
        &layer,
        &format!(
            "DORA Art. 9:                 {}",
            if fm.dora_art_9 { "[x]" } else { "[ ]" }
        ),
        20.0,
        y,
        9.0,
        false,
    );
    y -= line_h;
    write_line(
        &layer,
        &format!(
            "EU AI Act Art. 12:          {}",
            if fm.eu_ai_act_art_12 { "[x]" } else { "[ ]" }
        ),
        20.0,
        y,
        9.0,
        false,
    );
    y -= line_h;
    write_line(
        &layer,
        &format!(
            "NIST AI RMF:                {}",
            if fm.nist_ai_rmf { "[x]" } else { "[ ]" }
        ),
        20.0,
        y,
        9.0,
        false,
    );
    y -= line_h;
    write_line(
        &layer,
        &format!(
            "OWASP Agentic:              {}",
            if fm.owasp_agentic { "[x]" } else { "[ ]" }
        ),
        20.0,
        y,
        9.0,
        false,
    );
    y -= line_h * 1.5;

    // --- Section 6: Rekor anchor (if present) ---
    if let Some(entry) = &packet.rekor_entry {
        write_line(
            &layer,
            "6. Rekor Transparency Log Anchor",
            20.0,
            y,
            12.0,
            true,
        );
        y -= line_h;
        write_line(
            &layer,
            &format!("Rekor UUID:        {}", entry.uuid),
            20.0,
            y,
            9.0,
            false,
        );
        y -= line_h;
        write_line(
            &layer,
            &format!("Rekor log index:   {}", entry.log_index),
            20.0,
            y,
            9.0,
            false,
        );
        y -= line_h;
        write_line(
            &layer,
            &format!("Integrated time:   {} s", entry.integrated_time),
            20.0,
            y,
            9.0,
            false,
        );
        y -= line_h;
        write_line(
            &layer,
            &format!("Bundle URL:        {}", entry.bundle_url),
            20.0,
            y,
            8.0,
            false,
        );
    }

    // --- Footer ---
    write_line(
        &layer,
        "Verify offline with: themis-verify <packet.json> <signature.hex>",
        20.0,
        20.0,
        8.0,
        false,
    );

    // Save to an in-memory buffer.
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut writer = std::io::BufWriter::new(&mut buf);
        doc.save(&mut writer)
            .map_err(|e| PdfError::Save(format!("{e:?}")))?;
    }
    Ok(buf)
}

/// Human-readable label for a `BaaarReason`. Used in the "REASON:" line
/// of the HALT section.
fn format_baaar_reason(reason: BaaarReason) -> &'static str {
    match reason {
        BaaarReason::RiskScoreExceeded => "risk_score > 0.85",
        BaaarReason::SecretLeakDetected => "secret leak detected",
        BaaarReason::CoherenceTooLow => "coherence_score < 0.3",
        BaaarReason::MaxDebateRoundsReached => "debate_rounds >= 5",
        BaaarReason::ExplicitHaltRequested => "operator requested halt",
    }
}

/// Build the 5-row BAAAR condition matrix. Each row is
/// `(label, formatted_line)`. The `label` is `"fired"` for the row
/// that tripped the gate (so the renderer can bold it), or `""`
/// otherwise. We pull live values from the FraudAuditor's
/// `payload.assessment`; missing fields render as `n/a`.
fn build_condition_matrix(decisions: &[AgentDecision]) -> Vec<(&'static str, String)> {
    // Best-effort: find the FraudAuditor's assessment. The auditor
    // emits `payload.assessment.{risk_score,...}`; older agents may
    // emit the fields flat at the top level. Accept both shapes.
    let (risk_score, coherence_score, debate_rounds, has_secret) =
        extract_assessment(decisions);

    let mut rows: Vec<(&'static str, String)> = Vec::with_capacity(5);

    // 1. risk_score > 0.85
    {
        let score_str = risk_score
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "n/a".to_string());
        let tripped = risk_score.is_some_and(|v| v > 0.85);
        rows.push((
            if tripped { "fired" } else { "" },
            format!(
                "[{}] risk_score > 0.85  score={}  {}",
                if tripped { "X" } else { " " },
                score_str,
                if tripped { "FIRED" } else { "pass" }
            ),
        ));
    }
    // 2. secret leak
    {
        let tripped = has_secret;
        rows.push((
            if tripped { "fired" } else { "" },
            format!(
                "[{}] secret_leak finding present        {}",
                if tripped { "X" } else { " " },
                if tripped { "FIRED" } else { "pass" }
            ),
        ));
    }
    // 3. coherence_score < 0.3
    {
        let score_str = coherence_score
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "n/a".to_string());
        let tripped = coherence_score.is_some_and(|v| v < 0.3);
        rows.push((
            if tripped { "fired" } else { "" },
            format!(
                "[{}] coherence_score < 0.3  coherence={}  {}",
                if tripped { "X" } else { " " },
                score_str,
                if tripped { "FIRED" } else { "pass" }
            ),
        ));
    }
    // 4. debate_rounds >= 5
    {
        let rounds_str = debate_rounds
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".to_string());
        let tripped = debate_rounds.is_some_and(|v| v >= 5);
        rows.push((
            if tripped { "fired" } else { "" },
            format!(
                "[{}] debate_rounds >= 5  rounds={}  {}",
                if tripped { "X" } else { " " },
                rounds_str,
                if tripped { "FIRED" } else { "pass" }
            ),
        ));
    }
    // 5. explicit halt — there's no numeric value to show; the
    //    operator either pressed the button or didn't.
    {
        let explicit = decisions.iter().any(|d| {
            d.payload
                .get("assessment")
                .and_then(|a| a.get("explicit_halt"))
                .and_then(|v| v.as_bool())
                .unwrap_or_else(|| {
                    d.payload
                        .get("explicit_halt")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                })
        });
        let tripped = explicit;
        rows.push((
            if tripped { "fired" } else { "" },
            format!(
                "[{}] explicit_halt requested         {}",
                if tripped { "X" } else { " " },
                if tripped { "FIRED" } else { "pass" }
            ),
        ));
    }

    rows
}

/// Pull the live BAAAR inputs from the FraudAuditor's decision
/// payload. `None` fields mean "absent" — they're rendered as `n/a`
/// in the matrix instead of zero, so the judge can see what's
/// missing.
fn extract_assessment(
    decisions: &[AgentDecision],
) -> (Option<f32>, Option<f32>, Option<u32>, bool) {
    // Prefer the FraudAuditor's decision; fall back to any decision
    // that has an `assessment` block.
    let payload = decisions
        .iter()
        .find(|d| d.agent_id == "fraud_auditor")
        .map(|d| &d.payload)
        .or_else(|| {
            decisions
                .iter()
                .find(|d| d.payload.get("assessment").is_some())
                .map(|d| &d.payload)
        });

    let Some(payload) = payload else {
        return (None, None, None, false);
    };

    let inner = payload.get("assessment").unwrap_or(payload);
    let risk_score = inner.get("risk_score").and_then(|v| v.as_f64()).map(|v| v as f32);
    let coherence_score = inner
        .get("coherence_score")
        .and_then(|v| v.as_f64())
        .map(|v| v as f32);
    let debate_rounds = inner.get("debate_rounds").and_then(|v| v.as_u64()).map(|v| v as u32);
    let has_secret = inner
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|item| {
                item.get("kind")
                    .and_then(|k| k.as_str())
                    .is_some_and(|s| s == "secret_leak")
            })
        })
        .unwrap_or(false);

    (risk_score, coherence_score, debate_rounds, has_secret)
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
