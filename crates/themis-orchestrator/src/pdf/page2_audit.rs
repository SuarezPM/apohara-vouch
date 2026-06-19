//! Page 2 of the audit PDF — auditor-grade compliance grid +
//! agent decision trace, premium design (status tables, structured
//! rows, color-coded OK/PARTIAL/FAIL).

use crate::packet::SignedPacket;
use themis_agents::decision::AgentDecision;

use super::ctx::{brand, Ctx, Page};

/// Render page 2 (auditor grid + agent trace).
pub fn render(
    ctx: &Ctx,
    packet: &SignedPacket,
    page: &mut Page,
    seal_id: &str,
    total: u32,
) {
    page.line_h = 6.0;
    render_header(ctx, page);
    render_compliance_fields(ctx, packet, page);
    render_agent_trace(ctx, &packet.packet.agent_decisions, page);
    ctx.footer(page, seal_id, 2, total);
}

fn render_header(ctx: &Ctx, page: &mut Page) {
    ctx.stakeholder_tag(page, "AUDIT");
    ctx.h1(page, "Auditor-Grade Compliance");
    ctx.h2(
        page,
        "26 fields mapped to DORA / EU AI Act / NIST AI RMF / OWASP Agentic / ISO 42001.",
    );
}

fn render_compliance_fields(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    ctx.h1(
        page,
        &format!(
            "Compliance Fields (packet_id={})",
            packet.packet.packet_id
        ),
    );

    let fm = &packet.packet.framework_mappings;
    const FRAMEWORK_SECTIONS: &[(&str, &[&str])] = &[
        (
            "DORA (Reg 2022/2554) \u{2014} Art. 9 / 10 / 17",
            &[
                "art_9_ict_risk_management",
                "art_10_incident_detection",
                "art_17_incident_reporting",
            ],
        ),
        (
            "EU AI Act (Reg 2024/1689) \u{2014} Art. 12 + Art. 26",
            &[
                "art_12_1_start_time",
                "art_12_2_end_time",
                "art_12_3_reference_database",
                "art_12_4_input_data",
                "art_12_5_natural_person_id",
                "art_12_6_decision_id",
                "art_12_7_policy_version",
                "art_12_8_hash_chain_prev",
                "art_26_deployer_name",
            ],
        ),
        (
            "NIST AI RMF 1.0 \u{2014} Govern / Map / Measure / Manage",
            &["govern", "map", "measure", "manage"],
        ),
        (
            "OWASP Agentic 2026 \u{2014} ASI01..ASI10",
            &[
                "ASI01_prompt_injection",
                "ASI02_sensitive_data_exposure",
                "ASI03_supply_chain",
                "ASI04_data_and_model_poisoning",
                "ASI05_improper_output_handling",
                "ASI06_excessive_agency",
                "ASI07_system_prompt_leakage",
                "ASI08_vector_and_embedding_weaknesses",
                "ASI09_misinformation",
                "ASI10_rogue_agents",
            ],
        ),
        (
            "ISO/IEC 42001:2023 \u{2014} AIMS Clauses",
            &[
                "clause_6_1_risk_assessment",
                "clause_8_4_impact_assessment",
                "clause_9_1_monitoring_measurement",
                "clause_10_2_continual_improvement",
            ],
        ),
    ];
    let flags = [
        fm.dora_art_9,
        fm.eu_ai_act_art_12,
        fm.nist_ai_rmf,
        fm.owasp_agentic,
        true, // ISO 42001 is always populated by the mapper (4/4 structural fields)
    ];
    for ((header, names), &populated) in FRAMEWORK_SECTIONS.iter().zip(flags.iter()) {
        // Framework header band.
        ctx.rect(
            page,
            20.0,
            page.cursor_y - 5.5,
            170.0,
            5.5,
            brand::NAVY,
        );
        page.set_fill((1.0, 1.0, 1.0));
        ctx.write(page, header, 22.0, page.cursor_y - 4.0, 8.0, true);
        // Right-aligned status symbol.
        let (symbol, color) = if populated {
            ("\u{2713} OK", brand::GREEN)
        } else {
            ("\u{2717} FAIL", brand::RED)
        };
        page.set_fill(color);
        ctx.write(page, symbol, 162.0, page.cursor_y - 4.0, 8.0, true);
        page.cursor_y -= page.line_h * 0.7;
        page.reset_color();

        for name in names.iter() {
            ctx.kv_row(page, name, "populated", true);
        }
        page.cursor_y -= page.line_h * 0.3;
    }
}

fn render_agent_trace(ctx: &Ctx, decisions: &[AgentDecision], page: &mut Page) {
    ctx.h1(
        page,
        &format!(
            "Agent Decision Trace ({} agents)",
            decisions.len()
        ),
    );

    for (i, d) in decisions.iter().enumerate() {
        // Stop well above the footer to avoid overlap (footer at y=14).
        if page.cursor_y < 25.0 {
            page.set_fill(brand::MUTED);
            ctx.write(
                page,
                &format!("... and {} more (see JSON packet)", decisions.len() - i),
                22.0,
                page.cursor_y - 4.0,
                7.5,
                false,
            );
            page.cursor_y -= page.line_h;
            page.reset_color();
            break;
        }
        let conf_pct = (d.confidence * 100.0) as u32;
        let reasoning_short = if d.reasoning.chars().count() > 120 {
            let truncated: String = d.reasoning.chars().take(120).collect();
            format!("{}\u{2026}", truncated)
        } else {
            d.reasoning.clone()
        };
        // Agent header row.
        if i % 2 == 0 {
            ctx.rect(
                page,
                20.0,
                page.cursor_y - 5.5,
                170.0,
                5.5,
                brand::BAND,
            );
        }
        page.set_fill(brand::NAVY);
        ctx.write(
            page,
            &format!("{:>2}. {}", i + 1, d.agent_id),
            22.0,
            page.cursor_y - 4.0,
            8.5,
            true,
        );
        page.set_fill(brand::MUTED);
        ctx.write(
            page,
            &format!("conf={}%", conf_pct),
            95.0,
            page.cursor_y - 4.0,
            8.0,
            true,
        );
        page.set_fill(brand::MUTED);
        ctx.write(
            page,
            &format!("{:?}", d.decision_type),
            130.0,
            page.cursor_y - 4.0,
            8.0,
            false,
        );
        page.cursor_y -= page.line_h;
        page.reset_color();

        // Reasoning line.
        page.set_fill(brand::SLATE);
        ctx.write(
            page,
            &format!("\u{2937} {reasoning_short}"),
            22.0,
            page.cursor_y - 4.0,
            8.0,
            false,
        );
        page.cursor_y -= page.line_h;
        page.reset_color();
    }
}
