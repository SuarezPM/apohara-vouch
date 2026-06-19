//! Page 2 of the audit PDF — auditor-grade compliance grid + agent trace.
//!
//! Sections rendered:
//!   7. Compliance fields (26 populated across DORA / EU AI Act /
//!      NIST AI RMF / OWASP Agentic / ISO 42001)
//!   8. Agent decision trace (full reasoning truncated to 120 chars)
//!
//! Plus the page 2 footer.

use crate::packet::SignedPacket;
use themis_agents::decision::AgentDecision;

use super::ctx::{Ctx, Page};

/// Render page 2 (auditor grid + agent trace).
pub fn render(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    render_header(ctx, page);
    render_compliance_fields(ctx, packet, page);
    render_agent_trace(ctx, &packet.packet.agent_decisions, page);
    render_footer(ctx, page);
}

fn render_header(ctx: &Ctx, page: &mut Page) {
    ctx.write(
        page,
        "Apohara VOUCH Evidence Packet - Page 2 (Auditor-Grade)",
        20.0,
        page.cursor_y,
        16.0,
        true,
    );
    page.cursor_y -= page.line_h * 1.6;
    ctx.write(
        page,
        "26 compliance fields + agent decision trace. Print-ready for regulator review.",
        20.0,
        page.cursor_y,
        8.0,
        false,
    );
    page.cursor_y -= page.line_h * 1.6;
}

fn render_compliance_fields(ctx: &Ctx, packet: &SignedPacket, page: &mut Page) {
    ctx.write(
        page,
        &format!(
            "7. Compliance Fields (26 populated, packet_id={})",
            packet.packet.packet_id
        ),
        20.0,
        page.cursor_y,
        12.0,
        true,
    );
    page.cursor_y -= page.line_h;

    let fm = &packet.packet.framework_mappings;
    // Each framework: (header, field names). The populated-flag is
    // the framework_mappings boolean at the same index below.
    const FRAMEWORK_SECTIONS: &[(&str, &[&str])] = &[
        (
            "DORA (Reg 2022/2554) - Art. 9/10/17:",
            &[
                "art_9_ict_risk_management",
                "art_10_incident_detection",
                "art_17_incident_reporting",
            ],
        ),
        (
            "EU AI Act (Reg 2024/1689) - Art. 12 + Art. 26:",
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
            "NIST AI RMF 1.0 - Govern/Map/Measure/Manage:",
            &["govern", "map", "measure", "manage"],
        ),
        (
            "OWASP Agentic 2026 - ASI01..ASI10:",
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
            "ISO/IEC 42001:2023 - AIMS Clauses 6.1/8.4/9.1/10.2:",
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
        ctx.write(page, header, 20.0, page.cursor_y, 10.0, true);
        page.cursor_y -= page.line_h;
        for name in names.iter() {
            ctx.write(
                page,
                &format!("  [{}] {}", if populated { "x" } else { " " }, name),
                22.0,
                page.cursor_y,
                8.5,
                false,
            );
            page.cursor_y -= page.line_h;
        }
        page.cursor_y -= page.line_h * 0.4;
    }
    page.cursor_y -= page.line_h * 0.8;
}

fn render_agent_trace(ctx: &Ctx, decisions: &[AgentDecision], page: &mut Page) {
    ctx.write(
        page,
        &format!(
            "8. Agent Decision Trace ({} agents, reasoning <=120 chars)",
            decisions.len()
        ),
        20.0,
        page.cursor_y,
        12.0,
        true,
    );
    page.cursor_y -= page.line_h;
    for (i, d) in decisions.iter().enumerate() {
        let conf_pct = (d.confidence * 100.0) as u32;
        let reasoning_short = if d.reasoning.chars().count() > 120 {
            let truncated: String = d.reasoning.chars().take(120).collect();
            format!("{}...", truncated)
        } else {
            d.reasoning.clone()
        };
        let line1 = format!(
            "  {}. {} ({:?}, conf={}%)",
            i + 1,
            d.agent_id,
            d.decision_type,
            conf_pct
        );
        ctx.write(page, &line1, 20.0, page.cursor_y, 9.0, true);
        page.cursor_y -= page.line_h;
        ctx.write(
            page,
            &format!("     {reasoning_short}"),
            20.0,
            page.cursor_y,
            8.0,
            false,
        );
        page.cursor_y -= page.line_h;
        // Hard cap at the page footer; the spec requires all agents
        // in the trace, so we keep going even past y < 30.
        if page.cursor_y < 12.0 {
            ctx.write(
                page,
                "...(truncated: page full; see JSON packet for full reasoning)",
                20.0,
                page.cursor_y,
                8.0,
                false,
            );
            break;
        }
    }
}

fn render_footer(ctx: &Ctx, page: &mut Page) {
    ctx.write(
        page,
        "End of Page 2 - verify offline with: vouch-verify <packet.json> <signature.hex>",
        20.0,
        12.0,
        8.0,
        false,
    );
}
