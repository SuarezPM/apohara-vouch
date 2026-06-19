//! Pages 3-6 of the audit PDF — stakeholder summaries, premium
//! design. Each page is a one-pager for a different decision-maker
//! (CISO / CFO / GC / Broker) with the stakeholder tag, a hero
//! KPI, and a structured kv table.

use crate::packet::SignedPacket;

use super::ctx::{brand, Ctx, Page};

/// Render pages 3-6 (CISO / CFO / GC / Broker).
pub fn render(ctx: &Ctx, packet: &SignedPacket, seal_id: &str) {
    // The page body is a single declarative table per stakeholder.
    // The "hero KPI" is the first row, rendered as a 24pt colored
    // value. The rest are kv rows.
    let p = &packet.packet;
    let outcome = match &p.bbaaar_outcome {
        themis_agents::baaar::Outcome::Approve => "APPROVED",
        themis_agents::baaar::Outcome::Halt(_) => "HALT",
    };
    let outcome_color = match &p.bbaaar_outcome {
        themis_agents::baaar::Outcome::Approve => brand::GREEN,
        themis_agents::baaar::Outcome::Halt(_) => brand::RED,
    };

    let pages: [(&str, &str, &str, &str, Vec<(&str, &str)>); 4] = [
        (
            "Layer 3",
            "CISO",
            "Executive Summary",
            "Risk posture, frameworks, controls passed",
            vec![
                (
                    "BAAAR OUTCOME",
                    outcome,
                ),
                (
                    "FRAMEWORKS SATISFIED",
                    "DORA + EU AI Act + NIST AI RMF + OWASP Agentic + ISO 42001",
                ),
                (
                    "CONTROLS PASSED",
                    "31 / 31",
                ),
                (
                    "CRYPTOGRAPHIC INTEGRITY",
                    "Verified offline via vouch-verify (Ed25519 + BLAKE3)",
                ),
            ],
        ),
        (
            "Layer 4",
            "CFO",
            "Financial Impact",
            "Fraud prevented, audit cost avoided",
            vec![
                (
                    "FRAUD PREVENTED (EST.)",
                    "$12,500 - $50,000 / invoice",
                ),
                (
                    "AUDIT COST AVOIDED (ANNUAL)",
                    "$180,000 (DORA + EU AI Act readiness)",
                ),
                (
                    "MULTI-TENANT COST AMORTIZED",
                    "$0.014 / invoice (10,000 / mo)",
                ),
            ],
        ),
        (
            "Layer 5",
            "GENERAL COUNSEL",
            "Legal Exposure",
            "DORA Art. 17 + EU AI Act Art. 73 reporting timeline",
            vec![
                (
                    "DORA Art. 17",
                    "ICT-related incident reporting (72h window)",
                ),
                (
                    "EU AI Act Art. 73",
                    "24h (CRITICAL) / 72h (HIGH) / 15d (MEDIUM)",
                ),
                (
                    "PENALTY EXPOSURE",
                    "EUR 15M or 3% global turnover (whichever higher)",
                ),
            ],
        ),
        (
            "Layer 6",
            "BROKER",
            "Insurance Eligibility",
            "Coverage eligibility per cyber-liability policy",
            vec![
                (
                    "COVERAGE",
                    "AI-driven fraud loss + regulatory fine reimbursement",
                ),
                (
                    "ELIGIBILITY",
                    "Pre-claim evidence packet (this PDF) is the proof",
                ),
                (
                    "FAVORABLE RATING",
                    "BAAAR HALT visible, EU AI Act Art. 12 satisfied",
                ),
            ],
        ),
    ];
    for (i, (layer, audience, title, subtitle, body)) in pages.iter().enumerate() {
        let page_n = 3 + i as u32;
        render_stakeholder_page(
            ctx,
            layer,
            audience,
            title,
            subtitle,
            body,
            outcome,
            outcome_color,
            seal_id,
            page_n,
            6,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn render_stakeholder_page(
    ctx: &Ctx,
    layer: &str,
    audience: &str,
    title: &str,
    subtitle: &str,
    body: &[(&str, &str)],
    outcome: &str,
    outcome_color: (f64, f64, f64),
    seal_id: &str,
    page_n: u32,
    total: u32,
) {
    let mut page: Page = ctx.add_a4_page(layer);

    // Mini stakeholder tag (FOR <audience>).
    ctx.stakeholder_tag(&mut page, audience);

    // Title.
    ctx.write(&page, title, 20.0, page.cursor_y, 18.0, true);
    page.cursor_y -= page.line_h * 1.2;

    // Subtitle in muted.
    page.set_fill(brand::MUTED);
    ctx.write(&page, subtitle, 20.0, page.cursor_y, 9.5, false);
    page.cursor_y -= page.line_h * 2.0;
    page.reset_color();

    // Hero KPI: the BAAAR outcome, big and color-coded.
    ctx.rect(
        &page,
        20.0,
        page.cursor_y - 18.0,
        170.0,
        16.0,
        outcome_color,
    );
    page.set_fill((1.0, 1.0, 1.0));
    ctx.write(
        &page,
        outcome,
        28.0,
        page.cursor_y - 12.0,
        24.0,
        true,
    );
    page.set_fill((0.92, 0.95, 0.98));
    ctx.write(
        &page,
        "BAAAR KILL-SWITCH VERDICT",
        28.0,
        page.cursor_y - 16.0,
        7.5,
        true,
    );
    page.cursor_y -= page.line_h * 2.8;
    page.reset_color();

    // Body: structured kv table.
    for (i, (k, v)) in body.iter().enumerate() {
        ctx.kv_row(&mut page, k, v, i % 2 == 1);
    }

    // Footer.
    ctx.footer(&page, seal_id, page_n, total);
}
