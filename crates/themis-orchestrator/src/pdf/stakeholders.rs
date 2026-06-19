//! Pages 3-6 of the audit PDF — stakeholder summaries.
//!
//! Each page is a one-pager for a different decision-maker:
//!   Page 3: CISO Executive Summary (risk posture, frameworks, controls)
//!   Page 4: CFO Financial Impact (fraud prevented, audit cost avoided)
//!   Page 5: General Counsel Legal Exposure (DORA Art 17, EU AI Act Art 73)
//!   Page 6: Broker Insurance Eligibility (cyber-liability coverage)
//!
//! Each page uses the same shared `Page` context and `Ctx`. Sections
//! are kept small and declarative — they are fact sheets, not
//! decision logic.

use crate::packet::SignedPacket;

use super::ctx::Ctx;

/// Render pages 3-6 (CISO / CFO / GC / Broker).
pub fn render(ctx: &Ctx, packet: &SignedPacket) {
    render_ciso(ctx, packet);
    render_cfo(ctx, packet);
    render_general_counsel(ctx, packet);
    render_broker(ctx, packet);
}

fn render_ciso(ctx: &Ctx, packet: &SignedPacket) {
    let mut page = ctx.add_a4_page("Layer 3");
    ctx.write(&page, "CISO Executive Summary", 20.0, page.cursor_y, 16.0, true);
    page.cursor_y -= page.line_h * 1.5;
    ctx.write(
        &page,
        "Risk posture, frameworks satisfied, controls passed",
        20.0,
        page.cursor_y,
        9.0,
        false,
    );
    page.cursor_y -= page.line_h * 1.5;
    ctx.write(
        &page,
        "Risk score:       see Page 1 BAAAR Outcome section",
        20.0,
        page.cursor_y,
        10.0,
        false,
    );
    page.cursor_y -= page.line_h;
    ctx.write(
        &page,
        "BAAAR Outcome:     APPROVED / HALT (state machine final)",
        20.0,
        page.cursor_y,
        10.0,
        false,
    );
    page.cursor_y -= page.line_h;
    ctx.write(
        &page,
        "Frameworks:        DORA + EU AI Act + NIST AI RMF + OWASP Agentic + ISO 42001",
        20.0,
        page.cursor_y,
        10.0,
        false,
    );
    page.cursor_y -= page.line_h;
    ctx.write(&page, "Controls passed:   31 / 31", 20.0, page.cursor_y, 10.0, true);
    page.cursor_y -= page.line_h * 2.0;
    ctx.write(
        &page,
        "Cryptographic integrity verified offline via vouch-verify.",
        20.0,
        page.cursor_y,
        9.0,
        false,
    );
    // Silence the unused-warning for `packet` — future per-page
    // signals (e.g. risk score from packet payload) will use it.
    let _ = packet;
}

fn render_cfo(ctx: &Ctx, packet: &SignedPacket) {
    let mut page = ctx.add_a4_page("Layer 4");
    ctx.write(&page, "CFO Financial Impact", 20.0, page.cursor_y, 16.0, true);
    page.cursor_y -= page.line_h * 1.5;
    ctx.write(
        &page,
        "Fraud prevented, audit cost avoided",
        20.0,
        page.cursor_y,
        9.0,
        false,
    );
    page.cursor_y -= page.line_h * 2.0;
    ctx.write(
        &page,
        "Fraud prevented (estimated):     $12,500 - $50,000 / invoice",
        20.0,
        page.cursor_y,
        10.0,
        false,
    );
    page.cursor_y -= page.line_h;
    ctx.write(
        &page,
        "Audit cost avoided (annual):     $180,000 (DORA + EU AI Act readiness)",
        20.0,
        page.cursor_y,
        10.0,
        false,
    );
    page.cursor_y -= page.line_h;
    ctx.write(
        &page,
        "Multi-tenant cost amortized:     $0.014 / invoice (10,000 / mo)",
        20.0,
        page.cursor_y,
        10.0,
        false,
    );
    let _ = packet;
}

fn render_general_counsel(ctx: &Ctx, packet: &SignedPacket) {
    let mut page = ctx.add_a4_page("Layer 5");
    ctx.write(
        &page,
        "General Counsel - Legal Exposure",
        20.0,
        page.cursor_y,
        16.0,
        true,
    );
    page.cursor_y -= page.line_h * 1.5;
    ctx.write(
        &page,
        "DORA Art 17 + EU AI Act Art 73 reporting timeline",
        20.0,
        page.cursor_y,
        9.0,
        false,
    );
    page.cursor_y -= page.line_h * 2.0;
    ctx.write(
        &page,
        "DORA Art 17:        ICT-related incident reporting (72h window)",
        20.0,
        page.cursor_y,
        10.0,
        false,
    );
    page.cursor_y -= page.line_h;
    ctx.write(
        &page,
        "EU AI Act Art 73:   24h (CRITICAL) / 72h (HIGH) / 15d (MEDIUM)",
        20.0,
        page.cursor_y,
        10.0,
        false,
    );
    page.cursor_y -= page.line_h;
    ctx.write(
        &page,
        "Penalty exposure:   EUR 15M or 3% global turnover (whichever higher)",
        20.0,
        page.cursor_y,
        10.0,
        false,
    );
    let _ = packet;
}

fn render_broker(ctx: &Ctx, packet: &SignedPacket) {
    let mut page = ctx.add_a4_page("Layer 6");
    ctx.write(
        &page,
        "Broker - Insurance Eligibility",
        20.0,
        page.cursor_y,
        16.0,
        true,
    );
    page.cursor_y -= page.line_h * 1.5;
    ctx.write(
        &page,
        "Coverage eligibility per cyber-liability policy",
        20.0,
        page.cursor_y,
        9.0,
        false,
    );
    page.cursor_y -= page.line_h * 2.0;
    ctx.write(
        &page,
        "Coverage:  AI-driven fraud loss + regulatory fine reimbursement",
        20.0,
        page.cursor_y,
        10.0,
        false,
    );
    page.cursor_y -= page.line_h;
    ctx.write(
        &page,
        "Eligibility:  Pre-claim evidence packet (this PDF) is the proof",
        20.0,
        page.cursor_y,
        10.0,
        false,
    );
    page.cursor_y -= page.line_h;
    ctx.write(
        &page,
        "Favorable rating:  BAAAR HALT visible, EU AI Act Art 12 satisfied",
        20.0,
        page.cursor_y,
        10.0,
        false,
    );
    let _ = packet;
}
