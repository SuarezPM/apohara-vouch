//! Shared context + drawing helpers for the premium audit PDF.
//!
//! Holds the locked document handle, the two builtin fonts, and a
//! suite of small drawing helpers that every page uses. The design
//! language mirrors the Apohara Synthex evidence report (prior art):
//! navy hero band, gold accent, color-coded verdicts, monospace
//! crypto values, structured tables, and a per-page footer carrying
//! the seal id and page number.

use printpdf::{
    path::{PaintMode, WindingOrder},
    Color, IndirectFontRef, Line, Mm, PdfDocumentReference, PdfLayerReference, Point, Polygon, Rgb,
};

/// Apohara brand color tokens. All in 0.0..=1.0 sRGB.
pub mod brand {
    use super::Rgb;

    /// Deep navy — hero band, body text on light.
    pub const NAVY: (f64, f64, f64) = (0.039, 0.078, 0.157);
    /// Gold accent — VOUCH brand highlight, dividers on dark.
    pub const GOLD: (f64, f64, f64) = (0.831, 0.627, 0.090);
    /// Cool blue — mini-labels, links, "FOR" tags.
    pub const BLUE: (f64, f64, f64) = (0.290, 0.435, 0.647);
    /// Slate — body text on light backgrounds.
    pub const SLATE: (f64, f64, f64) = (0.122, 0.161, 0.220);
    /// Muted — secondary text, footer, table headers.
    pub const MUTED: (f64, f64, f64) = (0.420, 0.447, 0.502);
    /// Rule — hairline dividers.
    pub const RULE: (f64, f64, f64) = (0.890, 0.894, 0.898);
    /// Light band — alternating table row.
    pub const BAND: (f64, f64, f64) = (0.973, 0.976, 0.980);
    /// Crypto bg — chip background under monospace values.
    pub const CRYPTO_BG: (f64, f64, f64) = (0.945, 0.949, 0.957);

    /// APPROVED verdict.
    pub const GREEN: (f64, f64, f64) = (0.039, 0.541, 0.290);
    /// HALT verdict.
    pub const RED: (f64, f64, f64) = (0.773, 0.125, 0.165);
    /// REVIEW verdict.
    pub const AMBER: (f64, f64, f64) = (0.851, 0.467, 0.024);

    /// Build a printpdf `Rgb` from a token triple.
    pub fn rgb(t: (f64, f64, f64)) -> Rgb {
        Rgb::new(t.0 as f32, t.1 as f32, t.2 as f32, None)
    }
}

/// Per-page state. `cursor_y` is in millimetres, `line_h` is the
/// default line height in millimetres.
pub struct Page {
    pub layer: PdfLayerReference,
    pub cursor_y: f32,
    pub line_h: f32,
}

impl Page {
    /// Set the active fill color.
    pub fn set_fill(&self, t: (f64, f64, f64)) {
        self.layer.set_fill_color(Color::Rgb(brand::rgb(t)));
    }

    /// Reset fill color to slate (default body color).
    pub fn reset_color(&self) {
        self.set_fill(brand::SLATE);
    }
}

/// Document-wide state shared across all pages. Holds references to
/// the two builtin fonts (regular + bold).
pub struct Ctx<'a> {
    pub doc: &'a PdfDocumentReference,
    pub font_regular: &'a IndirectFontRef,
    pub font_bold: &'a IndirectFontRef,
}

impl<'a> Ctx<'a> {
    /// Build a new A4 portrait page.
    pub fn add_a4_page(&self, layer_name: &str) -> Page {
        let (page_idx, layer_idx) = self.doc.add_page(Mm(210.0), Mm(297.0), layer_name);
        let layer = self.doc.get_page(page_idx).get_layer(layer_idx);
        layer.set_fill_color(Color::Rgb(brand::rgb(brand::SLATE)));
        Page {
            layer,
            cursor_y: 280.0,
            line_h: 7.0,
        }
    }

    /// Write one line of text at `(x, y)` on the given page layer.
    pub fn write(&self, page: &Page, text: &str, x: f32, y: f32, size: f32, bold: bool) {
        let font = if bold { self.font_bold } else { self.font_regular };
        page.layer.use_text(text, size, Mm(x), Mm(y), font);
    }

    // ===== Drawing helpers (the premium design language) =====

    /// Draw a filled rectangle in mm coordinates. Used for the navy
    /// hero band, the verdict pill, the monospace value chip, and
    /// the alternating table rows.
    pub fn rect(&self, page: &Page, x: f32, y: f32, w: f32, h: f32, color: (f64, f64, f64)) {
        page.set_fill(color);
        let ring = vec![
            (Point::new(Mm(x), Mm(y)), false),
            (Point::new(Mm(x + w), Mm(y)), false),
            (Point::new(Mm(x + w), Mm(y + h)), false),
            (Point::new(Mm(x), Mm(y + h)), false),
        ];
        let poly = Polygon {
            rings: vec![ring],
            mode: PaintMode::Fill,
            winding_order: WindingOrder::NonZero,
        };
        page.layer.add_polygon(poly);
        page.reset_color();
    }

    /// Draw a horizontal hairline divider. The color is the muted
    /// rule gray by default.
    pub fn hr(&self, page: &Page, x: f32, y: f32, w: f32) {
        let color = brand::RULE;
        page.set_fill(color);
        let line = Line {
            points: vec![
                (Point::new(Mm(x), Mm(y)), false),
                (Point::new(Mm(x + w), Mm(y)), false),
            ],
            is_closed: false,
        };
        page.layer.add_line(line);
        page.reset_color();
    }

    /// Draw the navy hero band at the top of page 1. Includes the
    /// APOHARA VOUCH brand mark + tagline in white + gold.
    /// `width_mm` should be ~190 (the printable area on A4).
    pub fn hero_band(&self, page: &mut Page, width_mm: f32) {
        // Navy background, 22mm tall.
        self.rect(page, 10.0, page.cursor_y - 22.0, width_mm, 22.0, brand::NAVY);

        // Gold rule under the band.
        self.rect(
            page,
            10.0,
            page.cursor_y - 24.0,
            width_mm,
            0.6,
            brand::GOLD,
        );

        // APOHARA · VOUCH title in white.
        page.set_fill((1.0, 1.0, 1.0));
        self.write(
            page,
            "APOHARA \u{00B7} VOUCH",
            16.0,
            page.cursor_y - 10.0,
            18.0,
            true,
        );

        // Tagline in gold.
        page.set_fill(brand::GOLD);
        self.write(
            page,
            "Evidence Packet",
            16.0,
            page.cursor_y - 16.5,
            9.0,
            false,
        );

        // Right-aligned seal id in muted white.
        page.set_fill((0.78, 0.82, 0.88));
        self.write(
            page,
            "vouch.apohara.dev",
            145.0,
            page.cursor_y - 16.5,
            8.0,
            false,
        );

        page.reset_color();
        page.cursor_y -= 30.0;
    }

    /// Draw a small uppercase "FOR <stakeholder>" tag. Used at the
    /// top of stakeholder pages (CISO, CFO, GC, Broker).
    pub fn stakeholder_tag(&self, page: &mut Page, audience: &str) {
        page.set_fill(brand::BLUE);
        self.write(
            page,
            &format!("FOR {audience}"),
            20.0,
            page.cursor_y - 4.0,
            7.5,
            true,
        );
        page.cursor_y -= page.line_h * 1.4;
        page.reset_color();
    }

    /// Section title: 11pt bold, slate.
    pub fn h1(&self, page: &mut Page, text: &str) {
        self.write(page, text, 20.0, page.cursor_y, 14.0, true);
        page.cursor_y -= page.line_h * 1.1;
    }

    /// Section subtitle / lead: 9pt regular, muted, italic-looking
    /// (sans-serif doesn't have italic so we just use a smaller size
    /// and lighter color).
    pub fn h2(&self, page: &mut Page, text: &str) {
        page.set_fill(brand::MUTED);
        self.write(page, text, 20.0, page.cursor_y, 9.0, false);
        page.cursor_y -= page.line_h * 1.0;
        page.reset_color();
    }

    /// Body paragraph: 9.5pt regular, slate.
    pub fn body(&self, page: &mut Page, text: &str) {
        self.write(page, text, 20.0, page.cursor_y, 9.5, false);
        page.cursor_y -= page.line_h;
    }

    /// Bold body line: 9.5pt bold, slate.
    pub fn body_bold(&self, page: &mut Page, text: &str) {
        self.write(page, text, 20.0, page.cursor_y, 9.5, true);
        page.cursor_y -= page.line_h;
    }

    /// Verdict hero: large bold text in the verdict color.
    /// `text` is the verdict string ("APPROVED" / "HALT" /
    /// "REVIEW REQUIRED"); `color` is the brand token.
    pub fn verdict_hero(&self, page: &mut Page, text: &str, color: (f64, f64, f64)) {
        self.rect(
            page,
            20.0,
            page.cursor_y - 14.0,
            170.0,
            12.0,
            color,
        );
        page.set_fill((1.0, 1.0, 1.0));
        self.write(page, text, 26.0, page.cursor_y - 9.5, 22.0, true);
        page.cursor_y -= page.line_h * 2.6;
        page.reset_color();
    }

    /// Draw a chip-style value display: a light gray rounded rect
    /// with a small uppercase label above, then the value in slate.
    /// `value` is rendered in the regular font (which is what we
    /// have; a true monospace would require bundling a TTF).
    pub fn crypto_field(&self, page: &mut Page, label: &str, value: &str) {
        page.set_fill(brand::MUTED);
        self.write(
            page,
            &format!("{label}"),
            20.0,
            page.cursor_y - 1.0,
            7.0,
            true,
        );
        page.cursor_y -= page.line_h * 0.85;

        // Chip background.
        self.rect(
            page,
            20.0,
            page.cursor_y - 6.5,
            170.0,
            6.5,
            brand::CRYPTO_BG,
        );
        page.set_fill(brand::SLATE);
        self.write(
            page,
            value,
            22.0,
            page.cursor_y - 4.5,
            8.5,
            false,
        );
        page.cursor_y -= page.line_h * 1.1;
        page.reset_color();
    }

    /// Table row with two columns (label + value). The label is
    /// rendered in muted small caps, the value in slate.
    pub fn kv_row(
        &self,
        page: &mut Page,
        label: &str,
        value: &str,
        banded: bool,
    ) {
        if banded {
            self.rect(
                page,
                20.0,
                page.cursor_y - 6.0,
                170.0,
                6.5,
                brand::BAND,
            );
        }
        page.set_fill(brand::MUTED);
        self.write(
            page,
            label,
            22.0,
            page.cursor_y - 4.5,
            8.0,
            true,
        );
        page.set_fill(brand::SLATE);
        self.write(
            page,
            value,
            72.0,
            page.cursor_y - 4.5,
            9.0,
            false,
        );
        page.cursor_y -= page.line_h;
    }

    /// Status check row: ✓ OK / ▲ PARTIAL / ✗ FAIL with the actual
    /// text. Color codes the symbol.
    pub fn status_row(
        &self,
        page: &mut Page,
        symbol: &str,
        status: &str,
        text: &str,
        color: (f64, f64, f64),
    ) {
        page.set_fill(color);
        self.write(
            page,
            symbol,
            22.0,
            page.cursor_y - 4.5,
            10.0,
            true,
        );
        page.set_fill(brand::SLATE);
        self.write(
            page,
            status,
            32.0,
            page.cursor_y - 4.5,
            9.0,
            true,
        );
        page.set_fill(brand::MUTED);
        self.write(
            page,
            text,
            52.0,
            page.cursor_y - 4.5,
            8.5,
            false,
        );
        page.cursor_y -= page.line_h;
    }

    /// Footer: a hairline + the seal id (left) + the page number
    /// (right). Drawn at the very bottom of the page.
    pub fn footer(&self, page: &Page, seal_id: &str, page_n: u32, total: u32) {
        self.hr(page, 20.0, 14.0, 170.0);
        page.set_fill(brand::MUTED);
        self.write(
            page,
            seal_id,
            20.0,
            10.0,
            7.0,
            false,
        );
        self.write(
            page,
            "The seal proves WHEN this evidence existed and that it is unchanged \u{2014} not that any claim inside is accurate.",
            20.0,
            7.0,
            6.5,
            false,
        );
        self.write(
            page,
            &format!("p. {page_n} / {total}"),
            175.0,
            10.0,
            7.0,
            false,
        );
        page.reset_color();
    }
}
