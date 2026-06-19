//! Shared context for the PDF renderer.
//!
//! `PdfDocumentReference` is the locked handle printpdf hands out for
//! the whole document; every page layer borrows from it. Carrying
//! that + the two builtin fonts (regular + bold) through every page
//! function is the reason this module exists: without it the
//! signatures would explode to 4 args per page.

use printpdf::{IndirectFontRef, Mm, PdfDocumentReference, PdfLayerReference};

/// Per-page state. `cursor_y` is in millimetres, `line_h` is the
/// default line height in millimetres (different per page because
/// page 1 has 9 sections and page 2+ has denser grids).
pub struct Page {
    /// The locked layer reference for this page.
    pub layer: PdfLayerReference,
    /// Current vertical cursor in millimetres. Starts near the top
    /// (~280mm on A4) and moves DOWN as content is written.
    pub cursor_y: f32,
    /// Default line height for this page in millimetres.
    pub line_h: f32,
}

impl Page {
    /// Reset fill color to black. Useful at the top of every page
    /// because page 1's HALT/APPROVED stamps leave the layer filled
    /// red or green.
    pub fn reset_color(&self) {
        use printpdf::{Color, Rgb};
        self.layer
            .set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
    }
}

/// Document-wide state shared across all pages. Holds direct
/// references to the two builtin fonts (regular + bold). The caller
/// is responsible for building the `Ctx` AFTER `add_builtin_font`
/// succeeds; do not construct via `Default`.
pub struct Ctx<'a> {
    /// The locked document handle that every page layer borrows from.
    pub doc: &'a PdfDocumentReference,
    /// Built-in Helvetica (regular weight).
    pub font_regular: &'a IndirectFontRef,
    /// Built-in Helvetica (bold weight).
    pub font_bold: &'a IndirectFontRef,
}

impl<'a> Ctx<'a> {
    /// Build a new A4 portrait page. Returns the new `Page` ready
    /// for rendering. The printpdf `add_page` API gives us a
    /// `(page_idx, layer_idx)` tuple we then resolve to a layer.
    pub fn add_a4_page(&self, layer_name: &str) -> Page {
        let (page_idx, layer_idx) = self.doc.add_page(Mm(210.0), Mm(297.0), layer_name);
        let layer = self.doc.get_page(page_idx).get_layer(layer_idx);
        // Reset fill color to black on every fresh page.
        use printpdf::{Color, Rgb};
        layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
        Page {
            layer,
            cursor_y: 280.0,
            line_h: 7.0,
        }
    }

    /// Convenience: write one line of text at `(x, y)` on the given
    /// page layer, choosing bold or regular font.
    pub fn write(&self, page: &Page, text: &str, x: f32, y: f32, size: f32, bold: bool) {
        let font = if bold { self.font_bold } else { self.font_regular };
        page.layer.use_text(text, size, Mm(x), Mm(y), font);
    }
}
