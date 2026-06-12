//! 3 variants + auto-select by word count.
//!
//! Ported from Context Forge's `compressor.py:147-200` (the
//! `compress_with_variant` + `auto_compress` triplet). Three variants
//! with different rate + chunk profiles:
//!
//! * **Short** — small contexts (≤ 512 words). Aggressive compression
//!   (rate 0.3) at small chunk (80 words). Use case: invoice headers,
//!   single-line summaries.
//! * **Medium** — typical context (≤ 2048 words). Default rate (0.5)
//!   at standard chunk (160 words). Use case: invoice body + 1 PO.
//! * **Long** — long context (> 2048 words). Loose rate (0.7) at large
//!   chunk (320 words) so the perplexity ranking has enough signal.
//!   Use case: multi-page audit trail.
//!
//! The boundaries are inclusive of the lower bound: ≤ 512 → Short
//! (not Medium), ≤ 2048 → Medium (not Long), > 2048 → Long. This
//! matches the original Python comparator `if word_count <= 512`.

use crate::classifier::CompressionConfig;

/// The 3 compression profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Variant {
    /// Small contexts (≤ 512 words). Aggressive compression.
    Short,
    /// Typical context (≤ 2048 words). Default rate.
    Medium,
    /// Long context (> 2048 words). Loose rate, large chunk.
    Long,
}

impl Variant {
    /// Stable string identifier (used in `CompressionConfig` telemetry
    /// + Evidence Packet).
    pub fn name(&self) -> &'static str {
        match self {
            Variant::Short => "short",
            Variant::Medium => "medium",
            Variant::Long => "long",
        }
    }
}

/// Per-variant rate + chunk profile. Rate is the fraction of words
/// to drop; chunk_size_words caps how many words the perplexity ranker
/// sees at once.
#[derive(Debug, Clone, PartialEq)]
pub struct VariantConfig {
    /// Target rate for the variant (0.0 keep all, 1.0 drop all).
    pub target_rate: f32,
    /// Max words per chunk for the variant.
    pub chunk_size_words: usize,
}

impl VariantConfig {
    /// Build a config from a variant. The rates and chunk sizes are
    /// constants tied to the variant — there is no public constructor
    /// that takes free-form numbers, to keep the 3 profiles canonical.
    pub fn for_variant(v: Variant) -> Self {
        match v {
            Variant::Short => Self {
                target_rate: 0.3,
                chunk_size_words: 80,
            },
            Variant::Medium => Self {
                target_rate: 0.5,
                chunk_size_words: 160,
            },
            Variant::Long => Self {
                target_rate: 0.7,
                chunk_size_words: 320,
            },
        }
    }

    /// Build a `CompressionConfig` (from `crate::classifier`) that
    /// uses this variant's rate and chunk profile, with the default
    /// force tokens.
    pub fn to_compression_config(&self) -> CompressionConfig {
        CompressionConfig {
            rate: self.target_rate,
            chunk_size_words: self.chunk_size_words,
            ..CompressionConfig::default()
        }
    }
}

/// Pick the variant for a context of `word_count` words.
///
/// Boundaries are inclusive of the lower bound:
/// * `word_count <= 512`  → `Short`
/// * `word_count <= 2048` → `Medium`
/// * `word_count >  2048` → `Long`
pub fn auto_select(word_count: usize) -> Variant {
    if word_count <= 512 {
        Variant::Short
    } else if word_count <= 2048 {
        Variant::Medium
    } else {
        Variant::Long
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_name() {
        assert_eq!(Variant::Short.name(), "short");
    }

    #[test]
    fn medium_name() {
        assert_eq!(Variant::Medium.name(), "medium");
    }

    #[test]
    fn long_name() {
        assert_eq!(Variant::Long.name(), "long");
    }

    #[test]
    fn auto_select_short_at_100_words() {
        assert_eq!(auto_select(100), Variant::Short);
    }

    #[test]
    fn auto_select_medium_at_1024_words() {
        assert_eq!(auto_select(1024), Variant::Medium);
    }

    #[test]
    fn auto_select_long_at_5000_words() {
        assert_eq!(auto_select(5000), Variant::Long);
    }

    #[test]
    fn auto_select_short_inclusive_at_512() {
        // Boundary: exactly 512 is Short (inclusive of lower bound).
        assert_eq!(auto_select(512), Variant::Short);
    }

    #[test]
    fn auto_select_medium_inclusive_at_2048() {
        // Boundary: exactly 2048 is Medium (inclusive of lower bound).
        assert_eq!(auto_select(2048), Variant::Medium);
    }

    #[test]
    fn auto_select_long_strictly_above_2048() {
        // Strict >: 2049 is Long.
        assert_eq!(auto_select(2049), Variant::Long);
    }

    #[test]
    fn auto_select_zero_words_is_short() {
        // 0 ≤ 512 → Short (degenerate but defined).
        assert_eq!(auto_select(0), Variant::Short);
    }

    #[test]
    fn short_variant_config() {
        let c = VariantConfig::for_variant(Variant::Short);
        assert_eq!(c.target_rate, 0.3);
        assert_eq!(c.chunk_size_words, 80);
    }

    #[test]
    fn medium_variant_config() {
        let c = VariantConfig::for_variant(Variant::Medium);
        assert_eq!(c.target_rate, 0.5);
        assert_eq!(c.chunk_size_words, 160);
    }

    #[test]
    fn long_variant_config() {
        let c = VariantConfig::for_variant(Variant::Long);
        assert_eq!(c.target_rate, 0.7);
        assert_eq!(c.chunk_size_words, 320);
    }

    #[test]
    fn variant_config_to_compression_config_preserves_rate_and_chunk() {
        let v = VariantConfig::for_variant(Variant::Medium);
        let c = v.to_compression_config();
        assert_eq!(c.rate, 0.5);
        assert_eq!(c.chunk_size_words, 160);
        // Default force tokens are inherited.
        assert!(!c.force_tokens.is_empty());
    }
}
