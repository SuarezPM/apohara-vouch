//! LLMLingua-2 token-classifier port.
//!
//! Port of Microsoft's LLMLingua-2 prompt compression algorithm
//! (ACL 2024, xlm-roberta-large-meetingbank token-classifier). The
//! paper trains a small classifier to score every token's
//! "keep probability" given the surrounding context; tokens with low
//! probability are dropped from the prompt.
//!
//! # What is ported
//!
//! - **Chunking** at 160 words per chunk (matches the bound used in
//!   Context Forge `compressor.py:60-67` to stay under the 512-token
//!   xlm-roberta cap on dense technical text).
//! - **Force-token preservation**: punctuation (`.`, `!`, `?`, `,`,
//!   `\n`) is always kept because the sentence boundaries matter for
//!   downstream LLM parsing.
//! - **Rate-based selection**: keep `(1 - rate) * N` of the remaining
//!   words, ranked by a score.
//!
//! # What is a placeholder
//!
//! - **Perplexity ranking** is replaced by **word length** as the
//!   score. The real LLMLingua-2 classifier is a neural model; the
//!   Rust port stands in word length (longer words → higher
//!   information content → keep first). This is documented as a
//!   follow-up in the PRD for US-003; the API surface is correct
//!   so a real model integration is a drop-in replacement.
//!
//! # Why this is enough for THEMIS
//!
//! THEMIS measures the savings at the coordinator level (US-002
//! decision surface). The classifier needs to be a deterministic
//! function of `(text, config) → compressed_text`; the actual
//! compression quality is a follow-up sprint. US-003 ships the
//! API contract and chunking discipline; the neural model swaps
//! in later without breaking callers.

/// Default compression rate: keep 50% of words.
pub const DEFAULT_RATE: f32 = 0.5;

/// Default chunk size in words (160 words ≈ 290 tokens on dense
/// technical text, safely under the 512-token xlm-roberta cap).
pub const DEFAULT_CHUNK_SIZE_WORDS: usize = 160;

/// Punctuation that must always be preserved (sentence boundaries
/// matter for downstream LLM parsing).
pub const DEFAULT_FORCE_TOKENS: &[char] = &['.', '!', '?', ',', '\n'];

/// Configuration for the token-classifier.
#[derive(Debug, Clone, PartialEq)]
pub struct CompressionConfig {
    /// Fraction of words to drop (0.0 = keep all, 1.0 = drop all).
    pub rate: f32,
    /// Characters that must always be preserved.
    pub force_tokens: Vec<char>,
    /// Maximum words per chunk before splitting.
    pub chunk_size_words: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            rate: DEFAULT_RATE,
            force_tokens: DEFAULT_FORCE_TOKENS.to_vec(),
            chunk_size_words: DEFAULT_CHUNK_SIZE_WORDS,
        }
    }
}

impl CompressionConfig {
    /// Construct a config with explicit rate; other fields use defaults.
    pub fn with_rate(rate: f32) -> Self {
        Self {
            rate,
            ..Self::default()
        }
    }
}

/// Split `text` into chunks of at most `chunk_size` words each.
///
/// Returns owned `String` chunks. If `text` has fewer than
/// `chunk_size` words, returns a single-element vec with the full
/// text cloned. The caller does not need to keep `text` alive.
pub fn chunk_by_words(text: &str, chunk_size: usize) -> Vec<String> {
    if chunk_size == 0 {
        return vec![text.to_string()];
    }
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.is_empty() {
        return vec![String::new()];
    }
    if words.len() <= chunk_size {
        return vec![text.to_string()];
    }
    words
        .chunks(chunk_size)
        .map(|chunk| chunk.join(" "))
        .collect()
}

/// Decide which words to keep from `original_words`.
///
/// * `force_tokens` are always kept.
/// * Of the remaining words, keep `(1 - rate) * N` of them, ranked by
///   **word length** (longer first). The real LLMLingua-2 uses a
///   neural perplexity score; this port uses length as a stand-in.
/// * Force tokens that appear in `original_words` are returned in
///   their original positions; the rest are interleaved around them
///   in score order to preserve the original document order roughly.
///
/// `original_words` is a slice of `&str` (each entry is one word).
pub fn select_words_to_keep<'a>(
    original_words: &[&'a str],
    rate: f32,
    force_tokens: &[char],
) -> Vec<&'a str> {
    if original_words.is_empty() {
        return Vec::new();
    }
    let rate = rate.clamp(0.0, 1.0);

    // Partition into force-words (contain a force-token char) and
    // the rest. Force-words are always kept in their original
    // positions; the rest are ranked by length and trimmed.
    let mut force_positions: Vec<usize> = Vec::new();
    let mut non_force: Vec<(usize, &'a str)> = Vec::new();
    for (i, w) in original_words.iter().enumerate() {
        if w.chars().any(|c| force_tokens.contains(&c)) {
            force_positions.push(i);
        } else {
            non_force.push((i, w));
        }
    }

    // Sort non-force by length descending, then by original position
    // for stability. Drop the tail to satisfy the rate.
    let keep_count = ((1.0 - rate) * non_force.len() as f32).round() as usize;
    non_force.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    let kept_non_force: std::collections::BTreeSet<usize> =
        non_force.iter().take(keep_count).map(|(i, _)| *i).collect();

    // Walk the original document in order, keep force positions and
    // the selected non-force positions, drop the rest.
    let mut kept: Vec<&'a str> = Vec::new();
    for (i, w) in original_words.iter().enumerate() {
        if force_positions.contains(&i) || kept_non_force.contains(&i) {
            kept.push(*w);
        }
    }
    kept
}

/// Compress `text` end-to-end: chunk → select → join.
///
/// The function is deterministic given `(text, config)`.
pub fn compress_text(text: &str, config: &CompressionConfig) -> String {
    if text.is_empty() {
        return String::new();
    }
    let chunks = chunk_by_words(text, config.chunk_size_words);
    let mut out_parts: Vec<String> = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let words: Vec<&str> = chunk.split_whitespace().collect();
        let kept = select_words_to_keep(&words, config.rate, &config.force_tokens);
        out_parts.push(kept.join(" "));
    }
    out_parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_by_words_splits_at_boundaries() {
        let text = "alpha beta gamma delta epsilon zeta eta theta iota kappa";
        let chunks = chunk_by_words(text, 3);
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0], "alpha beta gamma");
        assert_eq!(chunks[1], "delta epsilon zeta");
        assert_eq!(chunks[2], "eta theta iota");
        assert_eq!(chunks[3], "kappa");
    }

    #[test]
    fn chunk_by_words_keeps_short_text_intact() {
        let text = "one two three";
        let chunks = chunk_by_words(text, 10);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "one two three");
    }

    #[test]
    fn chunk_by_words_handles_empty() {
        let chunks = chunk_by_words("", 10);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "");
    }

    #[test]
    fn force_tokens_are_always_preserved() {
        let words = vec!["alpha", "beta", ".", "gamma", "delta", "!"];
        let kept = select_words_to_keep(&words, 0.99, &['.', '!', '?', ',', '\n']);
        // Force tokens must be in the output.
        assert!(kept.contains(&"."));
        assert!(kept.contains(&"!"));
    }

    #[test]
    fn rate_0_5_keeps_about_half() {
        // 20 non-force words, rate 0.5 → 10 kept.
        let mut words: Vec<String> = (0..20).map(|i| format!("w{i}")).collect();
        // No force tokens.
        let word_refs: Vec<&str> = words.iter().map(String::as_str).collect();
        let kept = select_words_to_keep(&word_refs, 0.5, &['.', '!']);
        assert_eq!(kept.len(), 10);
        // Tie-break by length then position: "w0".."w9" are 2 chars,
        // "w10".."w19" are 3 chars. Longer (3-char) ones win.
        for w in &[
            "w10", "w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19",
        ] {
            assert!(kept.contains(w), "expected {w} to be kept");
        }
        words.clear();
    }

    #[test]
    fn rate_0_drops_nothing() {
        let words = vec!["a", "b", "c", "d"];
        let kept = select_words_to_keep(&words, 0.0, &['.', '!']);
        assert_eq!(kept, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn rate_1_drops_everything_except_force_tokens() {
        let words = vec!["a", "b", "c", ".", "d"];
        let kept = select_words_to_keep(&words, 1.0, &['.', '!']);
        assert!(kept.contains(&"."));
        assert!(!kept.contains(&"a"));
        assert!(!kept.contains(&"b"));
    }

    #[test]
    fn chunk_size_cap_is_respected() {
        // 500 words, chunk 50 → 10 chunks, each with ≤ 50 words.
        let text: String = (0..500)
            .map(|i| format!("w{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let chunks = chunk_by_words(&text, 50);
        assert_eq!(chunks.len(), 10);
        for c in &chunks {
            assert!(c.split_whitespace().count() <= 50);
        }
    }

    #[test]
    fn compress_text_end_to_end_default_config() {
        let text: String = (0..100)
            .map(|i| format!("w{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let compressed = compress_text(&text, &CompressionConfig::default());
        // rate 0.5 on 100 words → 50 words kept, joined back with spaces.
        let word_count = compressed.split_whitespace().count();
        assert_eq!(word_count, 50);
    }

    #[test]
    fn compress_text_with_force_tokens_keeps_punctuation() {
        let text = "alpha . beta , gamma ! delta ? epsilon , zeta .";
        let compressed = compress_text(
            text,
            &CompressionConfig {
                rate: 0.99, // drop almost everything except force tokens
                force_tokens: vec!['.', ',', '!', '?'],
                chunk_size_words: 160,
            },
        );
        // Every force token must survive.
        for tok in &[".", ",", "!", "?"] {
            assert!(compressed.contains(tok), "force token {tok} dropped");
        }
    }

    #[test]
    fn compress_text_empty_input() {
        let compressed = compress_text("", &CompressionConfig::default());
        assert_eq!(compressed, "");
    }

    #[test]
    fn config_default_matches_constants() {
        let c = CompressionConfig::default();
        assert_eq!(c.rate, DEFAULT_RATE);
        assert_eq!(c.chunk_size_words, DEFAULT_CHUNK_SIZE_WORDS);
        assert_eq!(c.force_tokens, DEFAULT_FORCE_TOKENS.to_vec());
    }
}
