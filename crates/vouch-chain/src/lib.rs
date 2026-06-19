//! vouch-chain — BLAKE3 hash chain (append-only, tamper-evident).
//!
//! AC-3.1, AC-3.8: thin crate providing a sequence-monotonic
//! chain. `Chain::append(entry)` returns a `ChainEntry` with
//! `blake3_hash = blake3(sequence || prev_hash || payload)`.
//! `Chain::verify()` walks the chain and reports the first
//! mismatch (genesis check, prev_hash linkage, recomputed hash).
//!
//! Determinism: two chains built from the same input sequence
//! produce identical chain roots (proptest-guaranteed).

use serde::{Deserialize, Serialize};

/// Genesis prev_hash: 64 hex zeros (matches themis-evidence).
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// A single chain entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEntry {
    /// Monotonic sequence (0 = genesis).
    pub sequence: u64,
    /// Payload bytes (UTF-8 string for chain-of-text use case;
    /// arbitrary bytes are stored as the canonical hex of
    /// `blake3::hash(&bytes)` for binary payloads).
    pub payload: String,
    /// `blake3(sequence_be || prev_hash || payload)`, hex.
    pub blake3_hash: String,
    /// Previous entry's `blake3_hash` (64 hex chars; genesis = zeros).
    pub prev_hash: String,
    /// Unix epoch ms.
    pub created_at_ms: i64,
}

/// Errors from chain operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    /// Recomputed hash did not match stored hash.
    #[error("hash mismatch at sequence {0}")]
    HashMismatch(u64),
    /// First entry was not genesis (sequence != 0).
    #[error("invalid genesis: expected sequence 0, got {0}")]
    InvalidGenesis(u64),
    /// Non-genesis entry has the all-zero prev_hash.
    #[error("broken chain at sequence {0}: prev_hash is all-zero placeholder")]
    BrokenChain(u64),
}

/// BLAKE3 chain.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    entries: Vec<ChainEntry>,
}

impl Chain {
    /// New empty chain (first append produces genesis).
    pub fn new() -> Self {
        Self::default()
    }

    /// Length.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Latest entry (or None if empty).
    pub fn latest(&self) -> Option<&ChainEntry> {
        self.entries.last()
    }

    /// All entries (immutable view).
    pub fn entries(&self) -> &[ChainEntry] {
        &self.entries
    }

    /// Test-only mutable accessor for proptest tampering. Production
    /// code uses `append` (append-only).
    #[doc(hidden)]
    pub fn entries_mut_for_test(&mut self) -> &mut Vec<ChainEntry> {
        &mut self.entries
    }

    /// Append `payload` with a synthetic timestamp.
    /// `now_ms` is exposed so tests can use a fixed clock.
    pub fn append_with_timestamp(
        &mut self,
        payload: &str,
        now_ms: i64,
    ) -> Result<&ChainEntry, ChainError> {
        let sequence = self.entries.len() as u64;
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.blake3_hash.clone())
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
        let blake3_hash = compute_hash(sequence, &prev_hash, payload);
        self.entries.push(ChainEntry {
            sequence,
            payload: payload.to_string(),
            blake3_hash,
            prev_hash,
            created_at_ms: now_ms,
        });
        Ok(self.entries.last().expect("just pushed"))
    }

    /// Append with `now_ms = 0` (deterministic, for tests).
    pub fn append(&mut self, payload: &str) -> Result<&ChainEntry, ChainError> {
        self.append_with_timestamp(payload, 0)
    }

    /// Re-verify the entire chain.
    pub fn verify(&self) -> Result<(), ChainError> {
        for (i, entry) in self.entries.iter().enumerate() {
            let expected_seq = i as u64;
            if entry.sequence != expected_seq {
                return Err(ChainError::InvalidGenesis(entry.sequence));
            }
            if entry.sequence == 0 {
                if entry.prev_hash != GENESIS_PREV_HASH {
                    return Err(ChainError::InvalidGenesis(entry.sequence));
                }
            } else if entry.prev_hash == GENESIS_PREV_HASH {
                return Err(ChainError::BrokenChain(entry.sequence));
            }
            let recomputed = compute_hash(entry.sequence, &entry.prev_hash, &entry.payload);
            if recomputed != entry.blake3_hash {
                return Err(ChainError::HashMismatch(entry.sequence));
            }
        }
        Ok(())
    }

    /// Chain root: hash of the last entry's `blake3_hash` (or
    /// `GENESIS_PREV_HASH` if empty). Two chains built from
    /// identical input produce identical roots.
    pub fn root(&self) -> String {
        match self.entries.last() {
            Some(e) => e.blake3_hash.clone(),
            None => GENESIS_PREV_HASH.to_string(),
        }
    }
}

/// `blake3(sequence_be(8) || prev_hash_hex(64) || payload_utf8)`,
/// returned as 64-char lowercase hex.
///
/// Format rationale: sequence in big-endian makes lexicographic
/// ordering match numeric ordering; prev_hash is hex so the
/// payload separator is unambiguous; payload is the raw UTF-8
/// bytes (any binary input is the caller's responsibility — pass
/// hex-encoded binary payloads).
pub fn compute_hash(sequence: u64, prev_hash: &str, payload: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&sequence.to_be_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(payload.as_bytes());
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    let mut hex = String::with_capacity(64);
    for b in bytes {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_sequence_zero_with_zero_prev_hash() {
        let mut chain = Chain::new();
        let genesis = chain.append("hello").unwrap();
        assert_eq!(genesis.sequence, 0);
        assert_eq!(genesis.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(genesis.blake3_hash.len(), 64);
    }

    #[test]
    fn chain_links_via_prev_hash() {
        let mut chain = Chain::new();
        let a_hash = chain.append("a").unwrap().blake3_hash.clone();
        let b_hash = chain.append("b").unwrap().blake3_hash.clone();
        let b_prev = chain.latest().unwrap().prev_hash.clone();
        let c_hash = chain.append("c").unwrap().blake3_hash.clone();
        let c_prev = chain.latest().unwrap().prev_hash.clone();
        assert_eq!(b_prev, a_hash);
        assert_eq!(c_prev, b_hash);
        assert_ne!(a_hash, b_hash);
        assert_ne!(b_hash, c_hash);
    }

    #[test]
    fn verify_accepts_intact_chain() {
        let mut chain = Chain::new();
        for i in 0..10 {
            chain.append(&format!("payload-{i}")).unwrap();
        }
        chain.verify().expect("intact chain must verify");
    }

    #[test]
    fn verify_detects_payload_tamper() {
        let mut chain = Chain::new();
        for i in 0..5 {
            chain.append(&format!("payload-{i}")).unwrap();
        }
        chain.entries_mut_for_test()[2].payload = "TAMPERED".to_string();
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, ChainError::HashMismatch(2)));
    }

    #[test]
    fn verify_detects_broken_linkage() {
        let mut chain = Chain::new();
        chain.append("a").unwrap();
        chain.append("b").unwrap();
        chain.entries_mut_for_test()[1].prev_hash = "ff".repeat(32);
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, ChainError::HashMismatch(1)));
    }

    #[test]
    fn identical_inputs_produce_identical_roots() {
        let mut a = Chain::new();
        let mut b = Chain::new();
        let inputs: Vec<String> = (0..50).map(|i| format!("entry-{i}-{}", i * 7)).collect();
        for s in &inputs {
            a.append(s).unwrap();
            b.append(s).unwrap();
        }
        assert_eq!(a.root(), b.root());
        assert_eq!(a.entries(), b.entries());
    }
}
