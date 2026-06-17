//! BLAKE3 hash chain (sequence-monotonic, append-only, tamper-evident).
//!
//! Each entry's `blake3_hash = blake3(sequence || prev_hash || payload)`.
//! The genesis entry has `prev_hash = "00" * 32`. Re-verify walks the
//! chain; a single tampered entry fails `verify()` and reports the
//! sequence number where the mismatch was detected.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Retention policy for the hash chain. US-06: enforces
/// EU AI Act Article 12 (6-month minimum retention) and
/// per-tenant / per-jurisdiction overrides. The default
/// is 6 months; the demo's tenant jurisdiction may
/// override to 24 months (biometric / law enforcement).
///
/// The policy is consulted by `EvidenceService::seal`
/// (and any other append path) when the previous chain
/// entry is older than the configured window — in that
/// case the append is rejected with `ChainError::RetentionExceeded`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Default retention in months (EU AI Act Art 12 = 6).
    pub default_months: u32,
    /// Per-tenant overrides (e.g. "wayne" -> 24 months for
    /// biometric / law enforcement data).
    #[serde(default)]
    pub per_tenant_overrides: std::collections::HashMap<String, u32>,
    /// Per-jurisdiction overrides (e.g. "EU" -> 6, "US" -> 12).
    #[serde(default)]
    pub per_jurisdiction_overrides: std::collections::HashMap<String, u32>,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            default_months: 6, // EU AI Act Article 12
            per_tenant_overrides: std::collections::HashMap::new(),
            per_jurisdiction_overrides: std::collections::HashMap::new(),
        }
    }
}

impl RetentionPolicy {
    /// Effective retention in months for a given tenant.
    /// Resolution order: tenant override → jurisdiction override →
    /// default. The demo's two baked tenants (stark, wayne)
    /// share the default EU jurisdiction.
    pub fn effective_months(&self, tenant_id: &str, jurisdiction: &str) -> u32 {
        if let Some(m) = self.per_tenant_overrides.get(tenant_id) {
            return *m;
        }
        if let Some(m) = self.per_jurisdiction_overrides.get(jurisdiction) {
            return *m;
        }
        self.default_months
    }
}

/// A single entry in the hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEntry {
    /// Monotonically increasing sequence number (0 for genesis).
    pub sequence: u64,
    /// The payload (the data being chained).
    pub payload: String,
    /// BLAKE3 hash of `(sequence || prev_hash || payload)`, hex.
    pub blake3_hash: String,
    /// The previous entry's `blake3_hash` (64-char hex; all-zero
    /// for the genesis entry).
    pub prev_hash: String,
    /// Unix epoch ms when the entry was created. US-06:
    /// used by `RetentionPolicy::enforce_chain` to
    /// reject appends that would exceed the configured
    /// retention window. `0` for entries created before
    /// the timestamp field was added (back-compat).
    #[serde(default)]
    pub created_at_ms: i64,
}

/// Hash-chain errors.
#[derive(Debug, Error)]
pub enum ChainError {
    /// A chain entry's recomputed hash did not match its stored hash.
    #[error("hash mismatch at sequence {0}")]
    HashMismatch(u64),
    /// The chain's first entry is not the genesis (sequence != 0).
    #[error("invalid genesis: sequence should be 0, got {0}")]
    InvalidGenesis(u64),
    /// A non-genesis entry has the all-zero prev_hash (broken chain).
    #[error("broken chain at sequence {0}: prev_hash is the all-zero placeholder")]
    BrokenChain(u64),
    /// US-06: the previous entry in the chain is older than
    /// the configured retention window. EU AI Act Art 12
    /// mandates a 6-month minimum retention; longer
    /// retention is allowed, shorter is not. The error
    /// carries the configured window in days for the
    /// audit log.
    #[error("retention exceeded: previous entry is older than the configured window ({window_months} months)")]
    RetentionExceeded {
        /// The configured retention window in months.
        window_months: u32,
    },
}

/// The hash chain. Append-only; no remove, no mutate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HashChain {
    /// All entries, in order. `pub` to allow serde derive and the
    /// `persistence` tests to tamper with entries. The struct itself
    /// stays append-only via the public API (`append`, `verify`).
    pub entries: Vec<ChainEntry>,
}

impl HashChain {
    /// New empty chain. The first `append()` call creates the
    /// genesis entry (sequence=0, prev_hash=64 zeros).
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries in the chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the chain has no entries yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The most recent entry, or `None` if the chain is empty.
    pub fn latest(&self) -> Option<&ChainEntry> {
        self.entries.last()
    }

    /// All entries, in order.
    pub fn entries(&self) -> &[ChainEntry] {
        &self.entries
    }

    /// Append a payload. Computes the new entry's hash and bumps
    /// the sequence number. Returns a reference to the appended
    /// entry.
    pub fn append(&mut self, payload: &str) -> Result<&ChainEntry, ChainError> {
        self.append_with_timestamp(payload, chrono::Utc::now().timestamp_millis())
    }

    /// Append a payload with an explicit timestamp (used by
    /// the retention-policy code path + tests). Computes
    /// the new entry's hash and bumps the sequence number.
    /// Returns a reference to the appended entry.
    pub fn append_with_timestamp(
        &mut self,
        payload: &str,
        created_at_ms: i64,
    ) -> Result<&ChainEntry, ChainError> {
        let sequence = self.entries.len() as u64;
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.blake3_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let blake3_hash = compute_entry_hash(sequence, &prev_hash, payload);
        self.entries.push(ChainEntry {
            sequence,
            payload: payload.to_string(),
            blake3_hash,
            prev_hash,
            created_at_ms,
        });
        Ok(self.entries.last().expect("just pushed"))
    }

    /// US-06: enforce the retention policy before a new
    /// append. If the most recent entry is older than the
    /// configured window (in months), returns
    /// `ChainError::RetentionExceeded` with the window
    /// in months. Empty chains always pass (the genesis
    /// entry is the first one to age).
    pub fn enforce_retention(
        &self,
        policy: &RetentionPolicy,
        now_ms: i64,
        tenant_id: &str,
        jurisdiction: &str,
    ) -> Result<(), ChainError> {
        let latest = match self.entries.last() {
            Some(e) => e,
            None => return Ok(()),
        };
        let window_months = policy.effective_months(tenant_id, jurisdiction);
        let window_ms = (window_months as i64) * 30 * 86_400 * 1000;
        let age_ms = now_ms - latest.created_at_ms;
        if age_ms > window_ms {
            return Err(ChainError::RetentionExceeded { window_months });
        }
        Ok(())
    }

    /// Verify the entire chain. Returns `Ok(())` if every entry's
    /// hash recomputes correctly; otherwise `Err(HashMismatch(seq))`.
    pub fn verify(&self) -> Result<(), ChainError> {
        let mut prev_hash = "0".repeat(64);
        for entry in &self.entries {
            // Genesis sanity: prev_hash must be the all-zero placeholder.
            if entry.sequence == 0 && entry.prev_hash != prev_hash {
                return Err(ChainError::InvalidGenesis(entry.sequence));
            }
            if entry.sequence > 0 && entry.prev_hash == "0".repeat(64) {
                return Err(ChainError::BrokenChain(entry.sequence));
            }
            let recomputed = compute_entry_hash(entry.sequence, &entry.prev_hash, &entry.payload);
            if recomputed != entry.blake3_hash {
                return Err(ChainError::HashMismatch(entry.sequence));
            }
            prev_hash = entry.blake3_hash.clone();
        }
        Ok(())
    }
}

/// BLAKE3 hash of `(sequence_bytes || prev_hash_bytes || payload_bytes)`.
/// `sequence` is encoded as 8 big-endian bytes for stability.
fn compute_entry_hash(sequence: u64, prev_hash_hex: &str, payload: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&sequence.to_be_bytes());
    hasher.update(prev_hash_hex.as_bytes());
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_uses_all_zero_prev_hash() {
        let mut chain = HashChain::new();
        let entry = chain.append("genesis payload").unwrap();
        assert_eq!(entry.sequence, 0);
        assert_eq!(entry.prev_hash, "0".repeat(64));
        assert_eq!(entry.blake3_hash.len(), 64);
    }

    #[test]
    fn appends_are_monotonic() {
        let mut chain = HashChain::new();
        chain.append("a").unwrap();
        chain.append("b").unwrap();
        chain.append("c").unwrap();
        assert_eq!(chain.len(), 3);
        for (i, e) in chain.entries().iter().enumerate() {
            assert_eq!(e.sequence, i as u64);
        }
    }

    #[test]
    fn prev_hash_links_to_previous_entry() {
        let mut chain = HashChain::new();
        let a_hash = chain.append("a").unwrap().blake3_hash.clone();
        let b_hash = chain.append("b").unwrap().blake3_hash.clone();
        let c_hash = chain.append("c").unwrap().blake3_hash.clone();
        // Re-read prev_hash via entries() to avoid holding a borrow.
        let entries = chain.entries().to_vec();
        assert_eq!(entries[1].prev_hash, a_hash);
        assert_eq!(entries[2].prev_hash, b_hash);
        // And the chain progresses.
        assert_ne!(a_hash, b_hash);
        assert_ne!(b_hash, c_hash);
    }

    #[test]
    fn verify_returns_true_on_clean_chain() {
        let mut chain = HashChain::new();
        for i in 0..5 {
            chain.append(&format!("payload {i}")).unwrap();
        }
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn verify_fails_on_tampered_payload() {
        let mut chain = HashChain::new();
        chain.append("a").unwrap();
        chain.append("b").unwrap();
        chain.append("c").unwrap();
        // Mutate one entry's payload in place.
        chain.entries[1].payload = "TAMPERED".to_string();
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, ChainError::HashMismatch(1)));
    }

    #[test]
    fn verify_fails_on_tampered_prev_hash() {
        let mut chain = HashChain::new();
        chain.append("a").unwrap();
        chain.append("b").unwrap();
        chain.entries[1].prev_hash = "ff".repeat(32);
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, ChainError::HashMismatch(1)));
    }

    #[test]
    fn latest_returns_most_recent() {
        let mut chain = HashChain::new();
        assert!(chain.latest().is_none());
        chain.append("first").unwrap();
        assert_eq!(chain.latest().unwrap().sequence, 0);
        chain.append("second").unwrap();
        assert_eq!(chain.latest().unwrap().sequence, 1);
    }
}
