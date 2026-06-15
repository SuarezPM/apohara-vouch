//! On-disk persistence for `HashChain` (per-tenant JSON file).
//!
//! The chain is append-only and tamper-evident. Persisting it
//! between restarts means the `chain_length` in a `SealedPacket`
//! stays consistent with the chain a verifier can replay — a
//! restart that resets the chain to genesis would invalidate
//! every previously-issued packet's `chain_length`.
//!
//! File layout: one JSON file per tenant at
//! `chain_dir/{tenant}.chain.json`. The file holds the entire
//! serialized `HashChain` (small — payload strings only, no
//! blobs). Restarts load + verify the chain before serving
//! any new `seal` request.
//!
//! Concurrency: this store is intended to be held behind the
//! orchestrator's `Mutex`. Two concurrent `seal` calls for the
//! same tenant would race; the orchestrator serializes them.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::chain::{ChainError, HashChain};

/// Errors from loading or saving a persisted `HashChain`.
#[derive(Debug, Error)]
pub enum ChainStoreError {
    /// IO error reading or writing the chain file.
    #[error("chain store io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON deserialization failed (corrupted file, wrong schema).
    #[error("chain store parse: {0}")]
    Parse(#[from] serde_json::Error),
    /// Loaded chain failed its own `verify()` (tampered on disk).
    #[error("chain store verify: {0}")]
    Verify(#[from] ChainError),
}

/// Per-tenant on-disk `HashChain`. Wraps a `PathBuf` so the
/// orchestrator can keep one store per tenant in a `HashMap`.
pub struct ChainStore {
    path: PathBuf,
    chain: HashChain,
}

impl std::fmt::Debug for ChainStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainStore")
            .field("path", &self.path)
            .field("len", &self.chain.len())
            .finish()
    }
}

impl ChainStore {
    /// Open a chain store for the given tenant. Creates the
    /// directory + file with an empty chain if missing; loads +
    /// verifies the existing chain otherwise.
    pub fn open(chain_dir: &Path, tenant_id: &str) -> Result<Self, ChainStoreError> {
        std::fs::create_dir_all(chain_dir)?;
        let path = chain_dir.join(format!("{tenant_id}.chain.json"));
        let chain = if path.exists() {
            let bytes = std::fs::read(&path)?;
            let chain: HashChain = serde_json::from_slice(&bytes)?;
            chain.verify()?;
            chain
        } else {
            let chain = HashChain::new();
            let json = serde_json::to_vec_pretty(&chain)?;
            std::fs::write(&path, json)?;
            chain
        };
        Ok(Self { path, chain })
    }

    /// Borrow the chain. Mutations go through `append` so the
    /// disk file stays in sync.
    pub fn chain(&self) -> &HashChain {
        &self.chain
    }

    /// Append a payload, persist the updated chain to disk, and
    /// return the new entry. Returns `ChainError` if the in-memory
    /// chain rejects the append (it shouldn't — it's append-only
    /// and well-formed); the caller surfaces persistence errors
    /// via `ChainStoreError`.
    pub fn append(&mut self, payload: &str) -> Result<crate::chain::ChainEntry, ChainStoreError> {
        // `append` returns `&ChainEntry`; we clone it after
        // re-validating.
        let entry = self.chain.append(payload)?;
        let entry = entry.clone();
        let json = serde_json::to_vec_pretty(&self.chain)?;
        // Atomic-ish write: write to temp, rename. Avoids a
        // half-written chain file if the process dies mid-write.
        let tmp = self.path.with_extension("chain.json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(entry)
    }

    /// Current chain length (mirrors `HashChain::len`).
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// True iff the chain has no entries.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn open_creates_empty_chain_for_new_tenant() {
        let dir = tmp_dir();
        let store = ChainStore::open(dir.path(), "stark").unwrap();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
        // File was created.
        assert!(dir.path().join("stark.chain.json").exists());
    }

    #[test]
    fn append_persists_to_disk() {
        let dir = tmp_dir();
        let mut store = ChainStore::open(dir.path(), "stark").unwrap();
        store.append("first").unwrap();
        store.append("second").unwrap();
        // Re-open from disk; chain is restored.
        let store2 = ChainStore::open(dir.path(), "stark").unwrap();
        assert_eq!(store2.len(), 2);
        assert_eq!(store2.chain().entries()[0].sequence, 0);
        assert_eq!(store2.chain().entries()[1].sequence, 1);
    }

    #[test]
    fn open_rejects_tampered_chain_on_disk() {
        let dir = tmp_dir();
        let mut store = ChainStore::open(dir.path(), "stark").unwrap();
        store.append("a").unwrap();
        store.append("b").unwrap();
        // Tamper: change the second entry's payload via raw file write.
        let path = dir.path().join("stark.chain.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        json["entries"][1]["payload"] = serde_json::Value::String("TAMPERED".to_string());
        std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
        // Reopen should fail because verify() detects the mismatch.
        let err = ChainStore::open(dir.path(), "stark").unwrap_err();
        assert!(matches!(err, ChainStoreError::Verify(_)));
    }

    #[test]
    fn per_tenant_chains_are_independent() {
        let dir = tmp_dir();
        let mut stark = ChainStore::open(dir.path(), "stark").unwrap();
        stark.append("stark-1").unwrap();
        let wayne = ChainStore::open(dir.path(), "wayne").unwrap();
        assert_eq!(wayne.len(), 0);
        assert_eq!(stark.len(), 1);
    }
}
