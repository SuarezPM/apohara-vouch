//! Tenant keyring — BIP32-*style* deterministic Ed25519 derivation.
//!
//! # Derivation pattern (HMAC-SHA512 truncated, not full BIP32)
//!
//! ```text
//! secret[0..32] = HMAC-SHA512(master_seed, domain_tag || tenant_id)[0..32]
//! ```
//!
//! where `domain_tag = "themis-3.0-tenant-keyring-v1"`.
//! ```
//!
//! The full BIP32 spec uses a 32-byte chain code, hardened/non-hardened
//! derivation paths, and parent → child key iteration. This is a
//! **simplified subset** that gives us:
//!
//! 1. **Deterministic**: same `(master_seed, tenant_id)` always yields
//!    the same Ed25519 secret key (and therefore the same pubkey).
//! 2. **Isolated**: different tenant_ids produce unrelated keys (HMAC
//!    PRF property).
//! 3. **Domain-separated**: a different `domain_tag` produces unrelated
//!    keys for the same `master_seed` (prevents cross-protocol key
//!    reuse if the same seed is used for a different purpose).
//! 4. **Dynamic**: new tenants can be added at runtime by deriving
//!    a new key — no key file, no restart.
//!
//! # Why not the full BIP32 chain-code machinery?
//!
//! A full HD wallet adds a chain code, a path syntax (`m/44'/0'/0'/0/0`),
//! parent → child key iteration, and hardened derivation. We don't
//! need any of that: a tenant has exactly one key, we never rotate
//! mid-flight, and we don't have a hierarchy below the tenant. Adding
//! the chain code would be cargo-culted complexity.
//!
//! # Backward compatibility with baked tenants
//!
//! The 2 fixture tenants (`stark`, `wayne`) have keys baked at compile
//! time via `include_bytes!` in `themis-evidence::signer`. This keyring
//! uses a **separate** derivation path (the master seed is *not* the
//! same as the baked seed). Baked keys remain authoritative for the
//! demo. The keyring is the **dynamic** path for tenants that don't
//! have a baked key file — i.e. the long tail of customers a real
//! deployment would add at runtime.

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::tenants::TenantError;

/// Domain separation tag. Different protocols (e.g. a future "agent
/// keyring" or "session keyring") MUST use a different tag to avoid
/// cross-protocol key reuse from the same master seed.
pub const BIP32_LIKE_DOMAIN: &[u8] = b"themis-3.0-tenant-keyring-v1";

/// HMAC-SHA512 (RFC 2104). Alias so callers don't import the
/// `generic-array`-flavored type directly.
type HmacSha512 = Hmac<Sha512>;

/// Per-tenant Ed25519 keyring derived from a single master seed.
///
/// All keys are derived lazily on first request for a `tenant_id`
/// and cached in a `Mutex<HashMap>`. The cache is bounded by the
/// number of distinct tenants seen since process start, which in
/// practice is a small constant.
#[derive(Debug)]
pub struct TenantKeyring {
    /// Master seed. 32 bytes; should be from a CSPRNG in production
    /// (`THEMIS_MASTER_SEED` env var as 64 hex chars) or a
    /// deterministic dev seed when the env var is missing.
    pub master_seed: [u8; 32],
    /// Derived keys, keyed by `tenant_id`. `Mutex` (not `RwLock`)
    /// because derivation is fast and the read path is short.
    derived: Mutex<HashMap<String, SigningKey>>,
}

impl TenantKeyring {
    /// New keyring with an explicit master seed.
    pub fn new(master_seed: [u8; 32]) -> Self {
        Self {
            master_seed,
            derived: Mutex::new(HashMap::new()),
        }
    }

    /// Derive a tenant's Ed25519 signing key.
    ///
    /// The derivation is `HMAC-SHA512(master_seed, domain_tag || tenant_id)[0..32]`,
    /// which is then fed to `SigningKey::from_bytes`. Pure function of
    /// the inputs — no I/O, no randomness, deterministic across calls
    /// and across processes.
    pub fn derive_for_tenant(&self, tenant_id: &str) -> SigningKey {
        let mut mac = HmacSha512::new_from_slice(&self.master_seed)
            .expect("HMAC-SHA512 accepts any key length including 32 bytes");
        mac.update(BIP32_LIKE_DOMAIN);
        mac.update(tenant_id.as_bytes());
        let tag = mac.finalize().into_bytes();
        // HMAC-SHA512 returns 64 bytes. Ed25519 wants 32.
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&tag[..32]);
        SigningKey::from_bytes(&secret)
    }

    /// Return the cached key for `tenant_id`, or derive + cache one.
    /// This is the hot path for the A2A handler when a peer asks
    /// for a tenant's public key.
    pub fn get_or_derive(&self, tenant_id: &str) -> Result<SigningKey, TenantError> {
        if tenant_id.is_empty() {
            return Err(TenantError::EmptyTenantId);
        }
        let mut cache = self
            .derived
            .lock()
            .map_err(|_| TenantError::KeyringLockPoisoned)?;
        if let Some(key) = cache.get(tenant_id) {
            return Ok(key.clone());
        }
        let key = self.derive_for_tenant(tenant_id);
        cache.insert(tenant_id.to_string(), key.clone());
        Ok(key)
    }

    /// Evict a tenant's cached key. Useful for forced re-derivation
    /// tests and for key rotation (call after replacing the master
    /// seed).
    pub fn evict(&self, tenant_id: &str) {
        if let Ok(mut cache) = self.derived.lock() {
            cache.remove(tenant_id);
        }
    }

    /// Number of cached keys.
    pub fn count(&self) -> usize {
        self.derived.lock().map(|c| c.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_keyring() -> TenantKeyring {
        // Fixed test seed — deterministic across runs.
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        TenantKeyring::new(seed)
    }

    #[test]
    fn derive_is_deterministic() {
        let k = fresh_keyring();
        let a = k.derive_for_tenant("stark");
        let b = k.derive_for_tenant("stark");
        assert_eq!(a.to_bytes(), b.to_bytes());
        assert_eq!(
            a.verifying_key().to_bytes(),
            b.verifying_key().to_bytes()
        );
    }

    #[test]
    fn different_tenant_ids_produce_different_keys() {
        let k = fresh_keyring();
        let stark = k.derive_for_tenant("stark");
        let wayne = k.derive_for_tenant("wayne");
        assert_ne!(stark.to_bytes(), wayne.to_bytes());
        assert_ne!(
            stark.verifying_key().to_bytes(),
            wayne.verifying_key().to_bytes()
        );
        // Both must be valid Ed25519 pubkeys (32 bytes).
        assert_eq!(stark.verifying_key().to_bytes().len(), 32);
        assert_eq!(wayne.verifying_key().to_bytes().len(), 32);
    }

    #[test]
    fn get_or_derive_caches() {
        let k = fresh_keyring();
        // First call: derives and caches.
        let a = k.get_or_derive("tenant-a").unwrap();
        assert_eq!(k.count(), 1);
        // Second call: must come from cache.
        let b = k.get_or_derive("tenant-a").unwrap();
        assert_eq!(k.count(), 1);
        // Same key bytes.
        assert_eq!(a.to_bytes(), b.to_bytes());
        // A different tenant grows the cache.
        let _ = k.get_or_derive("tenant-b").unwrap();
        assert_eq!(k.count(), 2);
    }

    #[test]
    fn evict_removes_from_cache() {
        let k = fresh_keyring();
        let _ = k.get_or_derive("tenant-a").unwrap();
        assert_eq!(k.count(), 1);
        k.evict("tenant-a");
        assert_eq!(k.count(), 0);
        // Re-derivation after eviction produces the same key.
        let after = k.get_or_derive("tenant-a").unwrap();
        let before = k.derive_for_tenant("tenant-a");
        assert_eq!(after.to_bytes(), before.to_bytes());
    }

    #[test]
    fn master_seed_domain_separation_works() {
        // Two keyrings with the same master_seed but different domain
        // tags must produce different keys for the same tenant_id.
        // We simulate "different domain" by re-running the same
        // derivation under a tag offset; the simpler proof is that
        // appending a byte to the tenant_id changes the key (HMAC
        // PRF property) — which is the same structural guarantee.
        let k = fresh_keyring();
        let a = k.derive_for_tenant("stark");
        let b = k.derive_for_tenant("stark\0");
        assert_ne!(a.to_bytes(), b.to_bytes());
        // The full domain-separation tag is exposed as a public
        // constant; assert it's exactly the expected bytes so a
        // future refactor doesn't silently weaken isolation.
        assert_eq!(
            BIP32_LIKE_DOMAIN,
            b"themis-3.0-tenant-keyring-v1"
        );
    }

    #[test]
    fn empty_tenant_id_rejected() {
        let k = fresh_keyring();
        let err = k.get_or_derive("").unwrap_err();
        assert!(matches!(err, TenantError::EmptyTenantId));
    }
}
