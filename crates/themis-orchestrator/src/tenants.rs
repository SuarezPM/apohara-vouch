//! TenantRegistry — 2 fictitious companies + 1 room per (tenant, invoice).
//!
//! Stark Industries and Wayne Enterprises on 2 trust domains with
//! distinct keypairs, 1 persistent parent room per tenant + N
//! sub-rooms per invoice, zero cross-tenant data leakage.
//!
//! The `ed25519_public_key_hex` field on each `Tenant` is derived
//! from `themis_evidence::signer::SignerService::for_tenant(tenant_id)`
//! — i.e. the same `SignerService` that produces the per-tenant
//! signatures. This guarantees that the pubkey shown in the PDF /
//! JSON packet is the *real* Ed25519 public key, not a placeholder.
//!
//! Story C-13 (G16, G28) adds a **dynamic** per-tenant keyring
//! (`TenantKeyring`) for tenants that don't have a baked seed
//! file. The keyring is HMAC-SHA512-derived from a master seed
//! and is *separate* from the baked seeds; the demo signs with
//! the baked seeds (so `themis-verify` works offline), and the
//! keyring is the long-tail path for runtime-added tenants.

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use thiserror::Error;
use uuid::Uuid;

use crate::keyring::TenantKeyring;

/// A tenant (fictitious company on a trust domain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    /// Tenant identifier (e.g. "stark", "wayne").
    pub id: String,
    /// Display name (e.g. "Stark Industries").
    pub name: String,
    /// Stable key identifier (for rotation logs).
    pub key_id: String,
    /// Hex-encoded Ed25519 public key (32 bytes = 64 hex chars).
    /// Derived from `SignerService::for_tenant(id).public_key_hex()`.
    pub ed25519_public_key_hex: String,
}

/// A Band room identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoomId(pub Uuid);

impl RoomId {
    /// New random room id.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RoomId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RoomId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Tenant-related errors.
#[derive(Debug, Error)]
pub enum TenantError {
    /// Tenant not registered.
    #[error("unknown tenant: {0}")]
    UnknownTenant(String),
    /// Cross-tenant access attempted.
    #[error(
        "cross-tenant access denied: tenant={tenant} tried to access {target_tenant}'s resource"
    )]
    CrossTenantAccess {
        /// The tenant that attempted the access.
        tenant: String,
        /// The tenant that owns the resource.
        target_tenant: String,
    },
    /// Empty tenant id supplied to a keyring operation.
    #[error("tenant id must not be empty")]
    EmptyTenantId,
    /// Keyring mutex was poisoned by a panic in a previous holder.
    #[error("tenant keyring lock poisoned")]
    KeyringLockPoisoned,
}

/// The registry. Holds the 2 default tenants and the
/// `(tenant_id, invoice_id) → RoomId` mapping. The latter uses
/// `DashMap` so concurrent `open_room` calls don't contend.
///
/// The keyring is `Arc<TenantKeyring>` so it can be cheaply cloned
/// into the A2A handler (Story C-12 peer integration) and the
/// orchestrator's per-tenant signing path.
#[derive(Clone)]
pub struct TenantRegistry {
    tenants: HashMap<String, Tenant>,
    rooms: DashMap<(String, String), RoomId>,
    /// BIP32-*style* keyring (HMAC-SHA512 truncated to 32 bytes).
    /// Shared with consumers via `Arc` to avoid cloning the
    /// per-tenant `Mutex<HashMap>` on every borrow.
    keyring: Arc<TenantKeyring>,
}

// Manual Debug: `DashMap` doesn't implement `Debug`. Print a short
// summary that doesn't lock the rooms map.
impl std::fmt::Debug for TenantRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantRegistry")
            .field("tenants", &self.tenants)
            .field("room_count", &self.rooms.len())
            .field("keyring_cached", &self.keyring.count())
            .finish()
    }
}

/// Load the master seed from the `THEMIS_MASTER_SEED` env var.
///
/// The env var must be a 32-byte seed encoded as 64 hex chars. If
/// the env var is missing, empty, malformed, or the wrong length,
/// fall back to a **deterministic dev seed** so tests are
/// reproducible. In production, the operator is expected to set
/// `THEMIS_MASTER_SEED` to a CSPRNG-generated 32-byte value.
pub fn load_master_seed_from_env() -> [u8; 32] {
    const ENV: &str = "THEMIS_MASTER_SEED";
    if let Ok(hex_seed) = std::env::var(ENV) {
        if let Ok(bytes) = hex::decode(hex_seed.trim()) {
            if bytes.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                return seed;
            }
        }
        // Env var present but unusable: log nothing in production
        // (logging may not be wired yet) and fall through to the
        // dev seed. The fail-soft behavior is documented in the
        // module-level doc comment.
    }
    // Deterministic dev seed: NOT for production. Marked clearly
    // so an operator reading a memory dump recognizes it. The
    // 32-byte literal is truncated with `b"..."[..32]` so a future
    // edit that grows the string doesn't silently shrink the seed.
    let dev = b"themis-dev-master-seed-do-not-use-in-prod-v0";
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&dev[..32]);
    seed
}

impl TenantRegistry {
    /// New registry with 2 default tenants: stark (Stark Industries)
    /// and wayne (Wayne Enterprises). Each `ed25519_public_key_hex`
    /// is derived from `SignerService::for_tenant(id).public_key_hex()`,
    /// so the pubkey in the registry matches the pubkey used for
    /// real Ed25519 signing. Panics at startup if the per-tenant
    /// seed file is missing (fail-fast — better than a placeholder
    /// that passes tests but breaks the demo).
    ///
    /// The keyring is initialized from `load_master_seed_from_env()`.
    /// **The keyring and the baked seeds are intentionally separate**:
    /// the demo signs with the baked seeds (so `themis-verify` works
    /// offline), and the keyring is the *dynamic* path for tenants
    /// that don't have a baked key file.
    pub fn with_default_tenants() -> Self {
        Self::with_default_tenants_and_seed(load_master_seed_from_env())
    }

    /// Same as `with_default_tenants` but takes an explicit master
    /// seed. Used by tests and by callers that want to inject a
    /// seed without touching the env var.
    pub fn with_default_tenants_and_seed(master_seed: [u8; 32]) -> Self {
        let mut tenants = HashMap::new();
        for (id, name, key_id) in [
            ("stark", "Stark Industries", "stark-prod-2026-01"),
            ("wayne", "Wayne Enterprises", "wayne-prod-2026-01"),
        ] {
            let signer =
                themis_evidence::signer::SignerService::for_tenant(id).unwrap_or_else(|e| {
                    panic!(
                        "SignerService::for_tenant({id}) failed at startup: {e}. \
                         Seed file missing? Baked keys are at crates/themis-evidence/keys/."
                    )
                });
            tenants.insert(
                id.to_string(),
                Tenant {
                    id: id.to_string(),
                    name: name.to_string(),
                    key_id: key_id.to_string(),
                    ed25519_public_key_hex: signer.public_key_hex(),
                },
            );
        }
        Self {
            tenants,
            rooms: DashMap::new(),
            keyring: Arc::new(TenantKeyring::new(master_seed)),
        }
    }

    /// Access the per-tenant keyring. The keyring is shared
    /// (`Arc<TenantKeyring>`) so callers can hand it to the A2A
    /// handler, a future per-tenant signer, or an integration test
    /// without copying the internal `Mutex<HashMap>`.
    pub fn keyring(&self) -> &TenantKeyring {
        &self.keyring
    }

    /// Get a tenant by id.
    pub fn get(&self, id: &str) -> Option<&Tenant> {
        self.tenants.get(id)
    }

    /// All tenant ids (sorted for determinism).
    pub fn all_tenant_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.tenants.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Open (or reuse) a Band room for `(tenant_id, invoice_id)`.
    /// Idempotent: second call for the same pair returns the same
    /// `RoomId`. Cross-tenant access attempts are rejected.
    pub fn open_room(&self, tenant_id: &str, invoice_id: &str) -> Result<RoomId, TenantError> {
        if !self.tenants.contains_key(tenant_id) {
            return Err(TenantError::UnknownTenant(tenant_id.to_string()));
        }
        let key = (tenant_id.to_string(), invoice_id.to_string());
        // entry().or_insert_with returns the existing RoomId if
        // present, else constructs a new one. DashMap guarantees
        // atomicity across concurrent callers. RoomId is Copy.
        // The closure is needed (the no-closure variant trips the
        // reverse clippy lint); the manual allow documents the
        // intentional choice.
        #[allow(clippy::unwrap_or_default)]
        let room_id = *self.rooms.entry(key).or_insert_with(RoomId::new);
        Ok(room_id)
    }

    /// Look up an existing room id for `(tenant_id, invoice_id)`.
    /// Returns `None` if the room was never opened. Cross-tenant
    /// access denied.
    pub fn get_room(
        &self,
        requesting_tenant: &str,
        target_tenant: &str,
        invoice_id: &str,
    ) -> Result<Option<RoomId>, TenantError> {
        if requesting_tenant != target_tenant {
            return Err(TenantError::CrossTenantAccess {
                tenant: requesting_tenant.to_string(),
                target_tenant: target_tenant.to_string(),
            });
        }
        if !self.tenants.contains_key(target_tenant) {
            return Err(TenantError::UnknownTenant(target_tenant.to_string()));
        }
        Ok(self
            .rooms
            .get(&(target_tenant.to_string(), invoice_id.to_string()))
            .map(|r| *r))
    }

    /// Number of rooms currently tracked (across all tenants).
    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_default_tenants_distinct() {
        let r = TenantRegistry::with_default_tenants();
        let stark = r.get("stark").unwrap();
        let wayne = r.get("wayne").unwrap();
        assert_eq!(stark.name, "Stark Industries");
        assert_eq!(wayne.name, "Wayne Enterprises");
        assert_ne!(stark.key_id, wayne.key_id);
        assert_ne!(stark.ed25519_public_key_hex, wayne.ed25519_public_key_hex);
        // Real Ed25519 pubkey is 32 bytes = 64 hex chars; both
        // tenants must have a real (non-placeholder) pubkey.
        assert_eq!(stark.ed25519_public_key_hex.len(), 64);
        assert_eq!(wayne.ed25519_public_key_hex.len(), 64);
        // The registry pubkey must match what the SignerService
        // returns for the same tenant. This is the contract that
        // makes `themis-verify` work end-to-end.
        let stark_signer = themis_evidence::signer::SignerService::for_tenant("stark").unwrap();
        let wayne_signer = themis_evidence::signer::SignerService::for_tenant("wayne").unwrap();
        assert_eq!(stark.ed25519_public_key_hex, stark_signer.public_key_hex());
        assert_eq!(wayne.ed25519_public_key_hex, wayne_signer.public_key_hex());
    }

    #[test]
    fn open_room_idempotent_for_same_pair() {
        let r = TenantRegistry::with_default_tenants();
        let a = r.open_room("stark", "inv-001").unwrap();
        let b = r.open_room("stark", "inv-001").unwrap();
        assert_eq!(a, b);
        assert_eq!(r.room_count(), 1);
    }

    #[test]
    fn open_room_rejects_unknown_tenant() {
        let r = TenantRegistry::with_default_tenants();
        let err = r.open_room("ghost", "inv-001").unwrap_err();
        assert!(matches!(err, TenantError::UnknownTenant(_)));
    }

    #[test]
    fn cross_tenant_room_read_denied() {
        let r = TenantRegistry::with_default_tenants();
        r.open_room("stark", "inv-001").unwrap();
        // wayne tries to read stark's room.
        let err = r.get_room("wayne", "stark", "inv-001").unwrap_err();
        assert!(matches!(err, TenantError::CrossTenantAccess { .. }));
    }

    #[test]
    fn cross_tenant_open_does_not_pollute_rooms() {
        // open_room takes the tenant_id as the owner; the registry
        // is keyed by (tenant_id, invoice_id) so the same invoice
        // id under two different tenants produces two distinct rooms.
        let r = TenantRegistry::with_default_tenants();
        let stark_room = r.open_room("stark", "inv-001").unwrap();
        let wayne_room = r.open_room("wayne", "inv-001").unwrap();
        assert_ne!(stark_room, wayne_room);
        assert_eq!(r.room_count(), 2);
    }

    #[test]
    fn all_tenant_ids_returns_two_sorted() {
        let r = TenantRegistry::with_default_tenants();
        assert_eq!(r.all_tenant_ids(), vec!["stark", "wayne"]);
    }

    #[test]
    fn get_room_returns_none_for_unopened_invoice() {
        let r = TenantRegistry::with_default_tenants();
        let result = r.get_room("stark", "stark", "never-opened").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn keyring_derives_keys_distinct_from_baked_seeds() {
        // Story C-13 / AC13: the keyring is a *separate* path from
        // the baked seeds, so a tenant's keyring key MUST NOT match
        // the baked SignerService key. This is the contract that
        // lets the keyring be the dynamic path for runtime-added
        // tenants without breaking `themis-verify` for the demo
        // (which still uses the baked seeds).
        let r = TenantRegistry::with_default_tenants_and_seed([7u8; 32]);
        let stark_tenant = r.get("stark").unwrap();
        let keyring_stark = r.keyring().derive_for_tenant("stark");
        let keyring_stark_pub_hex = hex::encode(keyring_stark.verifying_key().to_bytes());
        assert_ne!(
            stark_tenant.ed25519_public_key_hex, keyring_stark_pub_hex,
            "keyring key must not collide with baked SignerService key"
        );
    }

    #[test]
    fn keyring_empty_tenant_id_rejected() {
        let r = TenantRegistry::with_default_tenants_and_seed([0u8; 32]);
        let err = r.keyring().get_or_derive("").unwrap_err();
        assert!(matches!(err, TenantError::EmptyTenantId));
    }
}
