//! TenantRegistry — 2 fictitious companies + 1 room per (tenant, invoice).
//!
//! Stark Industries and Wayne Enterprises on 2 trust domains with
//! distinct keypairs, 1 persistent parent room per tenant + N
//! sub-rooms per invoice, zero cross-tenant data leakage.

use std::collections::HashMap;

use dashmap::DashMap;
use thiserror::Error;
use uuid::Uuid;

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
    #[error("cross-tenant access denied: tenant={tenant} tried to access {target_tenant}'s resource")]
    CrossTenantAccess {
        /// The tenant that attempted the access.
        tenant: String,
        /// The tenant that owns the resource.
        target_tenant: String,
    },
}

/// The registry. Holds the 2 default tenants and the
/// `(tenant_id, invoice_id) → RoomId` mapping. The latter uses
/// `DashMap` so concurrent `open_room` calls don't contend.
#[derive(Debug)]
pub struct TenantRegistry {
    tenants: HashMap<String, Tenant>,
    rooms: DashMap<(String, String), RoomId>,
}

impl TenantRegistry {
    /// New registry with 2 default tenants: stark (Stark Industries)
    /// and wayne (Wayne Enterprises). Distinct key_ids and Ed25519
    /// public keys so the byte-diff test in `isolation.rs` sees
    /// them differ.
    pub fn with_default_tenants() -> Self {
        let mut tenants = HashMap::new();
        tenants.insert(
            "stark".to_string(),
            Tenant {
                id: "stark".to_string(),
                name: "Stark Industries".to_string(),
                key_id: "stark-prod-2026-01".to_string(),
                // Deterministic-but-distinct placeholder keys. Real
                // keys come from `keys/stark.ed25519` at runtime.
                ed25519_public_key_hex: "11".repeat(32),
            },
        );
        tenants.insert(
            "wayne".to_string(),
            Tenant {
                id: "wayne".to_string(),
                name: "Wayne Enterprises".to_string(),
                key_id: "wayne-prod-2026-01".to_string(),
                ed25519_public_key_hex: "22".repeat(32),
            },
        );
        Self {
            tenants,
            rooms: DashMap::new(),
        }
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
    pub fn open_room(
        &self,
        tenant_id: &str,
        invoice_id: &str,
    ) -> Result<RoomId, TenantError> {
        if !self.tenants.contains_key(tenant_id) {
            return Err(TenantError::UnknownTenant(tenant_id.to_string()));
        }
        let key = (tenant_id.to_string(), invoice_id.to_string());
        // entry().or_insert_with returns the existing RoomId if
        // present, else inserts a new one. DashMap guarantees
        // atomicity across concurrent callers.
        let room_id = self
            .rooms
            .entry(key)
            .or_insert_with(RoomId::new)
            .clone();
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
}
