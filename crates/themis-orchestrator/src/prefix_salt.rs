//! Prefix Salt Planner — per-request cache_salt for the orchestrator.
//!
//! Ported from Apohara Context Forge's `serving/prefix_salt_planner.py:65-72`.
//! Produces the `cache_salt` string each agent's request carries. Backends
//! that key KV blocks by `hash(cache_salt, token_ids, ...)` (vLLM's
//! Automatic Prefix Caching, SGLang's RadixAttention) will only share
//! blocks between two requests when their `cache_salt` matches AND the
//! leading tokens are byte-identical.
//!
//! ## Two plans
//!
//! * **plan_shared** — agents that legitimately share the same prefix
//!   anchor get the SAME salt and therefore SHARE KV blocks intra-
//!   instance (free, native to the backend).
//! * **plan_isolated** — judge-class agents whose JCR Safety Gate fired
//!   INV-15 (use_dense=true) get a UNIQUE salt per request, forcing the
//!   backend to allocate fresh blocks. This is the serving-side
//!   realisation of INV-15: a judge under high JCR risk never reuses
//!   another agent's KV blocks.
//!
//! The digest is SHA-256 over the namespace plus all parts (joined
//! with a unit-separator byte `\x1f` so ambiguous concatenations can't
//! collide), truncated to 16 hex chars.

use sha2::{Digest, Sha256};

/// Stable namespace so salts from this planner cannot accidentally
/// collide with salts produced by some other subsystem that hashes
/// raw integers.
pub const SALT_NAMESPACE: &str = "apohara.apc.v1";

/// Prefix on the shared (intra-instance reuse) salt. Human-greppable
/// in backend logs; can never equal an isolated salt (which is
/// prefixed differently).
pub const SHARED_PREFIX: &str = "shared";

/// Prefix on the isolated (dense) salt. Can never equal a shared salt.
pub const ISOLATED_PREFIX: &str = "iso";

/// Length of the hex-char digest in the final salt string.
const DIGEST_HEX_LEN: usize = 16;

/// The cache_salt decision for a single agent request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaltPlan {
    /// The string to pass to the backend as the per-request salt.
    pub cache_salt: String,
    /// True if this salt is reused across agents with the same
    /// anchor (KV blocks are shared); false if the salt is unique
    /// to isolate the request (INV-15 dense path).
    pub shared: bool,
    /// Human-readable explanation, mirrors the JCR gate's reasoning
    /// when isolation was triggered.
    pub reason: String,
}

/// Compute the stable 16-hex-char digest over the namespace + parts.
fn digest(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SALT_NAMESPACE.as_bytes());
    for p in parts {
        hasher.update([0x1f_u8]); // unit separator — avoids ambiguous concatenation
        hasher.update(p.as_bytes());
    }
    let bytes = hasher.finalize();
    // Take the first 8 bytes (16 hex chars). 8 bytes = 64 bits of
    // entropy, which is plenty for a request-scoped cache key.
    let mut hex = String::with_capacity(DIGEST_HEX_LEN);
    for b in &bytes[..DIGEST_HEX_LEN / 2] {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

/// Plan a shared (intra-instance reuse) salt for an agent that
/// shares a prefix anchor with other agents.
///
/// * `anchor_hash` — opaque anchor identifier (e.g. the
///   `base_kv_hash` an anchor pool assigns to a prefix).
/// * `cla_group` — classification group identifier.
///
/// The plan is **deterministic**: the same `(anchor_hash, cla_group)`
/// always produces the same salt. Two requests in the same group
/// will hit the backend's prefix cache and share KV blocks.
pub fn plan_shared(anchor_hash: &str, cla_group: &str) -> SaltPlan {
    let d = digest(&[anchor_hash, cla_group]);
    SaltPlan {
        cache_salt: format!("{}:{}:{}", SHARED_PREFIX, SALT_NAMESPACE, d),
        shared: true,
        reason: format!(
            "shared salt for anchor={} group={} (KV blocks reused intra-instance)",
            anchor_hash, cla_group
        ),
    }
}

/// Plan an isolated (dense, INV-15) salt for a judge agent under
/// high JCR risk.
///
/// * `request_id` — caller-supplied unique identifier for the
///   request (e.g. UUID). Two distinct judge requests with distinct
///   `request_id` never collide with each other or with the shared
///   group.
///
/// The plan's `shared` is `false` — the backend MUST allocate fresh
/// blocks for this request (no KV reuse).
pub fn plan_isolated(request_id: &str) -> SaltPlan {
    let d = digest(&["isolated", request_id]);
    SaltPlan {
        cache_salt: format!("{}:{}:{}", ISOLATED_PREFIX, SALT_NAMESPACE, d),
        shared: false,
        reason: format!(
            "isolated salt for request_id={} (INV-15 dense prefill, no KV reuse)",
            request_id
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_shared_is_deterministic() {
        // Same input → same output.
        let a = plan_shared("anchor-abc", "stark-room");
        let b = plan_shared("anchor-abc", "stark-room");
        assert_eq!(a, b);
    }

    #[test]
    fn plan_isolated_starts_with_iso_prefix() {
        let p = plan_isolated("req-123");
        assert!(p.cache_salt.starts_with("iso:"));
        assert!(!p.shared);
    }

    #[test]
    fn plan_shared_starts_with_shared_prefix() {
        let p = plan_shared("anchor-abc", "stark-room");
        assert!(p.cache_salt.starts_with("shared:"));
        assert!(p.shared);
    }

    #[test]
    fn different_anchors_produce_different_shared_salts() {
        let a = plan_shared("anchor-abc", "stark-room");
        let b = plan_shared("anchor-xyz", "stark-room");
        assert_ne!(a.cache_salt, b.cache_salt);
    }

    #[test]
    fn different_groups_produce_different_shared_salts() {
        let a = plan_shared("anchor-abc", "stark-room");
        let b = plan_shared("anchor-abc", "wayne-room");
        assert_ne!(a.cache_salt, b.cache_salt);
    }

    #[test]
    fn different_request_ids_produce_different_isolated_salts() {
        let a = plan_isolated("req-001");
        let b = plan_isolated("req-002");
        assert_ne!(a.cache_salt, b.cache_salt);
    }

    #[test]
    fn digest_length_is_exactly_16_hex_chars() {
        // Extract the digest portion of a shared salt.
        let p = plan_shared("anchor-abc", "stark-room");
        let parts: Vec<&str> = p.cache_salt.split(':').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], SHARED_PREFIX);
        assert_eq!(parts[1], SALT_NAMESPACE);
        assert_eq!(parts[2].len(), 16);
        // And every char is a hex digit.
        for c in parts[2].chars() {
            assert!(c.is_ascii_hexdigit(), "{} is not hex", c);
        }
    }

    #[test]
    fn isolated_and_shared_salts_cannot_collide() {
        // The "iso" and "shared" prefixes are disjoint strings, so the
        // resulting salts can never be equal. (Defensive — the prefix
        // is what makes this safe, not the digest.)
        let shared = plan_shared("anchor-abc", "stark-room");
        let isolated = plan_isolated("req-001");
        assert_ne!(shared.cache_salt, isolated.cache_salt);
    }

    #[test]
    fn namespace_appears_in_both_plans() {
        // Both plans include the SALT_NAMESPACE as the second
        // colon-separated component, so backend log filters can scope
        // to "apohara" salts.
        let shared = plan_shared("a", "g");
        let isolated = plan_isolated("r");
        assert!(shared.cache_salt.contains(SALT_NAMESPACE));
        assert!(isolated.cache_salt.contains(SALT_NAMESPACE));
    }

    #[test]
    fn reason_field_explains_decision() {
        let shared = plan_shared("anchor-abc", "stark-room");
        let isolated = plan_isolated("req-001");
        assert!(shared.reason.contains("shared"));
        assert!(shared.reason.contains("anchor=anchor-abc"));
        assert!(isolated.reason.contains("isolated"));
        assert!(isolated.reason.contains("INV-15"));
    }
}
