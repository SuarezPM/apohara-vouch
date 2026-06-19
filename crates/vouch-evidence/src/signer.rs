//! Signer re-export surface for vouch-evidence.
//!
//! The actual crypto lives in `themis-evidence::signer`. This
//! module is a stable alias for callers that prefer the
//! vouch-* import path.

pub use themis_evidence::signer::{KeyPair, SignerError, SignerService, STARK_SEED, WAYNE_SEED};

/// Per-tenant signer factory. Alias for
/// [`themis_evidence::signer::SignerService::for_tenant`].
pub fn signer_for_tenant(tenant_id: &str) -> Result<SignerService, SignerError> {
    SignerService::for_tenant(tenant_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_for_tenant_works() {
        let s = signer_for_tenant("stark").expect("stark is baked");
        assert_eq!(s.tenant_id(), "stark");
    }
}
