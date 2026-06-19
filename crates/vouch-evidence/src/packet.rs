//! Sealed packet re-export surface for vouch-evidence.

pub use themis_evidence::packet::{
    DsseEnvelope, DsseSignature, EvError, EvidenceService, SealedPacket,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_are_reexported() {
        // Compile-time check: the type names resolve through
        // vouch_evidence::packet.
        fn _accepts<T: Send + Sync + 'static>() {}
        _accepts::<SealedPacket>();
        _accepts::<EvidenceService>();
    }
}
