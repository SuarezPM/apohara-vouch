//! Ed25519 signer + multi-tenant key file IO.
//!
//! Two ways to construct a `SignerService`:
//!
//! - **`from_seed(tenant, [u8; 32])`** — in-memory seed (tests +
//!   the verifier binary's deterministic replay).
//! - **`new(tenant, key_dir)`** — reads `keys/{tenant}.ed25519`
//!   from disk (creates it with random bytes + chmod 600 if
//!   missing). This is the legacy path; suitable for dev machines
//!   with persistent FS.
//! - **`for_tenant(tenant)`** — compile-time baked key via
//!   `include_bytes!`. The 2 fixture tenants (stark, wayne) have
//!   their 32-byte seeds committed to `keys/{tenant}.ed25519`
//!   and embedded in the binary. **This is the deployment path**
//!   (R4 + R8 mitigation: Vercel's ephemeral FS cannot persist
//!   generated keys across deploys; baked keys survive that).

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use thiserror::Error;

/// Stark's baked-in Ed25519 seed (32 bytes, hex sha256 of
/// `themis-stark-tenant-baked-seed-v1`). Embedded at compile time
/// via `include_bytes!`; survives Vercel's ephemeral FS.
pub static STARK_SEED: [u8; 32] = *include_bytes!("../keys/stark.ed25519");

/// Wayne's baked-in Ed25519 seed (32 bytes, hex sha256 of
/// `themis-wayne-tenant-baked-seed-v1`).
pub static WAYNE_SEED: [u8; 32] = *include_bytes!("../keys/wayne.ed25519");

/// An Ed25519 keypair (signing + verifying).
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// The signing key (private).
    pub signing: SigningKey,
    /// The verifying key (public).
    pub verifying: VerifyingKey,
}

impl KeyPair {
    /// Generate a fresh random keypair using the OS RNG.
    pub fn generate() -> Self {
        let mut csprng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        let signing = SigningKey::from_bytes(&bytes);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Construct from a 32-byte seed (deterministic).
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Hex-encoded public key (64 chars).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying.to_bytes())
    }
}

/// Signer errors.
#[derive(Debug, Error)]
pub enum SignerError {
    /// IO error reading or writing the key file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Key file is not exactly 32 bytes.
    #[error("invalid key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
    /// `for_tenant` was called with an id that has no baked key.
    #[error("no baked key for tenant: {0} (use `from_seed` or `new` instead)")]
    UnknownTenant(String),
}

/// Per-tenant signing service. Holds the signing key in memory;
/// loads from / writes to `keys/{tenant}.ed25519` on construction.
pub struct SignerService {
    keypair: KeyPair,
    tenant_id: String,
}

impl std::fmt::Debug for SignerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerService")
            .field("tenant_id", &self.tenant_id)
            .field("public_key_hex", &self.keypair.public_key_hex())
            .finish()
    }
}

impl SignerService {
    /// New signer for the given tenant. Reads `keys/{tenant}.ed25519`
    /// (creating it with random bytes + chmod 600 if missing).
    pub fn new(tenant_id: impl Into<String>, key_dir: &Path) -> Result<Self, SignerError> {
        let tenant_id = tenant_id.into();
        std::fs::create_dir_all(key_dir)?;
        let key_path = key_dir.join(format!("{tenant_id}.ed25519"));
        let keypair = if key_path.exists() {
            let bytes = std::fs::read(&key_path)?;
            if bytes.len() != 32 {
                return Err(SignerError::InvalidKeyLength(bytes.len()));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            KeyPair::from_bytes(seed)
        } else {
            let kp = KeyPair::generate();
            std::fs::write(&key_path, kp.signing.to_bytes())?;
            // chmod 600 on Unix. On non-Unix this is a no-op.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&key_path, perms)?;
            }
            kp
        };
        Ok(Self { keypair, tenant_id })
    }

    /// New signer from an in-memory seed (no file IO). For tests.
    pub fn from_seed(tenant_id: impl Into<String>, seed: [u8; 32]) -> Self {
        Self {
            keypair: KeyPair::from_bytes(seed),
            tenant_id: tenant_id.into(),
        }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.signing.sign(message)
    }

    /// Sign a message, return hex-encoded signature (128 chars).
    pub fn sign_hex(&self, message: &[u8]) -> String {
        hex::encode(self.sign(message).to_bytes())
    }

    /// Verify a signature. Returns true iff the signature is valid
    /// for the given message under this signer's public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.keypair.verifying.verify(message, signature).is_ok()
    }

    /// Hex-encoded public key (64 chars).
    pub fn public_key_hex(&self) -> String {
        self.keypair.public_key_hex()
    }

    /// The signer's tenant id.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Build a `SignerService` from a compile-time baked seed for
    /// the two fixture tenants (`stark`, `wayne`). The seeds live
    /// in `keys/{tenant}.ed25519` and are embedded via
    /// `include_bytes!`. Returns `SignerError::UnknownTenant` for
    /// any other tenant id (callers must use `from_seed` or `new`
    /// for non-baked tenants).
    pub fn for_tenant(tenant_id: &str) -> Result<Self, SignerError> {
        let seed: [u8; 32] = match tenant_id {
            "stark" => STARK_SEED,
            "wayne" => WAYNE_SEED,
            other => {
                return Err(SignerError::UnknownTenant(other.to_string()));
            }
        };
        Ok(Self::from_seed(tenant_id, seed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = SignerService::from_seed("stark", [1u8; 32]);
        let msg = b"hello world";
        let sig = signer.sign(msg);
        assert!(signer.verify(msg, &sig));
    }

    #[test]
    fn from_seed_is_deterministic() {
        let s1 = SignerService::from_seed("stark", [1u8; 32]);
        let s2 = SignerService::from_seed("stark", [1u8; 32]);
        assert_eq!(s1.public_key_hex(), s2.public_key_hex());
        assert_eq!(s1.sign_hex(b"hello"), s2.sign_hex(b"hello"),);
    }

    #[test]
    fn from_seed_distinct_tenants_differ() {
        let s1 = SignerService::from_seed("stark", [1u8; 32]);
        let s2 = SignerService::from_seed("wayne", [2u8; 32]);
        assert_ne!(s1.public_key_hex(), s2.public_key_hex());
    }

    #[test]
    fn public_key_hex_is_64_chars() {
        let s = SignerService::from_seed("x", [0u8; 32]);
        assert_eq!(s.public_key_hex().len(), 64);
    }

    #[test]
    fn sign_hex_is_128_chars() {
        let s = SignerService::from_seed("x", [0u8; 32]);
        assert_eq!(s.sign_hex(b"hello").len(), 128);
    }

    #[test]
    fn verify_fails_on_tampered_message() {
        let s = SignerService::from_seed("x", [0u8; 32]);
        let sig = s.sign(b"hello");
        assert!(!s.verify(b"hellp", &sig));
    }

    #[test]
    fn new_persists_key_with_chmod_600() {
        let tmp = TempDir::new().unwrap();
        let s1 = SignerService::new("stark", tmp.path()).unwrap();
        // Second construction reads the same file → same key.
        let s2 = SignerService::new("stark", tmp.path()).unwrap();
        assert_eq!(s1.public_key_hex(), s2.public_key_hex());

        // chmod 600 on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = tmp.path().join("stark.ed25519");
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn new_rejects_invalid_key_length() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("broken.ed25519");
        std::fs::write(&path, b"short").unwrap();
        let err = SignerService::new("broken", tmp.path()).unwrap_err();
        assert!(matches!(err, SignerError::InvalidKeyLength(5)));
    }

    #[test]
    fn for_tenant_returns_baked_signers() {
        let stark = SignerService::for_tenant("stark").unwrap();
        let wayne = SignerService::for_tenant("wayne").unwrap();
        assert_eq!(stark.tenant_id(), "stark");
        assert_eq!(wayne.tenant_id(), "wayne");
        // The two tenants must NOT share a key.
        assert_ne!(stark.public_key_hex(), wayne.public_key_hex());
    }

    #[test]
    fn for_tenant_is_deterministic() {
        // Same tenant → same keypair (baked seeds are constants).
        let s1 = SignerService::for_tenant("stark").unwrap();
        let s2 = SignerService::for_tenant("stark").unwrap();
        assert_eq!(s1.public_key_hex(), s2.public_key_hex());
        // Same input → same signature (deterministic Ed25519).
        let msg = b"deterministic test";
        assert_eq!(s1.sign_hex(msg), s2.sign_hex(msg));
    }

    #[test]
    fn for_tenant_rejects_unknown_tenant() {
        let err = SignerService::for_tenant("lexcorp").unwrap_err();
        assert!(matches!(err, SignerError::UnknownTenant(t) if t == "lexcorp"));
    }

    #[test]
    fn cross_tenant_verify_fails_with_baked_keys() {
        let stark = SignerService::for_tenant("stark").unwrap();
        let wayne = SignerService::for_tenant("wayne").unwrap();
        let msg = b"only stark should be able to verify this";
        let sig = stark.sign(msg);
        // Wayne cannot verify Stark's signature.
        assert!(!wayne.verify(msg, &sig));
        // But Stark can.
        assert!(stark.verify(msg, &sig));
    }

    #[test]
    fn baked_seed_is_32_bytes() {
        assert_eq!(STARK_SEED.len(), 32);
        assert_eq!(WAYNE_SEED.len(), 32);
        // Stark and Wayne seeds differ (no key reuse).
        assert_ne!(STARK_SEED, WAYNE_SEED);
    }
}
