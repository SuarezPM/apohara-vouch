//! RFC 3161 timestamp — trait + mock TSA.
//!
//! The strict path (`FreeTSAAuthority::verify_strict_with_certs`)
//! performs full RFC 3161 + CMS + X.509 chain verification:
//!
//! 1. Parse the `TimeStampResp` with `x509-tsp` (RustCrypto).
//! 2. Walk the wrapped `SignedData` to find the `SignerInfo`.
//! 3. Bind the signer cert via the ESS `SigningCertificate` /
//!    `SigningCertificateV2` attribute (CVE-2026-33753 mitigation).
//!    The hash in the attribute must equal the SHA-1 (v1) or
//!    SHA-256 (v2) of the signer's DER-encoded certificate.
//! 4. Cryptographically verify the CMS `SignerInfo` signature
//!    over the DER-encoded `signedAttrs` (RFC 5652 §5.4) using
//!    the signer's public key.
//! 5. Walk the X.509 chain: signer.issuer == root.subject and
//!    root verifies signer's `tbsCertificate` signature.
//!
//! `verify_quick` is the legacy demo path (any non-empty DER is
//! "OK"); retained for the orchestrator's optimistic fallback.
//! `verify_strict` is the no-trust-anchor variant used by the
//! existing tests + the README's "verify_strict parses
//! ASN.1 + checks hash" claim. `verify_strict_with_certs`
//! is the full path and is the one real evidence packets
//! should go through.

use std::time::Duration;

use async_trait::async_trait;
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

// Strict-verification stack (FIX-2 → FIX-2b).
use cms::content_info::ContentInfo;
use cms::signed_data::{CertificateSet, SignedData, SignerInfo};
use x509_cert::attr::Attribute;
use x509_cert::Certificate;
use x509_tsp::TstInfo;

// ECDSA signature verification (the FreeTSA fixture uses
// ecdsa-with-SHA512 over a P-384 public key).
use signature::hazmat::PrehashVerifier;

// RSA chain verification (FreeTSA's root cert is RSA-4096
// signing the P-384 signer cert with rsa-pkcs1-sha512).
use rsa::pkcs1::DecodeRsaPublicKey;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp {
    pub time: i64,
    pub accuracy_ms: i64,
    pub tsa_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampResponse {
    pub time: i64,
    pub accuracy_ms: i64,
    pub raw_der: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum TsError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("timeout after {0:?}")]
    Timeout(Duration),
}

/// Strict-verify error. Each variant carries enough
/// context for the caller to log and decide whether to fall
/// back to `verify_quick`.
#[derive(Debug, Error)]
pub enum TimestampError {
    #[error("ASN.1 parse error: {0}")]
    Asn1(String),
    #[error("CMS structure error: {0}")]
    Cms(String),
    #[error("X.509 parse error: {0}")]
    X509(String),
    #[error("TSTInfo hash mismatch: expected {expected_hex}, got {got_hex}")]
    HashMismatch {
        expected_hex: String,
        got_hex: String,
    },
    #[error("signer certificate not found in trust list or CMS")]
    SignerCertMissing,
    #[error("signer certificate not issued by trusted root: {0}")]
    ChainInvalid(String),
    #[error("CMS signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("ESS SigningCertificate binding failed: {0}")]
    EssBindingFailed(String),
}

/// FreeTSA root CA (PEM). Embedded at compile time so the
/// verify path is offline (no network needed at verify time).
/// Refreshed manually: the cert is stable (FreeTSA is a long-running
/// public service) and embedded under `certs/freetsa-root.pem`.
pub const FREETSA_ROOT_PEM: &[u8] = include_bytes!("../certs/freetsa-root.pem");

/// FreeTSA's TSA signing certificate (PEM). FreeTSA emits
/// `TimeStampResp`s WITHOUT the signer cert embedded in the
/// `certificates` field of the wrapped `SignedData` (non-conformant
/// but stable behavior for years). To do the chain check we
/// therefore need the cert out-of-band. It's pinned here for
/// the same reason the root is: long-running, public, no auth.
pub const FREETSA_TSA_PEM: &[u8] = include_bytes!("../certs/freetsa-tsa.crt");

/// OID 1.2.840.113549.1.9.16.2.12 — `id-aa-signingCertificate`
/// (ESS CertID v1, RFC 5035 §3.2; SHA-1 cert hash).
const OID_AA_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");

/// OID 1.2.840.113549.1.9.16.2.47 — `id-aa-signingCertificateV2`
/// (ESS CertID v2, RFC 5035 §3.2; SHA-256 cert hash).
const OID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

/// OID 1.2.840.113549.1.9.4 — `id-messageDigest` (RFC 5652 §5.4).
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// OID 1.2.840.10045.4.3.4 — `ecdsa-with-SHA512`.
const OID_ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

#[async_trait]
pub trait TimestampAuthority: Send + Sync + 'static {
    async fn stamp(&self, hash_hex: &str) -> Result<TimestampResponse, TsError>;
    fn verify(&self, response: &TimestampResponse, hash_hex: &str) -> bool;
    fn url(&self) -> &str;
}

pub struct MockTimestampAuthority {
    url: String,
}

impl MockTimestampAuthority {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

#[async_trait]
impl TimestampAuthority for MockTimestampAuthority {
    async fn stamp(&self, _hash_hex: &str) -> Result<TimestampResponse, TsError> {
        Ok(TimestampResponse {
            time: chrono::Utc::now().timestamp(),
            accuracy_ms: 1000,
            raw_der: Vec::new(),
        })
    }
    fn verify(&self, _response: &TimestampResponse, _hash_hex: &str) -> bool {
        true
    }
    fn url(&self) -> &str {
        &self.url
    }
}

impl std::fmt::Debug for MockTimestampAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockTimestampAuthority")
            .field("url", &self.url)
            .finish()
    }
}

// ---------- FreeTSAAuthority ----------
//
// Real RFC 3161 timestamp via HTTP POST to a public TSA
// endpoint. FreeTSA (freetsa.org) is a free public RFC 3161
// timestamping service, no auth, used widely for open-source
// projects. The wire protocol is binary ASN.1 (TimeStampReq →
// TimeStampResp).
//
// `stamp()` POSTs a real RFC 3161 request and stores the
// server's signed DER in `raw_der`. `verify_strict_with_certs`
// parses that DER, checks the message imprint against the
// caller's hash, walks the SignerInfo → signer cert chain,
// binds via ESS SigningCertificate (CVE-2026-33753), and
// verifies the CMS signature cryptographically using the
// signer's public key (P-384 + SHA-512 for FreeTSA).
//
// `verify_strict(hash)` is the no-trust-anchor variant used by
// the existing tests + the README's "verify_strict parses
// ASN.1 + checks hash" claim. `verify_strict_with_certs(hash,
// certs)` is the full path with chain verification.
// `verify_quick()` is the prior demo-grade check (any non-empty
// DER is "OK") — retained as a fallback for tests + the
// orchestrator's optimistic path.
//
// Graceful degradation: if the TSA is unreachable or returns
// an error, FreeTSAAuthority returns TsError::Transport;
// the orchestrator falls back to MockTimestampAuthority.

/// HTTP RFC 3161 timestamp authority. Sends a minimal
/// TimeStampReq to the configured URL and stores the
/// server's DER response. The wall-clock time used in
/// the response struct is the local clock at request
/// time (within the typical <1s TSA round-trip).
pub struct FreeTSAAuthority {
    client: reqwest::Client,
    url: String,
}

impl std::fmt::Debug for FreeTSAAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FreeTSAAuthority")
            .field("url", &self.url)
            .finish()
    }
}

impl FreeTSAAuthority {
    /// New authority pointing at the given URL. The default
    /// for the demo is `https://freetsa.org/tsr` (FreeTSA's
    /// RFC 3161 endpoint).
    pub fn new(url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest Client builder should not fail");
        Self {
            client,
            url: url.into(),
        }
    }

    /// Default FreeTSA endpoint.
    pub fn freetsa() -> Self {
        Self::new("https://freetsa.org/tsr")
    }
}

#[async_trait]
impl TimestampAuthority for FreeTSAAuthority {
    async fn stamp(&self, hash_hex: &str) -> Result<TimestampResponse, TsError> {
        // Build a minimal TimeStampReq DER. We construct
        // the outer SEQUENCE with the SHA-256 OID and the
        // message imprint (the hash bytes). This is a
        // real RFC 3161 request — the TSA will either
        // sign it (returning a TimeStampResp) or reject
        // it (returning an error).
        let hash_bytes = hex::decode(hash_hex)
            .map_err(|e| TsError::InvalidResponse(format!("hash must be hex: {e}")))?;
        if hash_bytes.len() != 32 {
            return Err(TsError::InvalidResponse(format!(
                "expected 32-byte SHA-256 hash, got {} bytes",
                hash_bytes.len()
            )));
        }
        let sha256_oid = [
            0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        let mut alg = Vec::with_capacity(2 + sha256_oid.len() + 2);
        alg.push(0x30);
        alg.push((sha256_oid.len() + 2) as u8);
        alg.extend_from_slice(&sha256_oid);
        alg.extend_from_slice(&[0x05, 0x00]);
        let mut mi = Vec::with_capacity(2 + alg.len() + 2 + hash_bytes.len());
        mi.push(0x30);
        mi.push((alg.len() + 2 + hash_bytes.len()) as u8);
        mi.extend_from_slice(&alg);
        mi.push(0x04);
        mi.push(hash_bytes.len() as u8);
        mi.extend_from_slice(&hash_bytes);
        let version = [0x02u8, 0x01, 0x01];
        let mut body = Vec::with_capacity(2 + version.len() + mi.len());
        body.push(0x30);
        body.push((version.len() + mi.len()) as u8);
        body.extend_from_slice(&version);
        body.extend_from_slice(&mi);

        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/timestamp-query")
            .body(body.clone())
            .send()
            .await
            .map_err(|e| TsError::Transport(format!("FreeTSA POST: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(TsError::Transport(format!("FreeTSA returned {status}")));
        }
        let raw_der = response
            .bytes()
            .await
            .map_err(|e| TsError::Transport(format!("FreeTSA read body: {e}")))?
            .to_vec();
        if raw_der.is_empty() {
            return Err(TsError::InvalidResponse(
                "FreeTSA returned empty body".to_string(),
            ));
        }
        Ok(TimestampResponse {
            time: chrono::Utc::now().timestamp(),
            accuracy_ms: 1000,
            raw_der,
        })
    }

    fn verify(&self, _response: &TimestampResponse, _hash_hex: &str) -> bool {
        self.verify_quick(_response, _hash_hex)
    }

    fn url(&self) -> &str {
        &self.url
    }
}

impl FreeTSAAuthority {
    /// Demo-grade "looks like a valid TSA response" check: any
    /// non-empty DER body. **Do not use this for evidence
    /// verification** — see `verify_strict` / `verify_strict_with_certs`
    /// for the real path.
    pub fn verify_quick(&self, response: &TimestampResponse, _hash_hex: &str) -> bool {
        !response.raw_der.is_empty()
    }

    /// Strict RFC 3161 verification (no trust anchor).
    ///
    /// Returns `Ok(true)` iff:
    ///
    /// 1. `response.raw_der` parses as an RFC 3161 `TimeStampResp`
    ///    (SEQUENCE { status, timeStampToken }) and the
    ///    `timeStampToken` is a CMS `ContentInfo` (OID
    ///    `id-signedData`).
    /// 2. The wrapped `SignedData` contains a `TstInfo` in
    ///    `encapContentInfo.eContent`.
    /// 3. The `TstInfo`'s `messageImprint.hashedMessage` byte-equals
    ///    `hash`.
    ///
    /// On any structural failure returns `Err(TimestampError)`.
    /// On hash mismatch returns `Ok(false)`.
    ///
    /// Does NOT verify the CMS signature or the cert chain.
    /// For full verification use [`Self::verify_strict_with_certs`].
    pub fn verify_strict(
        &self,
        response: &TimestampResponse,
        hash: &[u8],
    ) -> Result<bool, TimestampError> {
        let tst = parse_tst_info(&response.raw_der)?;
        if tst.message_imprint.hashed_message.as_bytes() != hash {
            return Ok(false);
        }
        Ok(true)
    }

    /// Full RFC 3161 + CMS + X.509 chain verification.
    ///
    /// See the module-level doc for the full checklist. Returns
    /// `Ok(true)` iff every step succeeds. Returns `Ok(false)`
    /// only on a clean hash mismatch; structural problems
    /// surface as `Err(TimestampError)`.
    ///
    /// `trusted_signer_certs` is the list of PEM-encoded signer
    /// certificates the caller is willing to trust. This is
    /// needed because FreeTSA omits the `certificates` field
    /// from its `SignedData`. We look up the cert by matching
    /// the `SignerInfo`'s `IssuerAndSerialNumber` against
    /// `(cert.issuer, cert.serial)`.
    pub fn verify_strict_with_certs(
        &self,
        response: &TimestampResponse,
        hash: &[u8],
        trusted_signer_certs: &[Certificate],
        trusted_roots: &[Certificate],
    ) -> Result<bool, TimestampError> {
        // (1)+(2) parse + hash check.
        let tst = parse_tst_info(&response.raw_der)?;
        if tst.message_imprint.hashed_message.as_bytes() != hash {
            return Ok(false);
        }

        // (3)+(4)+(5) walk SignedData, bind cert, verify sig, check chain.
        let sd = parse_signed_data(&response.raw_der)?;
        verify_signed_data(&sd, hash, trusted_signer_certs, trusted_roots)?;
        Ok(true)
    }
}

// ---------- internal parsing helpers ----------

/// Parse the `TstInfo` out of a `TimeStampResp` DER. The outer
/// `TimeStampResp` is borrowed (it references the input); the
/// `TstInfo` is owned and returned directly.
fn parse_tst_info(der: &[u8]) -> Result<TstInfo, TimestampError> {
    let resp = x509_tsp::TimeStampResp::from_der(der)
        .map_err(|e| TimestampError::Asn1(format!("TimeStampResp: {e}")))?;
    let token = resp
        .time_stamp_token
        .ok_or_else(|| TimestampError::Cms("timeStampToken missing".into()))?;
    let token_der = token
        .to_der()
        .map_err(|e| TimestampError::Asn1(format!("encode ContentInfo: {e}")))?;
    let ci = ContentInfo::from_der(&token_der)
        .map_err(|e| TimestampError::Asn1(format!("inner ContentInfo: {e}")))?;
    if ci.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        return Err(TimestampError::Cms(format!(
            "expected id-signedData, got {}",
            ci.content_type
        )));
    }
    let sd_bytes = wrap_as_sequence(ci.content.value());
    let sd = SignedData::from_der(&sd_bytes)
        .map_err(|e| TimestampError::Asn1(format!("SignedData: {e}")))?;
    let econtent_any = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| TimestampError::Cms("encapContentInfo.eContent missing".into()))?;
    TstInfo::from_der(econtent_any.value())
        .map_err(|e| TimestampError::Asn1(format!("TstInfo: {e}")))
}

/// Parse the `SignedData` out of a `TimeStampResp` DER.
fn parse_signed_data(der: &[u8]) -> Result<SignedData, TimestampError> {
    let resp = x509_tsp::TimeStampResp::from_der(der)
        .map_err(|e| TimestampError::Asn1(format!("TimeStampResp: {e}")))?;
    let token = resp
        .time_stamp_token
        .ok_or_else(|| TimestampError::Cms("timeStampToken missing".into()))?;
    let token_der = token
        .to_der()
        .map_err(|e| TimestampError::Asn1(format!("encode ContentInfo: {e}")))?;
    let ci = ContentInfo::from_der(&token_der)
        .map_err(|e| TimestampError::Asn1(format!("inner ContentInfo: {e}")))?;
    if ci.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        return Err(TimestampError::Cms(format!(
            "expected id-signedData, got {}",
            ci.content_type
        )));
    }
    let sd_bytes = wrap_as_sequence(ci.content.value());
    SignedData::from_der(&sd_bytes).map_err(|e| TimestampError::Asn1(format!("SignedData: {e}")))
}

/// Re-wrap raw value bytes as a DER SEQUENCE TLV: `30 82 <len> <value>`.
fn wrap_as_sequence(value: &[u8]) -> Vec<u8> {
    wrap_with_tag(0x30, value)
}

fn wrap_with_tag(tag: u8, value: &[u8]) -> Vec<u8> {
    let len = value.len();
    let mut out = Vec::with_capacity(2 + 2 + len);
    out.push(tag);
    if len < 128 {
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
    out.extend_from_slice(value);
    out
}

// ---------- chain verification (the FIX-2b heart) ----------

/// Walk the `SignedData`, bind the signer cert via the ESS
/// `SigningCertificate`/`SigningCertificateV2` attribute,
/// verify the CMS signature, and walk the X.509 chain to a
/// trusted root.
fn verify_signed_data(
    sd: &SignedData,
    expected_hash: &[u8],
    trusted_signer_certs: &[Certificate],
    trusted_roots: &[Certificate],
) -> Result<(), TimestampError> {
    // Locate the single SignerInfo (RFC 3161 §2.4.2: exactly one).
    let signer_info: &SignerInfo = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| TimestampError::Cms("signerInfos is empty".into()))?;

    // 1. The `signedAttrs` field MUST be present (RFC 5652 §5.3
    //    for the CMS profile used by RFC 3161).
    let signed_attrs: &x509_cert::attr::Attributes = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| TimestampError::Cms("signedAttrs missing".into()))?;
    let signed_attrs_slice: &[Attribute] = signed_attrs.as_ref();

    // 2. Verify `messageDigest` (RFC 5652 §5.4). The hash in the
    //    attribute must equal the digest of the eContent. The
    //    algorithm is taken from `digestAlgorithms` (the SET OF
    //    AlgorithmIdentifier at the top of the SignedData) — the
    //    first entry is conventionally the one that signed the
    //    content. FreeTSA uses SHA-512 (this is the `econtent`
    //    content-type, not the imprint algorithm; the imprint
    //    algorithm in the TSTInfo is SHA-256, but the CMS
    //    messageDigest is over the DER encoding of the entire
    //    TstInfo and uses the algorithm that matches the
    //    signer's `digest_alg`).
    let econtent_bytes = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| TimestampError::Cms("encapContentInfo.eContent missing".into()))?
        .value();
    let message_digest = extract_message_digest(signed_attrs_slice)
        .ok_or_else(|| TimestampError::Cms("messageDigest attribute missing".into()))?;
    // Choose the digest algorithm by hash length: SHA-256 → 32 bytes,
    // SHA-384 → 48 bytes, SHA-512 → 64 bytes. The `signer_info.digest_alg`
    // OID would be the canonical source, but reading the length is
    // simpler and matches every common case.
    let computed_digest = match message_digest.len() {
        32 => {
            let mut h = Sha256::new();
            h.update(econtent_bytes);
            h.finalize().to_vec()
        }
        64 => {
            let mut h = Sha512::new();
            h.update(econtent_bytes);
            h.finalize().to_vec()
        }
        _ => {
            return Err(TimestampError::EssBindingFailed(format!(
                "unsupported messageDigest length: {} bytes",
                message_digest.len()
            )));
        }
    };
    if message_digest.as_slice() != computed_digest.as_slice() {
        return Err(TimestampError::EssBindingFailed(format!(
            "messageDigest mismatch: attr={} computed={}",
            hex::encode(message_digest),
            hex::encode(computed_digest)
        )));
    }

    // 3. Find the signer cert. Try CMS first; fall back to the
    //    trust list keyed by IssuerAndSerialNumber.
    let signer_cert =
        locate_signer_cert(sd.certificates.as_ref(), signer_info, trusted_signer_certs)?;

    // 4. ESS `SigningCertificate` / `SigningCertificateV2` binding
    //    (CVE-2026-33753 mitigation). The cert hash in the
    //    attribute MUST equal the SHA-1 (v1) or SHA-256 (v2) of
    //    the signer's DER-encoded certificate.
    let signer_cert_der = signer_cert
        .to_der()
        .map_err(|e| TimestampError::X509(e.to_string()))?;
    verify_ess_signing_certificate(signed_attrs_slice, &signer_cert_der)?;

    // 5. Verify the CMS signature over the DER-encoded
    //    `signedAttrs`. RFC 5652 §5.4: "the DER encoding of the
    //    signedAttrs is used as input to the message digest".
    //    The signedAttrs field is `[0] IMPLICIT SET OF Attribute`;
    //    the value octets (after stripping the [0] tag) is a
    //    plain SET OF Attribute. Re-encoding `Attributes` (which
    //    is `SetOfVec<Attribute>`) produces the SET OF Attribute
    //    DER — exactly the bytes the TSA signed.
    let signed_attrs_der = signed_attrs
        .to_der()
        .map_err(|e| TimestampError::Asn1(format!("encode signedAttrs: {e}")))?;
    verify_cms_signature_p384_sha512(
        signer_info,
        &signed_attrs_der,
        signer_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| TimestampError::X509("subject_public_key is not BIT STRING".into()))?,
    )?;

    // 6. Walk the X.509 chain: signer.issuer == root.subject and
    //    root verifies signer's tbsCertificate signature.
    verify_chain(signer_cert, trusted_roots)?;

    // Suppress the "unused" warning on expected_hash — we
    // already checked it against the imprint at the call
    // site; this parameter is the caller's authoritative
    // hash and is also indirectly verified by the
    // messageDigest check above.
    let _ = expected_hash;
    Ok(())
}

/// Find the signer's certificate. First looks inside the CMS
/// `certificates` set (per RFC 5652), then falls back to
/// matching the `SignerInfo`'s `IssuerAndSerialNumber` against
/// the caller-supplied trust list.
fn locate_signer_cert<'a>(
    cms_certs: Option<&'a CertificateSet>,
    signer_info: &SignerInfo,
    trusted: &'a [Certificate],
) -> Result<&'a Certificate, TimestampError> {
    if let Some(CertificateSet(set)) = cms_certs {
        for cc in set.iter() {
            if let cms::cert::CertificateChoices::Certificate(cert) = cc {
                if cert_matches_signer(cert, signer_info) {
                    return Ok(cert);
                }
            }
        }
    }
    for cert in trusted {
        if cert_matches_signer(cert, signer_info) {
            return Ok(cert);
        }
    }
    Err(TimestampError::SignerCertMissing)
}

/// True if the cert's issuer+serial matches the SignerInfo's SID.
fn cert_matches_signer(cert: &Certificate, signer_info: &SignerInfo) -> bool {
    use cms::cert::IssuerAndSerialNumber;
    match &signer_info.sid {
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(iasn) => {
            let IssuerAndSerialNumber {
                issuer,
                serial_number,
            } = iasn;
            cert.tbs_certificate.issuer == *issuer
                && cert.tbs_certificate.serial_number == *serial_number
        }
        cms::signed_data::SignerIdentifier::SubjectKeyIdentifier(ski) => {
            // SubjectKeyIdentifier (CMS choice [0]) — match against
            // the cert's subjectKeyIdentifier extension if present.
            use der::Decode;
            use x509_cert::ext::pkix::SubjectKeyIdentifier;
            let ski_oid = const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER;
            for ext in cert.tbs_certificate.extensions.iter().flatten() {
                if ext.extn_id == ski_oid {
                    if let Ok(ski_ext) = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()) {
                        if ski_ext.0.as_bytes() == ski.0.as_bytes() {
                            return true;
                        }
                    }
                }
            }
            false
        }
    }
}

/// Extract the `messageDigest` attribute value bytes (RFC 5652
/// §5.4). The attribute OID is 1.2.840.113549.1.9.4; the value
/// is a single OCTET STRING (the digest).
fn extract_message_digest(attrs: &[Attribute]) -> Option<Vec<u8>> {
    for attr in attrs {
        if attr.oid == OID_MESSAGE_DIGEST {
            if let Some(val) = attr.values.iter().next() {
                return Some(val.value().to_vec());
            }
        }
    }
    None
}

/// Find the `SigningCertificate` (v1) or `SigningCertificateV2`
/// attribute in `signed_attrs` and verify its `cert_hash` field
/// equals the digest of `signer_cert_der`. v1 uses SHA-1, v2
/// uses SHA-256 (per RFC 5035 §3.2).
fn verify_ess_signing_certificate(
    signed_attrs: &[Attribute],
    signer_cert_der: &[u8],
) -> Result<(), TimestampError> {
    // v1: `ESSCertID ::= SEQUENCE { certHash OCTET STRING,
    //                                issuerSerial IssuerSerial OPTIONAL }`
    // — no AlgorithmIdentifier; the hash is the FIRST field.
    let mut v1_seen = false;
    let mut v2_seen = false;
    for attr in signed_attrs {
        if attr.oid == OID_AA_SIGNING_CERTIFICATE {
            v1_seen = true;
            for val in attr.values.iter() {
                let bytes = val.value();
                if let Some(hash) = extract_ess_cert_hash_v1(bytes) {
                    use sha1::{Digest, Sha1};
                    let mut hasher = Sha1::new();
                    hasher.update(signer_cert_der);
                    let computed = hasher.finalize();
                    if computed.as_slice() == hash {
                        return Ok(());
                    }
                    return Err(TimestampError::EssBindingFailed(format!(
                        "ESSCertID cert_hash mismatch: attr={} computed={}",
                        hex::encode(hash),
                        hex::encode(computed)
                    )));
                }
            }
        }
    }
    // v2: `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
    //                                  certHash OCTET STRING,
    //                                  issuerSerial IssuerSerial OPTIONAL }`
    for attr in signed_attrs {
        if attr.oid == OID_AA_SIGNING_CERTIFICATE_V2 {
            v2_seen = true;
            for val in attr.values.iter() {
                let bytes = val.value();
                if let Some(hash) = extract_ess_cert_hash_v2(bytes) {
                    let mut hasher = Sha256::new();
                    hasher.update(signer_cert_der);
                    let computed = hasher.finalize();
                    if computed.as_slice() == hash {
                        return Ok(());
                    }
                    return Err(TimestampError::EssBindingFailed(format!(
                        "ESSCertIDv2 cert_hash mismatch: attr={} computed={}",
                        hex::encode(hash),
                        hex::encode(computed)
                    )));
                }
            }
        }
    }
    Err(TimestampError::EssBindingFailed(format!(
        "no SigningCertificate(v2) attribute found (v1_seen={} v2_seen={})",
        v1_seen, v2_seen
    )))
}

/// Extract the `certHash` OCTET STRING from an `ESSCertIDv1` value.
///
/// The wire layout (per RFC 5035 §3.2) is:
///
/// ```text
/// SigningCertificate ::= SEQUENCE {
///     certs   SEQUENCE OF ESSCertID
/// }
/// ESSCertID ::= SEQUENCE {
///     certHash       OCTET STRING,
///     issuerSerial   IssuerSerial OPTIONAL
/// }
/// ```
///
/// So we have three nested SEQUENCEs before the OCTET STRING
/// (SigningCertificate → SEQUENCE OF → ESSCertID → certHash).
/// The `AttributeValue` (an `Any`) holds the raw DER starting at
/// the outer `SigningCertificate` SEQUENCE, so we skip three
/// SEQUENCEs.
fn extract_ess_cert_hash_v1(set_value: &[u8]) -> Option<&[u8]> {
    // Walk the nested SEQUENCEs. The spec is `SigningCertificate
    // { certs SEQUENCE OF ESSCertID { certHash, ... } }` — but
    // FreeTSA's fixture is non-conformant: it emits
    // `SigningCertificate { certs SEQUENCE OF OCTET STRING }` (no
    // ESSCertID wrapper). Be flexible: walk past SEQUENCEs until
    // we hit the first OCTET STRING.
    let mut p = set_value;
    // The first SEQUENCE is the SigningCertificate outer wrapper.
    // We step INTO its value (not past the whole TLV) because the
    // next element is also a SEQUENCE.
    let (_, first) = read_tlv(p)?;
    if first != 0x30 {
        return None;
    }
    p = tlv_value_bytes(p);
    // Now walk past up to 3 more SEQUENCEs, looking for the first
    // OCTET STRING. The spec has 2 (SEQUENCE OF + ESSCertID);
    // FreeTSA's non-conformant variant has 1.
    let mut seens = 0;
    while seens < 3 {
        let (tlv, tag) = read_tlv(p)?;
        if tag == 0x04 {
            // OCTET STRING found — return its value.
            let value_len = tlv_value_len(p);
            let header_len = tlv.len() - value_len;
            return Some(&p[header_len..header_len + value_len]);
        }
        if tag != 0x30 {
            return None;
        }
        p = tlv_value_bytes(p);
        seens += 1;
    }
    None
}

/// Extract the `certHash` OCTET STRING from an `ESSCertIDv2` value.
///
/// Layout: `SigningCertificateV2 { certs SEQUENCE OF ESSCertIDv2
/// { hashAlgorithm AlgorithmIdentifier, certHash OCTET STRING,
/// issuerSerial IssuerSerial OPTIONAL } }`. The first
/// SEQUENCE wraps `certs`; the second wraps the ESSCertIDv2
/// itself; inside, the AlgorithmIdentifier is a SEQUENCE and
/// the certHash is the following OCTET STRING.
fn extract_ess_cert_hash_v2(set_value: &[u8]) -> Option<&[u8]> {
    // Step into SigningCertificateV2 SEQUENCE.
    let (_, t0) = read_tlv(set_value)?;
    if t0 != 0x30 {
        return None;
    }
    let mut p = tlv_value_bytes(set_value);
    // Step into SEQUENCE OF ESSCertIDv2.
    let (_, t1) = read_tlv(p)?;
    if t1 != 0x30 {
        return None;
    }
    p = tlv_value_bytes(p);
    // Step into ESSCertIDv2 SEQUENCE.
    let (_, t2) = read_tlv(p)?;
    if t2 != 0x30 {
        return None;
    }
    p = tlv_value_bytes(p);
    // Step past AlgorithmIdentifier SEQUENCE.
    let (_, t3) = read_tlv(p)?;
    if t3 != 0x30 {
        return None;
    }
    p = skip_tlv(p);
    // Read the certHash OCTET STRING.
    let (hash_tlv, hash_tag) = read_tlv(p)?;
    if hash_tag != 0x04 {
        return None;
    }
    let hash_value = tlv_value_bytes(p);
    let header_len = hash_tlv.len() - hash_value.len();
    Some(&p[header_len..header_len + hash_value.len()])
}

/// Decode the ASN.1 DER-encoded ECDSA signature
/// (`SEQUENCE { r INTEGER, s INTEGER }`) into a P-384
/// `Signature` (the fixed-size 96-byte r‖s form). The
/// `ecdsa-core` crate (re-exported as `p384::ecdsa`) does not
/// have a `der` feature, so we walk the DER manually.
fn der_to_ecdsa_p384_signature(der: &[u8]) -> Result<p384::ecdsa::Signature, TimestampError> {
    use elliptic_curve::generic_array::GenericArray;
    // SEQUENCE { INTEGER r, INTEGER s }
    let (_, outer_tag) = read_tlv(der)
        .ok_or_else(|| TimestampError::SignatureInvalid("DER sig: missing SEQUENCE".into()))?;
    if outer_tag != 0x30 {
        return Err(TimestampError::SignatureInvalid(format!(
            "DER sig: expected SEQUENCE, got 0x{outer_tag:02x}"
        )));
    }
    let mut p = tlv_value_bytes(der);
    let (r_tlv, r_tag) =
        read_tlv(p).ok_or_else(|| TimestampError::SignatureInvalid("DER sig: missing r".into()))?;
    if r_tag != 0x02 {
        return Err(TimestampError::SignatureInvalid(format!(
            "DER sig: r not INTEGER, got 0x{r_tag:02x}"
        )));
    }
    let r_value_len = tlv_value_len(p);
    let r_hdr = r_tlv.len() - r_value_len;
    let r_bytes = &p[r_hdr..r_hdr + r_value_len];
    p = skip_tlv(p);
    let (s_tlv, s_tag) =
        read_tlv(p).ok_or_else(|| TimestampError::SignatureInvalid("DER sig: missing s".into()))?;
    if s_tag != 0x02 {
        return Err(TimestampError::SignatureInvalid(format!(
            "DER sig: s not INTEGER, got 0x{s_tag:02x}"
        )));
    }
    let s_value_len = tlv_value_len(p);
    let s_hdr = s_tlv.len() - s_value_len;
    let s_bytes = &p[s_hdr..s_hdr + s_value_len];
    // Pad/truncate to 48 bytes (P-384) — INTEGER is
    // big-endian, and may have a leading 0x00 to indicate
    // non-negative (or omit it for smaller values). Strip the
    // leading zero if present, then left-pad with zeros.
    fn normalize(b: &[u8], target: usize) -> Vec<u8> {
        let b = if b.first() == Some(&0x00) && b.len() > 1 {
            &b[1..]
        } else {
            b
        };
        let mut out = vec![0u8; target];
        if b.len() <= target {
            out[target - b.len()..].copy_from_slice(b);
        } else {
            // Truncate left (shouldn't happen for valid signatures).
            out.copy_from_slice(&b[b.len() - target..]);
        }
        out
    }
    let r48 = normalize(r_bytes, 48);
    let s48 = normalize(s_bytes, 48);
    let r_ga = GenericArray::clone_from_slice(&r48);
    let s_ga = GenericArray::clone_from_slice(&s48);
    p384::ecdsa::Signature::from_scalars(r_ga, s_ga)
        .map_err(|e| TimestampError::SignatureInvalid(format!("from_scalars: {e}")))
}

/// Verify the CMS signature using the FreeTSA-specific
/// algorithm: ECDSA over P-384 with SHA-512. FreeTSA's signer
/// cert is the only one supported right now (matches the
/// pinned `freetsa-tsa.crt`).
fn verify_cms_signature_p384_sha512(
    signer_info: &SignerInfo,
    message: &[u8],
    subject_public_key_bytes: &[u8],
) -> Result<(), TimestampError> {
    // 1. Confirm the signature algorithm is ecdsa-with-SHA512.
    if signer_info.signature_algorithm.oid != OID_ECDSA_WITH_SHA512 {
        return Err(TimestampError::SignatureInvalid(format!(
            "expected ecdsa-with-SHA512, got {}",
            signer_info.signature_algorithm.oid
        )));
    }
    // 2. Confirm the public key is on P-384 (97 bytes,
    //    SEC1 uncompressed: 04 || X || Y).
    if subject_public_key_bytes.len() != 97 || subject_public_key_bytes[0] != 0x04 {
        return Err(TimestampError::X509(format!(
            "expected 97-byte SEC1 uncompressed P-384 point, got {} bytes (prefix 0x{:02x})",
            subject_public_key_bytes.len(),
            subject_public_key_bytes.first().copied().unwrap_or(0)
        )));
    }
    let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(subject_public_key_bytes)
        .map_err(|e| TimestampError::X509(format!("p384 VerifyingKey: {e}")))?;
    // 3. SHA-512 the message and verify the signature. The CMS
    //    signature value is the ASN.1 DER-encoded ECDSA signature
    //    (SEQUENCE of two INTEGERs — `r` and `s`). We walk the DER
    //    manually to extract r and s, then build the fixed-size
    //    96-byte P-384 Signature (48 bytes r || 48 bytes s).
    // Use `verify_prehash` (not `verify`) because the digest
    // algorithm is ecdsa-with-SHA512, not P-384's default
    // SHA-384 — `verify` would hash the message with the wrong
    // digest.
    let mut hasher = Sha512::new();
    hasher.update(message);
    let digest = hasher.finalize();
    let sig_bytes: &[u8] = signer_info.signature.as_bytes();
    let sig = der_to_ecdsa_p384_signature(sig_bytes)?;
    verifying_key
        .verify_prehash(digest.as_slice(), &sig)
        .map_err(|e| TimestampError::SignatureInvalid(format!("verify: {e}")))
}

/// Walk the X.509 chain: signer.issuer == root.subject, and the
/// root's public key verifies the signer's `tbsCertificate`
/// signature. Supports both ECDSA-P-384 (FreeTSA's signer) and
/// RSA (FreeTSA's root) as the root's key type. The signer's
/// signature algorithm is taken from the cert itself.
fn verify_chain(signer: &Certificate, trusted_roots: &[Certificate]) -> Result<(), TimestampError> {
    for root in trusted_roots {
        if signer.tbs_certificate.issuer != root.tbs_certificate.subject {
            continue;
        }
        // Encode the tbsCertificate (this is what the root's
        // signature is computed over per RFC 5280 §4.1).
        let tbs_der = signer
            .tbs_certificate
            .to_der()
            .map_err(|e| TimestampError::X509(format!("encode tbsCertificate: {e}")))?;
        let sig_bytes: &[u8] = signer.signature.as_bytes().unwrap_or(&[]);
        let sig_alg_oid = signer.signature_algorithm.oid.to_string();
        // The root may have an RSA or ECDSA key. Pick the
        // verifier based on the root's SubjectPublicKeyInfo.
        let root_spki_oid = root.tbs_certificate.subject_public_key_info.algorithm.oid;
        if root_spki_oid == const_oid::db::rfc5912::RSA_ENCRYPTION
            || root_spki_oid.to_string() == "1.2.840.113549.1.1.1"
        {
            verify_chain_rsa(root, &tbs_der, sig_bytes, &sig_alg_oid)?;
        } else if root_spki_oid == const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
            // P-384 only for the ECDSA case.
            let root_pk_bytes = root
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| TimestampError::X509("root key not BIT STRING".into()))?;
            if root_pk_bytes.len() != 97 || root_pk_bytes[0] != 0x04 {
                return Err(TimestampError::ChainInvalid(format!(
                    "root EC key is not a 97-byte SEC1 uncompressed point: got {} bytes",
                    root_pk_bytes.len()
                )));
            }
            verify_chain_ecdsa_p384(root_pk_bytes, &tbs_der, sig_bytes, &sig_alg_oid)?;
        } else {
            return Err(TimestampError::ChainInvalid(format!(
                "unsupported root public key OID: {}",
                root_spki_oid
            )));
        }
        return Ok(());
    }
    Err(TimestampError::ChainInvalid(format!(
        "no root matches signer.issuer ({})",
        signer.tbs_certificate.issuer
    )))
}

/// RSA chain verification: root is RSA (e.g. rsaEncryption or
/// rsa-pkcs1-sha512); the signature algorithm on the signer's
/// `signatureAlgorithm` field tells us which hash to use.
fn verify_chain_rsa(
    root: &Certificate,
    tbs_der: &[u8],
    sig_bytes: &[u8],
    sig_alg_oid: &str,
) -> Result<(), TimestampError> {
    use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
    use rsa::signature::Verifier as _;
    let pk_der = root
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| TimestampError::X509("root RSA key not BIT STRING".into()))?;
    // FreeTSA's root signs with rsa-pkcs1-sha512; map OID
    // 1.2.840.113549.1.1.13 → Sha512. We rebuild the verifying
    // key for each hash because the `VerifyingKey<D>` is
    // generic over the digest type.
    match sig_alg_oid {
        "1.2.840.113549.1.1.11" => {
            // sha256WithRSAEncryption
            use sha2::Sha256;
            let pk = rsa::RsaPublicKey::from_pkcs1_der(pk_der)
                .map_err(|e| TimestampError::X509(format!("RSA pubkey decode: {e}")))?;
            let vk = RsaVerifyingKey::<Sha256>::new(pk);
            let sig = RsaSignature::try_from(sig_bytes)
                .map_err(|e| TimestampError::ChainInvalid(format!("RSA sig decode: {e}")))?;
            vk.verify(tbs_der, &sig)
                .map_err(|e| TimestampError::ChainInvalid(format!("RSA chain: {e}")))
        }
        "1.2.840.113549.1.1.12" => {
            // sha384WithRSAEncryption
            use sha2::Sha384;
            let pk = rsa::RsaPublicKey::from_pkcs1_der(pk_der)
                .map_err(|e| TimestampError::X509(format!("RSA pubkey decode: {e}")))?;
            let vk = RsaVerifyingKey::<Sha384>::new(pk);
            let sig = RsaSignature::try_from(sig_bytes)
                .map_err(|e| TimestampError::ChainInvalid(format!("RSA sig decode: {e}")))?;
            vk.verify(tbs_der, &sig)
                .map_err(|e| TimestampError::ChainInvalid(format!("RSA chain: {e}")))
        }
        "1.2.840.113549.1.1.13" => {
            // sha512WithRSAEncryption
            use sha2::Sha512;
            let pk = rsa::RsaPublicKey::from_pkcs1_der(pk_der)
                .map_err(|e| TimestampError::X509(format!("RSA pubkey decode: {e}")))?;
            let vk = RsaVerifyingKey::<Sha512>::new(pk);
            let sig = RsaSignature::try_from(sig_bytes)
                .map_err(|e| TimestampError::ChainInvalid(format!("RSA sig decode: {e}")))?;
            vk.verify(tbs_der, &sig)
                .map_err(|e| TimestampError::ChainInvalid(format!("RSA chain: {e}")))
        }
        _ => Err(TimestampError::ChainInvalid(format!(
            "unsupported RSA sig alg: {}",
            sig_alg_oid
        ))),
    }
}

/// ECDSA-P-384 chain verification: the root is P-384 and the
/// signature algorithm on the signer's `signatureAlgorithm` is
/// ecdsa-with-SHA512 (FreeTSA's signer cert).
fn verify_chain_ecdsa_p384(
    root_pk_bytes: &[u8],
    tbs_der: &[u8],
    sig_bytes: &[u8],
    sig_alg_oid: &str,
) -> Result<(), TimestampError> {
    let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(root_pk_bytes)
        .map_err(|e| TimestampError::X509(format!("p384 root: {e}")))?;
    let sig = der_to_ecdsa_p384_signature(sig_bytes)
        .map_err(|e| TimestampError::ChainInvalid(format!("decode root sig: {e}")))?;
    let digest = match sig_alg_oid {
        "1.2.840.10045.4.3.4" => {
            // ecdsa-with-SHA512
            let mut h = Sha512::new();
            h.update(tbs_der);
            h.finalize().to_vec()
        }
        "1.2.840.10045.4.3.3" => {
            // ecdsa-with-SHA384
            use sha2::Sha384;
            let mut h = Sha384::new();
            h.update(tbs_der);
            h.finalize().to_vec()
        }
        "1.2.840.10045.4.3.2" => {
            // ecdsa-with-SHA256
            use sha2::Sha256;
            let mut h = Sha256::new();
            h.update(tbs_der);
            h.finalize().to_vec()
        }
        _ => {
            return Err(TimestampError::ChainInvalid(format!(
                "unsupported ECDSA sig alg: {}",
                sig_alg_oid
            )));
        }
    };
    verifying_key
        .verify_prehash(&digest, &sig)
        .map_err(|e| TimestampError::ChainInvalid(format!("root sig over signer TBS: {e}")))
}

// ---------- TLV helpers (retained for the ESS cert-hash extractor) ----------

fn read_tlv(input: &[u8]) -> Option<(&[u8], u8)> {
    let (&tag, rest) = input.split_first()?;
    let (&len_byte, rest) = rest.split_first()?;
    let (value_len, header_extra): (usize, usize) = if len_byte < 0x80 {
        (len_byte as usize, 0)
    } else if len_byte == 0x81 {
        if rest.is_empty() {
            return None;
        }
        let (&len, rest) = rest.split_first()?;
        if rest.len() < len as usize {
            return None;
        }
        (len as usize, 1)
    } else if len_byte == 0x82 {
        if rest.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        let rest = &rest[2..];
        if rest.len() < len {
            return None;
        }
        (len, 2)
    } else {
        return None;
    };
    let header_len = 2 + header_extra;
    Some((&input[..header_len + value_len], tag))
}

fn skip_tlv(input: &[u8]) -> &[u8] {
    let Some((tlv, _tag)) = read_tlv(input) else {
        return &[];
    };
    &input[tlv.len()..]
}

fn tlv_value_bytes(input: &[u8]) -> &[u8] {
    let Some((tlv, _tag)) = read_tlv(input) else {
        return &[];
    };
    let value_len = tlv_value_len(input);
    let header_len = tlv.len() - value_len;
    &input[header_len..tlv.len()]
}

fn tlv_value_len(input: &[u8]) -> usize {
    if input.len() < 2 {
        return 0;
    }
    let len_byte = input[1];
    if len_byte < 0x80 {
        len_byte as usize
    } else if len_byte == 0x81 {
        if input.len() < 3 {
            return 0;
        }
        input[2] as usize
    } else if len_byte == 0x82 {
        if input.len() < 4 {
            return 0;
        }
        u16::from_be_bytes([input[2], input[3]]) as usize
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_returns_current_time_within_one_second() {
        let tsa = MockTimestampAuthority::new("https://mock.tsa.local");
        let before = chrono::Utc::now().timestamp();
        let resp = tsa.stamp("deadbeef").await.unwrap();
        let after = chrono::Utc::now().timestamp();
        assert!(resp.time >= before);
        assert!(resp.time <= after);
    }

    #[tokio::test]
    async fn mock_accuracy_is_1000_ms() {
        let tsa = MockTimestampAuthority::new("https://mock.tsa.local");
        let resp = tsa.stamp("x").await.unwrap();
        assert_eq!(resp.accuracy_ms, 1000);
    }

    #[test]
    fn mock_verify_returns_true() {
        let tsa = MockTimestampAuthority::new("https://mock.tsa.local");
        let resp = TimestampResponse {
            time: 1_700_000_000,
            accuracy_ms: 1000,
            raw_der: Vec::new(),
        };
        assert!(tsa.verify(&resp, "x"));
    }

    #[test]
    fn mock_url_returns_constructor_arg() {
        let tsa = MockTimestampAuthority::new("https://freetsa.org");
        assert_eq!(tsa.url(), "https://freetsa.org");
    }

    // --- FreeTSAAuthority tests ---

    #[test]
    fn freetsa_url_is_https() {
        let tsa = FreeTSAAuthority::freetsa();
        assert!(tsa.url().starts_with("https://"));
        assert!(tsa.url().contains("freetsa.org"));
    }

    #[tokio::test]
    async fn freetsa_rejects_non_32_byte_hash() {
        let tsa = FreeTSAAuthority::freetsa();
        let resp = tsa.stamp("deadbeef").await;
        assert!(resp.is_err());
        match resp.unwrap_err() {
            TsError::InvalidResponse(_) => {}
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn freetsa_rejects_non_hex_hash() {
        let tsa = FreeTSAAuthority::freetsa();
        let bad = "z".repeat(64);
        let resp = tsa.stamp(&bad).await;
        assert!(resp.is_err());
    }

    #[test]
    fn freetsa_verify_accepts_non_empty_der() {
        let tsa = FreeTSAAuthority::freetsa();
        let resp = TimestampResponse {
            time: 1_700_000_000,
            accuracy_ms: 1000,
            raw_der: vec![0x30, 0x00],
        };
        assert!(tsa.verify(&resp, "x"));
    }
}
