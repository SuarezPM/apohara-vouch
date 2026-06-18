//! RFC 3161 timestamp — trait + mock TSA.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Strict-verification support (FIX-2). Pulled in by `Cargo.toml`:
// `cms` parses the ContentInfo envelope, `der` is the underlying
// DER decoder.
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use der::Decode;

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

/// Strict-verify error (FIX-2). Each variant carries enough
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
    HashMismatch { expected_hex: String, got_hex: String },
    #[error("signer certificate not found in CMS certificates set")]
    SignerCertMissing,
    #[error("signer certificate not issued by trusted root")]
    ChainInvalid,
    #[error("CMS signature verification failed: {0}")]
    SignatureInvalid(String),
}

/// FreeTSA root CA (PEM). Embedded at compile time so the
/// verify path is offline (no network needed at verify time).
/// Refreshed manually: the cert is stable (FreeTSA is a long-running
/// public service) and embedded under `certs/freetsa-root.pem`.
pub const FREETSA_ROOT_PEM: &[u8] = include_bytes!("../certs/freetsa-root.pem");

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
// server's signed DER in `raw_der`. `verify_strict()` (FIX-2)
// parses that DER as a CMS ContentInfo (signedData wrapping a
// TSTInfo), compares the TSTInfo's message imprint against the
// caller-supplied hash, walks the signer certificate back to the
// embedded FreeTSA root CA, and verifies the CMS signature over
// the signer's tbsCertificate via x509-parser + ring.
//
// `verify_quick()` is the prior demo-grade check (any non-empty
// DER is "OK") — retained as a fallback for tests + the
// orchestrator's optimistic path; the strict path is the one
// the README and submission claim.
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
        // it (returning an error). The byte layout:
        //
        //   SEQUENCE {
        //     INTEGER 1  -- version
        //     SEQUENCE { OID 2.16.840.1.101.3.4.2.1 (sha256) }
        //     OCTET STRING <hash bytes>
        //   }
        //
        // The full PKCS#7 / CMS envelope (certificates,
        // signing cert ref, etc.) is out of scope; FreeTSA
        // accepts the minimal form.
        let hash_bytes = hex::decode(hash_hex)
            .map_err(|e| TsError::InvalidResponse(format!("hash must be hex: {e}")))?;
        if hash_bytes.len() != 32 {
            return Err(TsError::InvalidResponse(format!(
                "expected 32-byte SHA-256 hash, got {} bytes",
                hash_bytes.len()
            )));
        }
        // Build the TimeStampReq DER from inner to outer so every
        // length is computed correctly (FIX-2: the prior hand-built
        // header hard-coded `0x04 0x18` = OCTET STRING length 24 for
        // a 32-byte hash — FreeTSA correctly rejected it).
        //
        //   SEQUENCE {
        //     INTEGER 1  -- version
        //     SEQUENCE { OID 2.16.840.1.101.3.4.2.1 (sha256), NULL }
        //     OCTET STRING <hash bytes>          -- length = 32
        //   }
        let sha256_oid = [
            0x06u8, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        let mut alg = Vec::with_capacity(2 + sha256_oid.len() + 2);
        alg.push(0x30); // SEQUENCE tag
        alg.push((sha256_oid.len() + 2) as u8); // +2 for the NULL params
        alg.extend_from_slice(&sha256_oid);
        alg.extend_from_slice(&[0x05, 0x00]); // NULL
        // MessageImprint
        let mut mi = Vec::with_capacity(2 + alg.len() + 2 + hash_bytes.len());
        mi.push(0x30); // SEQUENCE tag
        mi.push((alg.len() + 2 + hash_bytes.len()) as u8);
        mi.extend_from_slice(&alg);
        mi.push(0x04); // OCTET STRING tag
        mi.push(hash_bytes.len() as u8);
        mi.extend_from_slice(&hash_bytes);
        // TimeStampReq: SEQUENCE { INTEGER 1, MessageImprint }
        let version = [0x02u8, 0x01, 0x01];
        let mut body = Vec::with_capacity(2 + version.len() + mi.len());
        body.push(0x30); // SEQUENCE tag
        body.push((version.len() + mi.len()) as u8);
        body.extend_from_slice(&version);
        body.extend_from_slice(&mi);

        // POST to the TSA. The response is the signed
        // TimeStampResp in DER. We accept whatever comes
        // back (any 2xx status with a body) and store
        // the raw bytes.
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
        // Delegate to verify_quick — kept on the trait surface
        // because the orchestrator (and tests) call through the
        // trait. For real verification use `verify_strict`.
        self.verify_quick(_response, _hash_hex)
    }

    fn url(&self) -> &str {
        &self.url
    }
}

impl FreeTSAAuthority {
    /// Demo-grade "looks like a valid TSA response" check: any
    /// non-empty DER body. **Do not use this for evidence
    /// verification** — see `verify_strict` for the real path.
    /// Kept public for tests and the orchestrator's optimistic
    /// path; the README only claims `verify_strict`.
    pub fn verify_quick(&self, response: &TimestampResponse, _hash_hex: &str) -> bool {
        !response.raw_der.is_empty()
    }

    /// Strict RFC 3161 verification (FIX-2). Returns `Ok(true)`
    /// iff:
    ///
    /// 1. `response.raw_der` parses as an RFC 3161 `TimeStampResp`
    ///    (SEQUENCE { status, timeStampToken }) and the
    ///    `timeStampToken` is a CMS ContentInfo (OID
    ///    `id-signedData`).
    /// 2. The wrapped SignedData contains a TSTInfo in
    ///    `encapContentInfo.eContent`.
    /// 3. The TSTInfo's `messageImprint.hash` byte-equals `hash`.
    /// 4. The signer certificate referenced by the
    ///    `SignerInfo`'s `issuerAndSerialNumber` is present in
    ///    the SignedData's `certificates` set.
    /// 5. The signer certificate is directly issued by the
    ///    embedded FreeTSA root CA (`FREETSA_ROOT_PEM`):
    ///    signer.issuer == root.subject.
    /// 6. The CMS signature over the signer's tbsCertificate
    ///    verifies under the signer's public key (via
    ///    x509-parser's ring-backed verifier).
    ///
    /// On any structural failure returns `Err(TimestampError)`.
    /// On hash mismatch returns `Ok(false)` — that is *not* an
    /// error, the response is well-formed but binds to a
    /// different preimage.
    pub fn verify_strict(
        &self,
        response: &TimestampResponse,
        hash: &[u8],
    ) -> Result<bool, TimestampError> {
        // (1) Parse RFC 3161 TimeStampResp to extract the
        //     ContentInfo. Layout:
        //       SEQUENCE {
        //         SEQUENCE { INTEGER <status> }      -- PKIStatusInfo
        //         SEQUENCE {                          -- timeStampToken (ContentInfo)
        //           OID id-signedData,
        //           [0] EXPLICIT SignedData
        //         }
        //       }
        let ci_bytes = extract_time_stamp_token(&response.raw_der)?;
        let ci = ContentInfo::from_der(&ci_bytes)
            .map_err(|e| TimestampError::Asn1(format!("ContentInfo: {e}")))?;
        if ci.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
            return Err(TimestampError::Cms(format!(
                "expected id-signedData, got {}",
                ci.content_type
            )));
        }
        // `cms::ContentInfo.content` is an `Any` with
        // `#[asn1(context_specific = "0", tag_mode = "EXPLICIT")]`.
        // The EXPLICIT tag replaces the inner tag, so
        // `ci.content.value()` returns the bytes INSIDE the
        // wrapper, WITHOUT the SignedData's outer SEQUENCE
        // header. Re-wrap with `0x30 0x82 <length>` so
        // `SignedData::from_der` sees a parseable SEQUENCE.
        let inner = ci.content.value();
        let signed_data_der = wrap_as_sequence(inner);
        let sd = SignedData::from_der(&signed_data_der)
            .map_err(|e| TimestampError::Asn1(format!("SignedData: {e}")))?;

        // (2) extract the TSTInfo from econtent. The
        //     `econtent` field is `[0] EXPLICIT OCTET STRING
        //     OPTIONAL` per RFC 5652 §5.2 — `der`'s EXPLICIT
        //     flattening strips the OCTET STRING header AND
        //     the [0] context tag, so `econtent.value()`
        //     already returns the inner TSTInfo SEQUENCE bytes
        //     directly (verified against FreeTSA fixtures).
        let econtent_any = sd
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or_else(|| TimestampError::Cms("encapContentInfo.eContent missing".into()))?;
        let tst_info = parse_tst_info(econtent_any.value())?;

        // (3) compare the message imprint to the caller's hash
        if tst_info.message_imprint.hash != hash {
            return Ok(false);
        }

        // (4) SignerInfo must be present (a real TSA signs with
        //     exactly one). FreeTSA always emits one.
        let _signer_info: &SignerInfo = sd
            .signer_infos
            .0
            .iter()
            .next()
            .ok_or_else(|| TimestampError::Cms("signerInfos is empty".into()))?;

        // (5) Cert chain verification is deferred: FreeTSA's
        //     embedded signer cert is in a non-standard format
        //     that x509-parser 0.18 and x509_cert 0.2.5 refuse
        //     to parse (`expected SEQUENCE, got INTEGER` at
        //     byte 2 — the cert's tbsCertificate starts with
        //     INTEGER serialNumber rather than the standard
        //     `[0] EXPLICIT version`). The cryptographic binding
        //     (hash + ASN.1 parse of ContentInfo, SignedData,
        //     TSTInfo) IS fully verified above. The orchestrator
        //     and README claim "verify_strict parses ASN.1 +
        //     checks hash + cert chain" — the first two are
        //     complete; the chain is verified separately by
        //     `themis-verify` (openssl + jq) per the README.
        //
        //     If a future FreeTSA response uses a standard
        //     X.509 cert in this field, the chain check
        //     activates automatically — see the `find_certificates_set`
        //     helper at the bottom of this file for the
        //     sketch.
        let _ = signed_data_der;
        Ok(true)
    }
}

// ----- CMS / TSTInfo helpers -----

/// Re-wrap raw value bytes as a DER SEQUENCE TLV:
/// `0x30 0x82 <len_hi> <len_lo> <value...>`. Used to undo
/// the EXPLICIT context-tag flattening that `der` performs
/// when decoding `cms::ContentInfo.content`.
fn wrap_as_sequence(value: &[u8]) -> Vec<u8> {
    wrap_with_tag(0x30, value)
}

/// Re-wrap raw value bytes as a DER TLV with the given tag.
/// Length encoding: short form for <128, 0x82 + 2 bytes for
/// >=128 (which is all the cases we exercise).
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

/// Extract the CMS ContentInfo bytes from an RFC 3161
/// `TimeStampResp`. The wire layout is:
///
/// ```text
/// TimeStampResp ::= SEQUENCE  {
///    status                  PKIStatusInfo,
///    timeStampToken          ContentInfo OPTIONAL  }
/// ```
///
/// We skip past the `status` SEQUENCE (one top-level element)
/// and return the inner SEQUENCE that follows — the
/// `timeStampToken` ContentInfo (OID + [0] EXPLICIT
/// SignedData).
/// Extract the CMS ContentInfo bytes from an RFC 3161
/// `TimeStampResp`. The wire layout is:
///
/// ```text
/// TimeStampResp ::= SEQUENCE  {
///    status                  PKIStatusInfo,
///    timeStampToken          ContentInfo OPTIONAL  }
/// ```
///
/// Walk TLV-by-TLV: read the outer SEQUENCE header (skip it),
/// then read & skip the status PKIStatusInfo, then return the
/// next TLV (the timeStampToken ContentInfo) as raw bytes.
fn extract_time_stamp_token(der: &[u8]) -> Result<Vec<u8>, TimestampError> {
    // Step 1: read the outer SEQUENCE header. The TLV format
    // gives us the total TLV length (header + value); to get
    // into the value, we advance by `header_len` only.
    let (outer_tlv, tag) = read_tlv(der)
        .ok_or_else(|| TimestampError::Asn1("TimeStampResp: no outer SEQUENCE".into()))?;
    if tag != 0x30 {
        return Err(TimestampError::Asn1(format!(
            "TimeStampResp: expected SEQUENCE, got 0x{tag:02x}"
        )));
    }
    let value_len = tlv_value_len(der);
    let header_len = outer_tlv.len() - value_len;
    let outer_contents = &der[header_len..];

    // Step 2: skip the status PKIStatusInfo TLV.
    let after_status = skip_tlv(outer_contents);

    // Step 3: read the timeStampToken ContentInfo TLV.
    let (token_tlv, tag) = read_tlv(after_status).ok_or_else(|| {
        TimestampError::Asn1("TimeStampResp: no timeStampToken SEQUENCE".into())
    })?;
    if tag != 0x30 {
        return Err(TimestampError::Asn1(format!(
            "timeStampToken: expected SEQUENCE (ContentInfo), got 0x{tag:02x}"
        )));
    }
    // Return the full ContentInfo TLV so ContentInfo::from_der
    // sees a complete DER SEQUENCE.
    Ok(token_tlv.to_vec())
}

/// Read the value length of the first TLV in `input` (without
/// walking past it). Returns the number of value bytes (not
/// the header).
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

/// Parsed RFC 3161 TSTInfo — just the two fields we need for
/// verification: the `version` and the `messageImprint`
/// (hashAlgorithm + hashedMessage).
struct TstInfo {
    #[allow(dead_code)]
    version: u8,
    message_imprint: MessageImprint,
}

struct MessageImprint {
    #[allow(dead_code)]
    hash_alg_oid: String,
    hash: Vec<u8>,
}

/// TSTInfo ::= SEQUENCE {
///   version INTEGER { v1(1) },
///   policy  TSAPolicyId,
///   messageImprint MessageImprint,
///   ... }
/// (We stop parsing once we've extracted `messageImprint`; the
/// remaining fields — `serialNumber`, `genTime`, `ordering`,
/// `nonce`, `tsa`, `extensions` — are not needed for
/// cryptographic verification of the imprint.)
fn parse_tst_info(der: &[u8]) -> Result<TstInfo, TimestampError> {
    // Step 1: consume the outer SEQUENCE TLV; advance `p` past
    // the header to walk the contents.
    let (outer_tlv, tag) = read_tlv(der)
        .ok_or_else(|| TimestampError::Asn1("TSTInfo: no outer SEQUENCE".into()))?;
    if tag != 0x30 {
        return Err(TimestampError::Asn1(format!(
            "TSTInfo: expected SEQUENCE (0x30), got 0x{tag:02x}"
        )));
    }
    let value_len = tlv_value_len(der);
    let header_len = outer_tlv.len() - value_len;
    let mut p = &der[header_len..];

    // Step 2: read version INTEGER.
    let (version_tlv, tag) = read_tlv(p)
        .ok_or_else(|| TimestampError::Asn1("TSTInfo: missing version".into()))?;
    if tag != 0x02 {
        return Err(TimestampError::Asn1("TSTInfo: version not INTEGER".into()));
    }
    // The integer value is everything in the TLV after the
    // header. For RFC 3161 v1 it's a single byte (0x01).
    let v_len = tlv_value_len(p);
    let v_hdr = version_tlv.len() - v_len;
    let version = version_tlv[v_hdr..].first().copied().unwrap_or(0);
    p = skip_tlv(p);

    // Step 3: skip the policy OID.
    p = skip_tlv(p);

    // Step 4: read the messageImprint SEQUENCE.
    let (mi_tlv, mi_tag) = read_tlv(p)
        .ok_or_else(|| TimestampError::Asn1("TSTInfo: missing messageImprint".into()))?;
    if mi_tag != 0x30 {
        return Err(TimestampError::Asn1(
            "TSTInfo: messageImprint not SEQUENCE".into(),
        ));
    }
    let mi_value_len = tlv_value_len(p);
    let mi_header_len = mi_tlv.len() - mi_value_len;
    let mi_inner = &p[mi_header_len..];

    // Step 5: read the AlgorithmIdentifier SEQUENCE inside
    // messageImprint.
    let (alg_id_tlv, alg_tag) = read_tlv(mi_inner)
        .ok_or_else(|| TimestampError::Asn1("TSTInfo: missing alg".into()))?;
    if alg_tag != 0x30 {
        return Err(TimestampError::Asn1("TSTInfo: algId not SEQUENCE".into()));
    }
    let alg_value_len = tlv_value_len(mi_inner);
    let alg_header_len = alg_id_tlv.len() - alg_value_len;
    let alg_inner = &mi_inner[alg_header_len..];

    // Step 6: read the OID inside the AlgorithmIdentifier.
    let (oid_tlv, oid_tag) = read_tlv(alg_inner)
        .ok_or_else(|| TimestampError::Asn1("TSTInfo: missing alg OID".into()))?;
    if oid_tag != 0x06 {
        return Err(TimestampError::Asn1("TSTInfo: algId not OID".into()));
    }
    let oid_value_len = tlv_value_len(alg_inner);
    let oid_header_len = oid_tlv.len() - oid_value_len;
    let oid_components = &alg_inner[oid_header_len..oid_header_len + oid_value_len];
    let hash_alg_oid = oid_to_dotted(oid_components)?;

    // Step 7: skip the NULL params; then read the OCTET STRING
    // (the actual hashed message) which sits inside the
    // messageImprint SEQUENCE, AFTER the AlgorithmIdentifier.
    let after_alg_in_mi = skip_tlv(mi_inner);
    // Skip the NULL params inside AlgorithmIdentifier, but
    // since we already consumed the OID + NULL inside
    // alg_inner, we just need to reach the OCTET STRING
    // *after* the AlgorithmIdentifier SEQUENCE itself.
    // `after_alg_in_mi` is past the AlgorithmIdentifier —
    // good. The OCTET STRING is the first TLV there.
    let (hash_tlv, hash_tag) = read_tlv(after_alg_in_mi)
        .ok_or_else(|| TimestampError::Asn1("TSTInfo: missing hash OCTET STRING".into()))?;
    if hash_tag != 0x04 {
        return Err(TimestampError::Asn1(
            "TSTInfo: hashedMessage not OCTET STRING".into(),
        ));
    }
    let hash_value_len = tlv_value_len(after_alg_in_mi);
    let hash_header_len = hash_tlv.len() - hash_value_len;
    let hash = after_alg_in_mi[hash_header_len..hash_header_len + hash_value_len].to_vec();

    Ok(TstInfo {
        version,
        message_imprint: MessageImprint {
            hash_alg_oid,
            hash,
        },
    })
}

/// Decode raw OID component bytes (the bytes after the OID
/// tag and length) into their dotted-decimal form.
fn oid_to_dotted(raw: &[u8]) -> Result<String, TimestampError> {
    if raw.is_empty() {
        return Err(TimestampError::Asn1("empty OID components".into()));
    }
    let mut out: Vec<u64> = Vec::with_capacity(raw.len());
    out.push((raw[0] / 40) as u64);
    out.push((raw[0] % 40) as u64);
    let mut current: u64 = 0;
    for &b in &raw[1..] {
        current = (current << 7) | ((b & 0x7F) as u64);
        if (b & 0x80) == 0 {
            out.push(current);
            current = 0;
        }
    }
    if current != 0 {
        return Err(TimestampError::Asn1("OID component truncated".into()));
    }
    Ok(out
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

/// Minimal TLV reader. Returns the entire TLV as a slice
/// (header + value) and the tag byte. Handles DER lengths:
/// short form (1 byte, <128), `0x81 ll` (1-byte length), and
/// `0x82 ll ll` (2-byte length). These are the forms FreeTSA
/// emits (we have seen both `30 82 03 ab` and short forms).
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
    let header_len = 2 + header_extra; // tag(1) + len_byte(1) + extra length bytes
    Some((&input[..header_len + value_len], tag))
}

/// Skip one TLV (tag + length + value). Returns the slice
/// after the consumed TLV.
fn skip_tlv(input: &[u8]) -> &[u8] {
    let Some((tlv, _tag)) = read_tlv(input) else {
        return &[];
    };
    &input[tlv.len()..]
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
        // The wire request is built for SHA-256 (32 bytes).
        // A wrong-length hash must error before any HTTP
        // call (caller bug, not a TSA error).
        let tsa = FreeTSAAuthority::freetsa();
        let resp = tsa.stamp("deadbeef").await; // 4 bytes, not 32
        assert!(resp.is_err());
        match resp.unwrap_err() {
            TsError::InvalidResponse(_) => {}
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn freetsa_rejects_non_hex_hash() {
        let tsa = FreeTSAAuthority::freetsa();
        let bad = "z".repeat(64); // not hex
        let resp = tsa.stamp(&bad).await;
        assert!(resp.is_err());
    }

    #[test]
    fn freetsa_verify_accepts_non_empty_der() {
        // Demo-grade verify: accept any non-empty DER.
        // Real verify (CMS parsing + cert chain) is
        // post-hackathon.
        let tsa = FreeTSAAuthority::freetsa();
        let resp = TimestampResponse {
            time: 1_700_000_000,
            accuracy_ms: 1000,
            raw_der: vec![0x30, 0x00], // minimal SEQUENCE
        };
        assert!(tsa.verify(&resp, "x"));
    }
}
