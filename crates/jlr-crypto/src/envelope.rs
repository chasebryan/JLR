//! The JLR signed-record envelope: COSE_Sign1 (RFC 9052) with a strict profile.
//!
//! ```text
//! 18([ protected: bstr .cbor { 1: -19, 4: kid, 16: typ },
//!      unprotected: {},
//!      payload: bstr,
//!      signature: bstr ])
//! Sig_structure = ["Signature1", protected, external_aad, payload]
//! external_aad  = "JLR/1/" || record_type || "/" || scope
//! ```
//!
//! Verification never re-serializes: the signature is checked over the
//! protected-header bytes exactly as received, and the whole envelope must
//! also be canonical JLR-DCBOR/1.

use crate::keys::{KeyId, PublicKey, Role, TrustAnchors, verify_signature};
use crate::{Digest, SigningKeypair};
use jlr_cbor::{Error as CborError, Map, Value, decode, encode};
use std::fmt;

/// CBOR tag for COSE_Sign1.
pub const COSE_SIGN1_TAG: u64 = 18;
/// COSE algorithm identifier for fully specified Ed25519 (RFC 9864).
pub const ALG_ED25519: i64 = -19;

const LABEL_ALG: u64 = 1;
const LABEL_KID: u64 = 4;
const LABEL_TYP: u64 = 16;

/// Reasons an envelope is refused.
#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The bytes were not canonical JLR-DCBOR/1.
    Encoding(CborError),
    /// The structure was not a JLR COSE_Sign1.
    Structure(&'static str),
    /// The algorithm was not fully specified Ed25519.
    Algorithm,
    /// The header declared a different record type than the verifier expected.
    RecordType,
    /// The signing key is not among the trust anchors.
    UnknownKey(KeyId),
    /// The key is trusted, but not for the role this record type requires.
    RoleNotAllowed(Role),
    /// The signature does not verify for this scope.
    BadSignature,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvelopeError::Encoding(e) => write!(f, "envelope encoding: {e}"),
            EnvelopeError::Structure(s) => write!(f, "envelope structure: {s}"),
            EnvelopeError::Algorithm => write!(f, "unsupported signature algorithm"),
            EnvelopeError::RecordType => write!(f, "record type does not match"),
            EnvelopeError::UnknownKey(k) => write!(f, "signing key {k} is not trusted"),
            EnvelopeError::RoleNotAllowed(r) => write!(f, "key role {r} may not sign this record type"),
            EnvelopeError::BadSignature => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl From<CborError> for EnvelopeError {
    fn from(e: CborError) -> Self {
        EnvelopeError::Encoding(e)
    }
}

/// A successfully verified envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The canonical payload bytes that were signed.
    pub payload: Vec<u8>,
    /// Identifier of the signing key.
    pub kid: KeyId,
    /// Role of the signing key.
    pub role: Role,
    /// SHA-256 of the payload: the record's content identity.
    pub record_digest: Digest,
    /// SHA-256 of the whole envelope: the ledger leaf and evidence reference.
    pub envelope_digest: Digest,
}

/// Namespace for envelope construction and verification.
#[derive(Debug)]
pub struct Envelope;

fn typ_string(record_type: &str) -> String {
    format!("application/vnd.jlr.{record_type}+cbor;v=1")
}

fn external_aad(record_type: &str, scope: &str) -> Vec<u8> {
    format!("JLR/1/{record_type}/{scope}").into_bytes()
}

fn sig_structure(protected: &[u8], aad: &[u8], payload: &[u8]) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(aad.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]))
}

impl Envelope {
    /// Signs `payload` (already canonical JLR-DCBOR/1) as `record_type` for
    /// `scope`. The scope is usually a node identifier, or `"*"` for records
    /// that are valid on any node.
    pub fn sign(record_type: &str, scope: &str, payload: &[u8], key: &SigningKeypair) -> Vec<u8> {
        let public = key.public();
        let protected = encode(&Value::Map(
            Map::new()
                .with(LABEL_ALG, ALG_ED25519)
                .with(LABEL_KID, public.id().0)
                .with(LABEL_TYP, typ_string(record_type)),
        ));
        let aad = external_aad(record_type, scope);
        let signature = key.sign(&sig_structure(&protected, &aad, payload));
        encode(&Value::Tag(
            COSE_SIGN1_TAG,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(Map::new()),
                Value::Bytes(payload.to_vec()),
                Value::Bytes(signature.to_vec()),
            ])),
        ))
    }

    /// Verifies an envelope against `anchors`.
    ///
    /// `allowed` lists the roles permitted to sign this record type; a valid
    /// signature from any other role is refused.
    pub fn verify(
        bytes: &[u8],
        record_type: &str,
        scope: &str,
        anchors: &TrustAnchors,
        allowed: &[Role],
    ) -> Result<Verified, EnvelopeError> {
        let top = decode(bytes)?;
        let inner = top.as_tag(COSE_SIGN1_TAG).map_err(|_| EnvelopeError::Structure("missing COSE_Sign1 tag"))?;
        let parts = inner.as_array().map_err(|_| EnvelopeError::Structure("not an array"))?;
        if parts.len() != 4 {
            return Err(EnvelopeError::Structure("COSE_Sign1 must have four elements"));
        }
        let protected = parts[0].as_bytes().map_err(|_| EnvelopeError::Structure("protected header"))?;
        match &parts[1] {
            Value::Map(m) if m.is_empty() => {}
            _ => return Err(EnvelopeError::Structure("unprotected header must be empty")),
        }
        let payload = parts[2].as_bytes().map_err(|_| EnvelopeError::Structure("payload"))?;
        let signature =
            parts[3].as_byte_array::<64>().map_err(|_| EnvelopeError::Structure("signature must be 64 bytes"))?;

        let header = decode(protected)?;
        let mut fields = jlr_cbor::Fields::new(&header).map_err(|_| EnvelopeError::Structure("protected map"))?;
        let alg = fields.req(LABEL_ALG).and_then(Value::as_i64).map_err(|_| EnvelopeError::Structure("alg"))?;
        let kid =
            fields.req(LABEL_KID).and_then(Value::as_byte_array::<32>).map_err(|_| EnvelopeError::Structure("kid"))?;
        let typ = fields
            .req(LABEL_TYP)
            .and_then(|v| v.as_text().map(str::to_owned))
            .map_err(|_| EnvelopeError::Structure("typ"))?;
        fields.finish().map_err(|_| EnvelopeError::Structure("unknown protected header label"))?;

        if alg != ALG_ED25519 {
            return Err(EnvelopeError::Algorithm);
        }
        if typ != typ_string(record_type) {
            return Err(EnvelopeError::RecordType);
        }
        let kid = KeyId(kid);
        let key: &PublicKey = anchors.get(&kid).ok_or(EnvelopeError::UnknownKey(kid))?;
        if !allowed.contains(&key.role) {
            return Err(EnvelopeError::RoleNotAllowed(key.role));
        }
        let aad = external_aad(record_type, scope);
        verify_signature(key, &sig_structure(protected, &aad, payload), &signature)
            .map_err(|_| EnvelopeError::BadSignature)?;

        Ok(Verified {
            payload: payload.to_vec(),
            kid,
            role: key.role,
            record_digest: Digest::of(payload),
            envelope_digest: Digest::of(bytes),
        })
    }

    /// Extracts the payload of a well-formed envelope **without verifying its signature**.
    ///
    /// Only for callers that already hold independent proof that these exact
    /// bytes are authentic, such as a Merkle root over them that a trusted key
    /// has signed. Everything else must use [`Envelope::verify`].
    pub fn unverified_payload(bytes: &[u8]) -> Option<Vec<u8>> {
        let top = decode(bytes).ok()?;
        let parts = top.as_tag(COSE_SIGN1_TAG).ok()?.as_array().ok()?;
        if parts.len() != 4 {
            return None;
        }
        Some(parts[2].as_bytes().ok()?.to_vec())
    }

    /// Reads the signing key identifier without verifying anything.
    ///
    /// The result is untrusted routing information only, for choosing which
    /// anchors to try.
    pub fn peek_kid(bytes: &[u8]) -> Option<KeyId> {
        let top = decode(bytes).ok()?;
        let parts = top.as_tag(COSE_SIGN1_TAG).ok()?.as_array().ok()?;
        let header = decode(parts.first()?.as_bytes().ok()?).ok()?;
        let kid = header.as_map().ok()?.get_uint(LABEL_KID)?.as_byte_array::<32>().ok()?;
        Some(KeyId(kid))
    }
}
