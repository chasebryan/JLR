//! Cryptographic building blocks for JLR.
//!
//! * [`Digest`]: SHA-256 with an explicit algorithm label everywhere it is
//!   serialized (bare digests are never written).
//! * [`Role`], [`SigningKeypair`], [`PublicKey`]: Ed25519 keys tagged with the
//!   authority they hold. Verification is always the strict variant.
//! * [`Envelope`]: a COSE_Sign1 (RFC 9052) structure whose signed context
//!   binds the algorithm, the key identifier, the record type and the node
//!   scope, so a signature can never be replayed as another record type, on
//!   another node, or under another protocol version.

#![forbid(unsafe_code)]

mod envelope;
mod keys;

pub use envelope::{ALG_ED25519, COSE_SIGN1_TAG, Envelope, EnvelopeError, Verified};
pub use keys::{KeyError, KeyId, PublicKey, Role, SigningKeypair, TrustAnchors};

use jlr_cbor::{Cbor, Error as CborError, Value};
use sha2::{Digest as _, Sha256};
use std::fmt;

/// Wire label for SHA-256 (COSE algorithm identifier -16).
pub const ALG_SHA256: i64 = -16;

/// A labelled SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// Hashes `data`.
    pub fn of(data: &[u8]) -> Self {
        Digest(Sha256::digest(data).into())
    }

    /// Hashes the concatenation of several parts with a domain-separation
    /// context, framing each part with its length so parts cannot be shifted
    /// into one another.
    pub fn of_parts(context: &str, parts: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        h.update((context.len() as u64).to_be_bytes());
        h.update(context.as_bytes());
        for p in parts {
            h.update((p.len() as u64).to_be_bytes());
            h.update(p);
        }
        Digest(h.finalize().into())
    }

    /// Lowercase hexadecimal form of the digest bytes.
    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            s.push(char::from_digit(u32::from(b & 15), 16).unwrap_or('0'));
        }
        s
    }

    /// Parses 64 hexadecimal characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 || !s.is_ascii() {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16)?;
            let lo = (chunk[1] as char).to_digit(16)?;
            out[i] = ((hi << 4) | lo) as u8;
        }
        Some(Digest(out))
    }

    /// The all-zero digest, used only as the "previous" link of a first entry.
    pub const ZERO: Digest = Digest([0u8; 32]);
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.hex())
    }
}

/// Serialized as the two-element array `[alg, bytes]` so no digest is ever
/// written without its algorithm.
impl Cbor for Digest {
    fn to_value(&self) -> Value {
        Value::Array(vec![Value::from(ALG_SHA256), Value::Bytes(self.0.to_vec())])
    }

    fn from_value(v: &Value) -> Result<Self, CborError> {
        let a = v.as_array()?;
        if a.len() != 2 {
            return Err(CborError::Invalid("digest must be [alg, bytes]"));
        }
        if a[0].as_i64()? != ALG_SHA256 {
            return Err(CborError::Invalid("unsupported digest algorithm"));
        }
        Ok(Digest(a[1].as_byte_array::<32>()?))
    }
}

/// Fills `buf` from the operating-system random number generator.
///
/// Failure to obtain randomness is fatal for key generation and record
/// identifiers, so callers propagate it instead of falling back.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b)?;
    Ok(b)
}

/// Constant-time equality for secret-adjacent comparisons.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests;
