//! Signed revocation lists.

use jlr_cbor::{Cbor, Error, Value, record};
use jlr_model::EpnRecord;

/// What a revocation entry names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RevocationKind {
    /// An exact EPN identifier.
    Epn = 1,
    /// Any artifact with this content digest (`sha256:<hex>`).
    Digest = 2,
    /// Any artifact whose recorded signer equals this string.
    Signer = 3,
}

impl Cbor for RevocationKind {
    fn to_value(&self) -> Value {
        Value::Uint(*self as u64)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        match v.as_u64()? {
            1 => Ok(Self::Epn),
            2 => Ok(Self::Digest),
            3 => Ok(Self::Signer),
            _ => Err(Error::Invalid("unknown revocation kind")),
        }
    }
}

record! {
    /// One revocation.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RevocationEntry {
        /// What the target string names.
        1 => kind: RevocationKind,
        /// EPN identifier, `sha256:<hex>` digest, or signer identifier.
        2 => target: String,
        /// Why it was revoked.
        3 => reason: String,
    }
}

record! {
    /// A list of revocations with its own epoch.
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct Revocations {
        /// Schema version, currently 1.
        1 => schema: u32,
        /// Monotonic epoch; verifiers refuse to go backwards.
        2 => epoch: u64,
        /// Entries.
        3 => entries: Vec<RevocationEntry>,
    }
}

impl Revocations {
    /// An empty list at epoch 1.
    pub fn empty() -> Self {
        Self { schema: 1, epoch: 1, entries: Vec::new() }
    }

    /// The first matching entry for `record`, if any.
    pub fn hit(&self, record: &EpnRecord) -> Option<&RevocationEntry> {
        let id = record.id().to_string();
        let digest = record.digest.to_string();
        self.entries.iter().find(|e| match e.kind {
            RevocationKind::Epn => e.target == id,
            RevocationKind::Digest => e.target == digest,
            RevocationKind::Signer => record.signer.as_deref() == Some(e.target.as_str()),
        })
    }
}
