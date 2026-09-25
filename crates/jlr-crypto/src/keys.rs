//! Key roles, key files and the set of trusted verification keys.

use crate::{Digest, random_bytes};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use jlr_cbor::{Cbor, Error as CborError, Map, Value, decode, encode};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Write as _;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The authority a key holds. No single runtime process should hold more
/// than one of these private keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Role {
    /// Offline, long-lived; authorizes release, policy and recovery keys.
    Root = 1,
    /// Signs JLR releases and manifests.
    Release = 2,
    /// Signs administrative policy bundles and profile bundles.
    Policy = 3,
    /// Authorizes recovery artifacts and recovery writes.
    Recovery = 4,
    /// Per-machine identity; signs ledger checkpoints and local admissions.
    Device = 5,
}

impl Role {
    /// Stable lowercase name.
    pub fn name(self) -> &'static str {
        match self {
            Role::Root => "root",
            Role::Release => "release",
            Role::Policy => "policy",
            Role::Recovery => "recovery",
            Role::Device => "device",
        }
    }

    /// Parses [`Role::name`].
    pub fn parse(s: &str) -> Option<Role> {
        Some(match s {
            "root" => Role::Root,
            "release" => Role::Release,
            "policy" => Role::Policy,
            "recovery" => Role::Recovery,
            "device" => Role::Device,
            _ => return None,
        })
    }

    fn from_u64(n: u64) -> Option<Role> {
        Some(match n {
            1 => Role::Root,
            2 => Role::Release,
            3 => Role::Policy,
            4 => Role::Recovery,
            5 => Role::Device,
            _ => return None,
        })
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Errors from key handling.
#[derive(Debug)]
pub enum KeyError {
    /// The random number generator failed.
    Random,
    /// Key material was malformed.
    Malformed(&'static str),
    /// The public key is a low-order point or otherwise weak.
    WeakKey,
    /// I/O failure reading or writing a key file.
    Io(std::io::Error),
    /// CBOR failure while reading a key file.
    Cbor(CborError),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Random => write!(f, "operating-system RNG failed"),
            KeyError::Malformed(m) => write!(f, "malformed key: {m}"),
            KeyError::WeakKey => write!(f, "weak public key rejected"),
            KeyError::Io(e) => write!(f, "key file I/O: {e}"),
            KeyError::Cbor(e) => write!(f, "key file encoding: {e}"),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<std::io::Error> for KeyError {
    fn from(e: std::io::Error) -> Self {
        KeyError::Io(e)
    }
}
impl From<CborError> for KeyError {
    fn from(e: CborError) -> Self {
        KeyError::Cbor(e)
    }
}

/// Identifier of a public key: SHA-256 of its 32 raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(pub [u8; 32]);

impl KeyId {
    /// Short form for human display.
    pub fn short(&self) -> String {
        Digest(self.0).hex()[..16].to_owned()
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kid:{}", Digest(self.0).hex())
    }
}
impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kid:{}", self.short())
    }
}

/// A public verification key together with the role it may exercise.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
    bytes: [u8; 32],
    /// Authority this key is enrolled for.
    pub role: Role,
}

impl PublicKey {
    /// Builds a key from raw bytes, rejecting invalid and weak points.
    pub fn from_bytes(bytes: [u8; 32], role: Role) -> Result<Self, KeyError> {
        let vk = VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::Malformed("not a curve point"))?;
        if vk.is_weak() {
            return Err(KeyError::WeakKey);
        }
        Ok(PublicKey { bytes, role })
    }

    /// Raw 32-byte compressed Edwards point.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Identifier derived from the key bytes.
    pub fn id(&self) -> KeyId {
        KeyId(Digest::of(&self.bytes).0)
    }

    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey, KeyError> {
        VerifyingKey::from_bytes(&self.bytes).map_err(|_| KeyError::Malformed("not a curve point"))
    }
}

impl Cbor for PublicKey {
    fn to_value(&self) -> Value {
        Value::Map(Map::new().with(1u8, self.role as u8).with(2u8, self.bytes))
    }

    fn from_value(v: &Value) -> Result<Self, CborError> {
        let mut f = jlr_cbor::Fields::new(v)?;
        let role = Role::from_u64(f.req(1)?.as_u64()?).ok_or(CborError::Invalid("unknown role"))?;
        let bytes = f.req(2)?.as_byte_array::<32>()?;
        f.finish()?;
        PublicKey::from_bytes(bytes, role).map_err(|_| CborError::Invalid("invalid public key"))
    }
}

/// A private key with its role. The seed is wiped on drop.
#[derive(ZeroizeOnDrop)]
pub struct SigningKeypair {
    seed: [u8; 32],
    #[zeroize(skip)]
    role: Role,
}

impl fmt::Debug for SigningKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKeypair({} {})", self.role, self.public().id())
    }
}

impl SigningKeypair {
    /// Generates a fresh key from the operating-system RNG.
    pub fn generate(role: Role) -> Result<Self, KeyError> {
        let seed = random_bytes::<32>().map_err(|_| KeyError::Random)?;
        Ok(Self { seed, role })
    }

    /// Builds a key from a fixed seed. Intended for test vectors only.
    pub fn from_seed(seed: [u8; 32], role: Role) -> Self {
        Self { seed, role }
    }

    /// Role this key holds.
    pub fn role(&self) -> Role {
        self.role
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    /// The matching public key.
    pub fn public(&self) -> PublicKey {
        PublicKey { bytes: self.signing_key().verifying_key().to_bytes(), role: self.role }
    }

    /// Signs `message` with Ed25519 (RFC 8032, pure mode).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key().sign(message).to_bytes()
    }

    /// Writes the key to `path` with owner-only permissions.
    ///
    /// The file is created exclusively and will not overwrite an existing key.
    pub fn save(&self, path: &Path) -> Result<(), KeyError> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut record = Value::Map(Map::new().with(0u8, 1u8).with(1u8, self.role as u8).with(2u8, self.seed));
        let mut bytes = encode(&record);
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        bytes.zeroize();
        if let Value::Map(_) = &mut record {
            record = Value::Null;
        }
        drop(record);
        Ok(())
    }

    /// Loads a key written by [`SigningKeypair::save`], refusing files that
    /// other users can read.
    pub fn load(path: &Path) -> Result<Self, KeyError> {
        use std::os::unix::fs::PermissionsExt as _;
        let meta = std::fs::metadata(path)?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(KeyError::Malformed("key file is accessible by group or others"));
        }
        let mut bytes = std::fs::read(path)?;
        let parsed = decode(&bytes);
        bytes.zeroize();
        let v = parsed?;
        let mut f = jlr_cbor::Fields::new(&v)?;
        if f.req(0)?.as_u64()? != 1 {
            return Err(KeyError::Malformed("unsupported key file version"));
        }
        let role = Role::from_u64(f.req(1)?.as_u64()?).ok_or(KeyError::Malformed("unknown role"))?;
        let seed = f.req(2)?.as_byte_array::<32>()?;
        f.finish()?;
        Ok(Self { seed, role })
    }
}

/// The set of verification keys a verifier is willing to accept.
#[derive(Clone, Default, Debug)]
pub struct TrustAnchors {
    keys: BTreeMap<KeyId, PublicKey>,
}

impl TrustAnchors {
    /// An empty set that trusts nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key.
    pub fn insert(&mut self, key: PublicKey) {
        self.keys.insert(key.id(), key);
    }

    /// Removes a key, for example after revocation.
    pub fn remove(&mut self, id: &KeyId) -> Option<PublicKey> {
        self.keys.remove(id)
    }

    /// Looks up a key by identifier.
    pub fn get(&self, id: &KeyId) -> Option<&PublicKey> {
        self.keys.get(id)
    }

    /// Number of trusted keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Iterates over keys in identifier order.
    pub fn iter(&self) -> impl Iterator<Item = &PublicKey> {
        self.keys.values()
    }
}

impl Cbor for TrustAnchors {
    fn to_value(&self) -> Value {
        Value::Array(self.keys.values().map(Cbor::to_value).collect())
    }

    fn from_value(v: &Value) -> Result<Self, CborError> {
        let mut anchors = TrustAnchors::new();
        for item in v.as_array()? {
            let k = PublicKey::from_value(item)?;
            if anchors.keys.contains_key(&k.id()) {
                return Err(CborError::Invalid("duplicate trust anchor"));
            }
            anchors.insert(k);
        }
        Ok(anchors)
    }
}

pub(crate) fn verify_signature(key: &PublicKey, message: &[u8], signature: &[u8; 64]) -> Result<(), KeyError> {
    let vk = key.verifying_key()?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(message, &sig).map_err(|_| KeyError::Malformed("signature invalid"))
}
