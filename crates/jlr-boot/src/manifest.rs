//! Release manifests.

use jlr_cbor::{Cbor, record};
use jlr_crypto::{Digest, Envelope, EnvelopeError, Role, TrustAnchors};
use jlr_model::record_type;
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::io::{Read, Write};

record! {
    /// A named piece of a release with its digest.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Component {
        /// Component name, for example `jlr`.
        1 => name: String,
        /// SHA-256 of its bytes.
        2 => digest: Digest,
    }
}

record! {
    /// What a release signer vouches for.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ReleaseManifest {
        /// Schema version, currently 1.
        1 => schema: u32,
        /// Release name.
        2 => name: String,
        /// Human-readable version.
        3 => version: String,
        /// Monotonic release counter used for rollback protection.
        4 => epoch: u64,
        /// SHA-256 of the base image file.
        5 => image_digest: Digest,
        /// Exact size of the base image in bytes.
        6 => image_size: u64,
        /// Once this release boots successfully, no release with a lower epoch may boot.
        7 => min_epoch: u64,
        /// Digest of the default policy bundle shipped in the image.
        8 => policy_digest: Option<Digest>,
        /// Digests of notable components inside the image.
        9 => components: Vec<Component>,
    }
}

impl ReleaseManifest {
    /// Current schema version.
    pub const SCHEMA: u32 = 1;

    /// Signs the manifest as a release record.
    pub fn sign(&self, key: &jlr_crypto::SigningKeypair) -> Vec<u8> {
        Envelope::sign(record_type::RELEASE, "*", &self.to_cbor(), key)
    }
}

/// Why a boot step was refused.
#[derive(Debug)]
pub enum BootError {
    /// The manifest signature or signer was not acceptable.
    Signature(EnvelopeError),
    /// The manifest payload was malformed or unsupported.
    Manifest(String),
    /// The release is older than the rollback floor.
    Rollback {
        /// Epoch of the release.
        epoch: u64,
        /// Current floor.
        floor: u64,
    },
    /// The image does not match the digest the manifest commits to.
    ImageDigest {
        /// Digest in the manifest.
        expected: Digest,
        /// Digest of the bytes read.
        actual: Digest,
    },
    /// The image size differs from the manifest.
    ImageSize {
        /// Size in the manifest.
        expected: u64,
        /// Bytes read.
        actual: u64,
    },
    /// No slot can be booted.
    NoBootableSlot,
    /// Boot media or state could not be read or written.
    Io(String),
}

impl fmt::Display for BootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootError::Signature(e) => write!(f, "manifest signature refused: {e}"),
            BootError::Manifest(m) => write!(f, "manifest invalid: {m}"),
            BootError::Rollback { epoch, floor } => {
                write!(f, "release epoch {epoch} is below the rollback floor {floor}")
            }
            BootError::ImageDigest { expected, actual } => {
                write!(f, "image digest mismatch: manifest {expected}, image {actual}")
            }
            BootError::ImageSize { expected, actual } => {
                write!(f, "image size mismatch: manifest {expected}, image {actual}")
            }
            BootError::NoBootableSlot => write!(f, "no slot can be booted"),
            BootError::Io(m) => write!(f, "boot media: {m}"),
        }
    }
}
impl std::error::Error for BootError {}

/// Verifies a signed manifest against the trust anchors.
///
/// Only a key enrolled with the [`Role::Release`] role may sign releases; a
/// valid signature from any other role is refused. The floor is checked here
/// so that a refused rollback never reaches the image.
pub fn verify_manifest(bytes: &[u8], anchors: &TrustAnchors, floor: u64) -> Result<ReleaseManifest, BootError> {
    let v =
        Envelope::verify(bytes, record_type::RELEASE, "*", anchors, &[Role::Release]).map_err(BootError::Signature)?;
    let m = ReleaseManifest::from_cbor(&v.payload).map_err(|e| BootError::Manifest(e.to_string()))?;
    if m.schema != ReleaseManifest::SCHEMA {
        return Err(BootError::Manifest(format!("unsupported schema {}", m.schema)));
    }
    if m.epoch < floor {
        return Err(BootError::Rollback { epoch: m.epoch, floor });
    }
    if m.min_epoch > m.epoch {
        return Err(BootError::Manifest("min_epoch exceeds epoch".into()));
    }
    Ok(m)
}

/// Copies an image from `source` into `sink` (RAM), hashing while copying, and
/// checks size and digest against the manifest.
///
/// The copy is what gets mounted, so there is no window between verification
/// and use in which the media could change the bytes. On mismatch the caller
/// must discard the sink.
pub fn verify_image(m: &ReleaseManifest, source: &mut impl Read, sink: &mut impl Write) -> Result<u64, BootError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = source.read(&mut buf).map_err(|e| BootError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        // Refuse to buffer more than the manifest promised.
        if total > m.image_size {
            return Err(BootError::ImageSize { expected: m.image_size, actual: total });
        }
        hasher.update(&buf[..n]);
        sink.write_all(&buf[..n]).map_err(|e| BootError::Io(e.to_string()))?;
    }
    if total != m.image_size {
        return Err(BootError::ImageSize { expected: m.image_size, actual: total });
    }
    let actual = Digest(hasher.finalize().into());
    if actual != m.image_digest {
        return Err(BootError::ImageDigest { expected: m.image_digest, actual });
    }
    Ok(total)
}
