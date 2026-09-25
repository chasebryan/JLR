//! A sealed in-memory copy of an executable.

use crate::sys;
use jlr_crypto::Digest;
use nix::fcntl::{FcntlArg, SealFlag, fcntl};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

/// Why sealing failed.
#[derive(Debug)]
pub enum SealError {
    /// The bytes read do not hash to the digest that was authorised.
    DigestMismatch {
        /// Digest the caller expected.
        expected: Digest,
        /// Digest of the bytes actually read.
        actual: Digest,
    },
    /// The file exceeds the size limit.
    TooLarge(u64),
    /// I/O or system-call failure.
    Io(std::io::Error),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::DigestMismatch { expected, actual } => {
                write!(f, "content changed since it was measured: expected {expected}, read {actual}")
            }
            SealError::TooLarge(n) => write!(f, "executable of {n} bytes is too large to seal"),
            SealError::Io(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for SealError {}
impl From<std::io::Error> for SealError {
    fn from(e: std::io::Error) -> Self {
        SealError::Io(e)
    }
}
impl From<nix::Error> for SealError {
    fn from(e: nix::Error) -> Self {
        SealError::Io(e.into())
    }
}

/// An immutable in-memory executable whose content is known to match a digest.
///
/// Once sealed, the kernel refuses every write, resize and further sealing of
/// the memfd. What is executed is exactly what was hashed, no matter what
/// happens to the original file afterwards.
#[derive(Debug)]
pub struct SealedExe {
    file: File,
    digest: Digest,
    size: u64,
}

impl SealedExe {
    /// Copies `source` into a memfd, hashing while copying, and seals it.
    ///
    /// Fails with [`SealError::DigestMismatch`] when the bytes read do not hash
    /// to `expected`, so a file modified between measurement and launch is
    /// never executed.
    pub fn seal(source: &mut File, expected: &Digest, max_size: u64) -> Result<SealedExe, SealError> {
        source.seek(SeekFrom::Start(0))?;
        let mut mem = sys::memfd_exec("jlr-exe")?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = source.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > max_size {
                return Err(SealError::TooLarge(total));
            }
            hasher.update(&buf[..n]);
            mem.write_all(&buf[..n])?;
        }
        let actual = Digest(hasher.finalize().into());
        if &actual != expected {
            return Err(SealError::DigestMismatch { expected: *expected, actual });
        }
        fcntl(
            &mem,
            FcntlArg::F_ADD_SEALS(
                SealFlag::F_SEAL_SEAL | SealFlag::F_SEAL_SHRINK | SealFlag::F_SEAL_GROW | SealFlag::F_SEAL_WRITE,
            ),
        )?;
        mem.seek(SeekFrom::Start(0))?;
        Ok(SealedExe { file: mem, digest: actual, size: total })
    }

    /// Digest of the sealed bytes.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The sealed descriptor.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Whether the kernel reports all four seals on the descriptor.
    pub fn is_fully_sealed(&self) -> bool {
        match fcntl(&self.file, FcntlArg::F_GET_SEALS) {
            Ok(bits) => {
                let want =
                    (SealFlag::F_SEAL_SEAL | SealFlag::F_SEAL_SHRINK | SealFlag::F_SEAL_GROW | SealFlag::F_SEAL_WRITE)
                        .bits();
                bits & want == want
            }
            Err(_) => false,
        }
    }
}
