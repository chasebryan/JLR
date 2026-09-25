//! Measurement of files and their surroundings.
//!
//! The central rule is **measure the descriptor you will use**. A path can be
//! swapped between hashing and execution, so [`open_measured`] opens the file
//! once, hashes it through that descriptor, and hands the descriptor back; the
//! launcher then executes that same descriptor. Symlinks are never followed
//! implicitly (`O_NOFOLLOW`).

#![forbid(unsafe_code)]

mod classify;
mod dpkg;
mod facts;
mod observe;
mod walk;

pub use classify::{classify, is_governed};
pub use dpkg::{DpkgDb, DpkgOwnership};
pub use facts::{PathFacts, Trust, path_facts};
pub use observe::{Observation, ObserveOptions, observe, observe_open};
pub use walk::{WalkOptions, walk};

use jlr_crypto::Digest;
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// What was measured through a file descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measured {
    /// SHA-256 of the full content.
    pub digest: Digest,
    /// Size in bytes.
    pub size: u64,
    /// Full `st_mode`, including type and permission bits.
    pub mode: u32,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Device number.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// Modification time in seconds since the Unix epoch.
    pub mtime: i64,
    /// The first bytes of the file, for classification.
    pub head: Vec<u8>,
}

/// Errors from measurement.
#[derive(Debug)]
pub enum MeasureError {
    /// The path is a symbolic link.
    Symlink,
    /// The object is not a regular file.
    NotRegular,
    /// The file exceeds the configured size limit.
    TooLarge(u64),
    /// The file changed while it was being read.
    ChangedWhileReading,
    /// An I/O error.
    Io(io::Error),
}

impl std::fmt::Display for MeasureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeasureError::Symlink => write!(f, "path is a symbolic link"),
            MeasureError::NotRegular => write!(f, "not a regular file"),
            MeasureError::TooLarge(n) => write!(f, "file of {n} bytes exceeds the size limit"),
            MeasureError::ChangedWhileReading => write!(f, "file changed while it was being measured"),
            MeasureError::Io(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for MeasureError {}
impl From<io::Error> for MeasureError {
    fn from(e: io::Error) -> Self {
        MeasureError::Io(e)
    }
}

/// Number of leading bytes kept for classification.
pub const HEAD_LEN: usize = 64;

/// Hashes an open file from its start and rewinds it.
///
/// The file is measured twice in the sense that its metadata is compared
/// before and after reading; a size or mtime change is reported rather than
/// producing a digest of a moving target.
pub fn measure_file(file: &mut File, max_size: u64) -> Result<Measured, MeasureError> {
    let before = file.metadata()?;
    if !before.file_type().is_file() {
        return Err(MeasureError::NotRegular);
    }
    if before.len() > max_size {
        return Err(MeasureError::TooLarge(before.len()));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut head = Vec::with_capacity(HEAD_LEN);
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if head.len() < HEAD_LEN {
            let take = (HEAD_LEN - head.len()).min(n);
            head.extend_from_slice(&buf[..take]);
        }
        total += n as u64;
        if total > max_size {
            return Err(MeasureError::TooLarge(total));
        }
        hasher.update(&buf[..n]);
    }
    let after = file.metadata()?;
    if after.len() != total || after.mtime() != before.mtime() || after.mtime_nsec() != before.mtime_nsec() {
        return Err(MeasureError::ChangedWhileReading);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(Measured {
        digest: Digest(hasher.finalize().into()),
        size: total,
        mode: before.mode(),
        uid: before.uid(),
        gid: before.gid(),
        dev: before.dev(),
        ino: before.ino(),
        mtime: before.mtime(),
        head,
    })
}

/// Opens `path` without following a final symlink and measures it.
///
/// The returned [`File`] is the very descriptor that was hashed; execute or
/// map that descriptor, not the path.
pub fn open_measured(path: &Path, max_size: u64) -> Result<(File, Measured), MeasureError> {
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(MeasureError::Symlink),
        Err(e) => return Err(e.into()),
    };
    let m = measure_file(&mut file, max_size)?;
    Ok((file, m))
}

#[cfg(test)]
mod tests;
