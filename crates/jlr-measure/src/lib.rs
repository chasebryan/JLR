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

/// The observable state of a file: size, both times to the nanosecond, inode and device.
///
/// A stamp is taken before hashing and compared after, and it is what an incremental scan
/// records. `mtime` alone is settable by the file's owner; `ctime` is not, so a change that
/// restores `mtime` still changes the stamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    /// Size in bytes.
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: u64,
    /// Change time, nanoseconds since the Unix epoch.
    pub ctime_ns: u64,
    /// Inode number.
    pub ino: u64,
    /// Device number.
    pub dev: u64,
}

impl Stamp {
    /// The stamp of a file's metadata.
    pub fn of(m: &std::fs::Metadata) -> Stamp {
        let ns = |s: i64, n: i64| (s.max(0) as u64).saturating_mul(1_000_000_000).saturating_add(n.max(0) as u64);
        Stamp {
            size: m.len(),
            mtime_ns: ns(m.mtime(), m.mtime_nsec()),
            ctime_ns: ns(m.ctime(), m.ctime_nsec()),
            ino: m.ino(),
            dev: m.dev(),
        }
    }
}

/// What was measured through a file descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measured {
    /// The state of the file **before** it was hashed. The hash is only reported if the state
    /// was identical afterwards.
    pub stamp: Stamp,
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
    /// MD5 of the same bytes, computed in the same pass as `digest` so that one stamp check covers both. Only
    /// present when the caller asked for it (dpkg's manifests are MD5, and are compared, not trusted).
    pub md5_hex: Option<String>,
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
    measure_inner(file, max_size, &mut || {}, false)
}

/// [`measure_file`] with a hook that runs after the last byte is read and before the file's state is
/// checked again. Tests use it to change the file at the worst possible moment.
#[cfg(test)]
fn measure_file_with(file: &mut File, max_size: u64, after_read: &mut dyn FnMut()) -> Result<Measured, MeasureError> {
    measure_inner(file, max_size, after_read, false)
}

fn measure_inner(
    file: &mut File,
    max_size: u64,
    after_read: &mut dyn FnMut(),
    want_md5: bool,
) -> Result<Measured, MeasureError> {
    let before = file.metadata()?;
    if !before.file_type().is_file() {
        return Err(MeasureError::NotRegular);
    }
    let stamp = Stamp::of(&before);
    if before.len() > max_size {
        return Err(MeasureError::TooLarge(before.len()));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut md5 = want_md5.then(md5::Md5::new);
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
        if let Some(m) = md5.as_mut() {
            m.update(&buf[..n]);
        }
    }
    after_read();
    let after = file.metadata()?;
    // Every observable field must match, including ctime and the inode. Comparing mtime alone
    // lets the file's owner rewrite already-hashed bytes and put the old mtime back.
    if Stamp::of(&after) != stamp || after.len() != total {
        return Err(MeasureError::ChangedWhileReading);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(Measured {
        stamp,
        digest: Digest(hasher.finalize().into()),
        size: total,
        mode: before.mode(),
        uid: before.uid(),
        gid: before.gid(),
        dev: before.dev(),
        ino: before.ino(),
        mtime: before.mtime(),
        head,
        md5_hex: md5.map(|m| m.finalize().iter().map(|b| format!("{b:02x}")).collect()),
    })
}

/// Files up to this size get a second attempt when they change underneath the read. Larger files get one: the retry
/// re-reads everything, and an owner who keeps touching a big file must not be able to multiply the gate's work.
const RETRY_UP_TO: u64 = 16 * 1024 * 1024;

/// Like [`measure_file`], retrying once when a small file changes underneath the read.
///
/// A file that keeps changing is reported as [`MeasureError::ChangedWhileReading`]; the caller
/// must treat that as "not measurable", never as "fine".
pub fn measure_file_stable(file: &mut File, max_size: u64) -> Result<Measured, MeasureError> {
    measure_file_stable_with(file, max_size, false, &mut |_| {})
}

/// [`measure_file_stable`], optionally also computing MD5 in the same pass, with a hook that receives the attempt
/// number after each attempt's last byte is read. Tests use the hook to change the file at the worst moment.
pub(crate) fn measure_file_stable_with(
    file: &mut File,
    max_size: u64,
    want_md5: bool,
    between: &mut dyn FnMut(usize),
) -> Result<Measured, MeasureError> {
    let attempts = if file.metadata().map(|m| m.len()).unwrap_or(u64::MAX) <= RETRY_UP_TO { 2 } else { 1 };
    let mut last = MeasureError::ChangedWhileReading;
    for attempt in 0..attempts {
        match measure_inner(file, max_size, &mut || between(attempt), want_md5) {
            Err(MeasureError::ChangedWhileReading) => last = MeasureError::ChangedWhileReading,
            other => return other,
        }
    }
    Err(last)
}

/// Opens `path` without following a final symlink and measures it.
///
/// The returned [`File`] is the very descriptor that was hashed; execute or
/// map that descriptor, not the path.
pub fn open_measured(path: &Path, max_size: u64) -> Result<(File, Measured), MeasureError> {
    open_measured_with(path, max_size, false)
}

/// [`open_measured`], optionally computing MD5 in the same pass as the SHA-256.
pub(crate) fn open_measured_with(path: &Path, max_size: u64, want_md5: bool) -> Result<(File, Measured), MeasureError> {
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(MeasureError::Symlink),
        Err(e) => return Err(e.into()),
    };
    let m = measure_file_stable_with(&mut file, max_size, want_md5, &mut |_| {})?;
    Ok((file, m))
}

#[cfg(test)]
mod tests;
