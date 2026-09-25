//! Small persistent records: node identity, the path index, atomic writes and
//! the content-addressed object store.

use crate::paths::Paths;
use jlr_cbor::{Cbor, record};
use jlr_crypto::Digest;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

record! {
    /// Identity of this installation.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct NodeInfo {
        /// Random node identifier.
        1 => node_id: String,
        /// Creation time, seconds since the Unix epoch.
        2 => created_at: u64,
        /// Assurance mode this state directory was created for.
        3 => mode: String,
    }
}

record! {
    /// What was last seen at one path.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct IndexRow {
        /// Absolute path.
        1 => path: String,
        /// EPN identifier last seen there.
        2 => epn: String,
        /// File size.
        3 => size: u64,
        /// Modification time, nanoseconds since the Unix epoch.
        4 => mtime_ns: u64,
        /// Change time, nanoseconds since the Unix epoch.
        5 => ctime_ns: u64,
        /// Inode.
        6 => ino: u64,
        /// Device.
        7 => dev: u64,
        /// When the bytes were last actually hashed, in seconds since the Unix epoch.
        /// Metadata alone is never trusted forever: see the policy's `evidence_max_age_secs`.
        8 => measured_at: u64,
    }
}

record! {
    /// The path index, kept sorted by path.
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct IndexFile {
        /// Rows.
        1 => rows: Vec<IndexRow>,
    }
}

/// Creates a directory tree with owner-only permissions.
pub fn mkdir_private(p: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(p)
}

/// Writes a file atomically. With `durable`, the data and the directory entry
/// are flushed before returning; otherwise the caller must flush the file
/// system (see [`sync_fs`]) before anything that depends on the file.
fn write_atomic_inner(path: &Path, data: &[u8], durable: bool) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    mkdir_private(dir)?;
    let tmp =
        dir.join(format!(".{}.tmp{}", path.file_name().and_then(|n| n.to_str()).unwrap_or("x"), std::process::id()));
    {
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?;
        if durable {
            f.sync_all()?;
        }
    }
    fs::rename(&tmp, path)?;
    if durable {
        fs::File::open(dir).and_then(|d| d.sync_all())?;
    }
    Ok(())
}

/// Writes a file atomically and durably: temp file, fsync, rename, fsync of the directory.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic_inner(path, data, true)
}

/// Flushes the whole file system that holds `dir`.
///
/// Objects are written without individual syncs for speed; this makes them
/// durable in one call, and must run before the ledger events that reference
/// them are made durable.
pub fn sync_fs(dir: &Path) -> std::io::Result<()> {
    let f = fs::File::open(dir)?;
    nix::unistd::syncfs(&f).map_err(std::io::Error::from)
}

/// Stores `data` under its own SHA-256 in `<objects>/<kind>/<aa>/<rest>.cbor`, once.
pub fn put_object(paths: &Paths, kind: &str, data: &[u8]) -> std::io::Result<Digest> {
    let d = Digest::of(data);
    let hex = d.hex();
    let path = paths.objects().join(kind).join(&hex[..2]).join(format!("{}.cbor", &hex[2..]));
    if !path.exists() {
        write_atomic_inner(&path, data, false)?;
    }
    Ok(d)
}

/// Whether an object exists.
pub fn has_object(paths: &Paths, kind: &str, d: &Digest) -> bool {
    let hex = d.hex();
    paths.objects().join(kind).join(&hex[..2]).join(format!("{}.cbor", &hex[2..])).exists()
}

/// Reads an object and checks that it still hashes to its name.
pub fn get_object(paths: &Paths, kind: &str, d: &Digest) -> std::io::Result<Vec<u8>> {
    let hex = d.hex();
    let data = fs::read(paths.objects().join(kind).join(&hex[..2]).join(format!("{}.cbor", &hex[2..])))?;
    if &Digest::of(&data) != d {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "object content does not match its name"));
    }
    Ok(data)
}

/// Loads the path index; a missing or damaged index is only a cache miss.
pub fn load_index(paths: &Paths) -> IndexFile {
    fs::read(paths.index()).ok().and_then(|b| IndexFile::from_cbor(&b).ok()).unwrap_or_default()
}

/// Saves the path index atomically.
pub fn save_index(paths: &Paths, idx: &IndexFile) -> std::io::Result<()> {
    write_atomic(&paths.index(), &idx.to_cbor())
}
