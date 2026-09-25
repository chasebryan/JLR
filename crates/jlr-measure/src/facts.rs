//! Facts about where a file lives and who can change it.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Which owners and groups are acceptable writers besides root.
///
/// On systems with user-private groups the user's own group belongs here, or
/// every file in a home directory would look group-writable by strangers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trust {
    /// Uids, besides root, whose ownership is acceptable.
    pub uids: Vec<u32>,
    /// Gids, besides root's, whose group-write bit is acceptable.
    pub gids: Vec<u32>,
}

impl Trust {
    /// Only root is trusted.
    pub fn root_only() -> Self {
        Self::default()
    }

    /// Root plus the identity this process runs as, read from `/proc/self`.
    pub fn current_process() -> Self {
        match fs::metadata("/proc/self") {
            Ok(m) => Trust { uids: vec![m.uid()], gids: vec![m.gid()] },
            Err(_) => Self::root_only(),
        }
    }
}

/// Permission facts relevant to trust.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathFacts {
    /// The file has the setuid bit.
    pub setuid: bool,
    /// The file has the setgid bit.
    pub setgid: bool,
    /// The file, a directory that contains it, or a symlink used to reach it
    /// can be modified by an actor that is not trusted.
    pub writable_by_untrusted: bool,
}

const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
const S_ISVTX: u32 = 0o1000;

fn owner_untrusted(uid: u32, trust: &Trust) -> bool {
    uid != 0 && !trust.uids.contains(&uid)
}

/// Whether an untrusted actor can replace or modify this object.
fn writable(m: &fs::Metadata, trust: &Trust) -> bool {
    if owner_untrusted(m.uid(), trust) {
        return true; // the owner can always chmod or replace it
    }
    let mode = m.mode();
    let group = mode & 0o020 != 0 && m.gid() != 0 && !trust.gids.contains(&m.gid());
    let other = mode & 0o002 != 0;
    // A sticky directory only lets owners remove their own entries, which
    // does not let others replace the trusted file itself.
    (group || other) && !(m.is_dir() && mode & S_ISVTX != 0)
}

/// Computes [`PathFacts`] for `path`.
///
/// The verdict covers everything an attacker could use to change what the
/// path resolves to: the real file, every real ancestor directory, every
/// directory on the lexical route, and every symlink traversed on the way (a
/// symlink's own mode is meaningless, only its owner matters).
pub fn path_facts(path: &Path, trust: &Trust) -> std::io::Result<PathFacts> {
    let abs = std::path::absolute(path)?;
    let real = fs::canonicalize(&abs)?;
    let file = fs::metadata(&real)?;
    let mut facts = PathFacts {
        setuid: file.mode() & S_ISUID != 0,
        setgid: file.mode() & S_ISGID != 0,
        writable_by_untrusted: writable(&file, trust),
    };

    // Real ancestor directories.
    let mut cur = PathBuf::from("/");
    let comps: Vec<_> = real.components().collect();
    for comp in comps.iter().take(comps.len().saturating_sub(1)) {
        if let Component::Normal(c) = comp {
            cur.push(c);
            if let Ok(m) = fs::symlink_metadata(&cur)
                && writable(&m, trust)
            {
                facts.writable_by_untrusted = true;
            }
        }
    }

    // Lexical route, which may pass through symlinks.
    let mut cur = PathBuf::from("/");
    for comp in abs.components() {
        if let Component::Normal(c) = comp {
            cur.push(c);
            if let Ok(m) = fs::symlink_metadata(&cur) {
                let bad =
                    if m.file_type().is_symlink() { owner_untrusted(m.uid(), trust) } else { writable(&m, trust) };
                if bad && cur != real {
                    facts.writable_by_untrusted = true;
                }
            }
        }
    }
    Ok(facts)
}
