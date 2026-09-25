//! Directory traversal that never follows symlinks.

use crate::{classify, is_governed};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Traversal options.
#[derive(Clone, Debug)]
pub struct WalkOptions {
    /// Stay on the device of the starting directory.
    pub one_file_system: bool,
    /// Skip these absolute directory prefixes.
    pub exclude: Vec<PathBuf>,
    /// Maximum directory depth.
    pub max_depth: usize,
    /// Return only files whose class is governed by default.
    pub governed_only: bool,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            one_file_system: true,
            exclude: ["/proc", "/sys", "/dev", "/run", "/tmp/.X11-unix"].iter().map(PathBuf::from).collect(),
            max_depth: 64,
            governed_only: true,
        }
    }
}

/// Walks `root` and returns regular files, in sorted order for determinism.
///
/// Symlinks are skipped: a link is not an artifact, and following it would
/// let a writable directory redirect the walk anywhere.
pub fn walk(root: &Path, opts: &WalkOptions) -> std::io::Result<Vec<PathBuf>> {
    let dev = fs::symlink_metadata(root)?.dev();
    let mut out = Vec::new();
    let mut stack = vec![(root.to_owned(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if opts.exclude.iter().any(|e| dir.starts_with(e)) {
            continue;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let path = e.path();
            let Ok(meta) = fs::symlink_metadata(&path) else { continue };
            let ft = meta.file_type();
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                if depth < opts.max_depth && (!opts.one_file_system || meta.dev() == dev) {
                    stack.push((path, depth + 1));
                }
            } else if ft.is_file() {
                if opts.governed_only {
                    let mut head = [0u8; crate::HEAD_LEN];
                    // lstat said "regular file", but the entry may have been swapped since: never follow a
                    // symlink and never block on a FIFO or device.
                    let n = fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                        .open(&path)
                        .and_then(|mut f| f.read(&mut head))
                        .unwrap_or(0);
                    if !is_governed(classify(&head[..n], &path, meta.mode())) {
                        continue;
                    }
                }
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}
