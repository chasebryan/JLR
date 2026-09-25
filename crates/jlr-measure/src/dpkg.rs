//! Debian package database adapter.
//!
//! The database lives on the host disk, so everything learned here is
//! *unauthenticated package-manager metadata*: it is evidence that a file
//! matches what the local package manager believes it installed, and nothing
//! more. Host root can rewrite it. A verified package signature is a separate
//! and stronger piece of evidence that this adapter does not claim.

use md5::{Digest as _, Md5};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// What the package database says about one path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DpkgOwnership {
    /// Package name (architecture-qualified for multi-arch packages).
    pub package: String,
    /// Installed version.
    pub version: String,
    /// Whether the package's `md5sums` lists this file.
    pub manifest_md5: Option<String>,
}

/// An in-memory index of installed packages and their files.
#[derive(Debug, Default)]
pub struct DpkgDb {
    root: PathBuf,
    owner: HashMap<String, String>,
    versions: HashMap<String, String>,
    md5: HashMap<String, HashMap<String, String>>,
}

fn strip_usrmerge(p: &str) -> Option<String> {
    for d in ["/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"] {
        if p == d || p.starts_with(&format!("{d}/")) {
            return Some(format!("/usr{p}"));
        }
    }
    None
}

impl DpkgDb {
    /// Loads the database rooted at `root` (normally `/`).
    pub fn load(root: &Path) -> std::io::Result<DpkgDb> {
        let info = root.join("var/lib/dpkg/info");
        let status = root.join("var/lib/dpkg/status");
        let mut db = DpkgDb { root: root.to_owned(), ..DpkgDb::default() };

        // Installed packages and versions from the status file.
        let mut text = String::new();
        fs::File::open(&status)?.read_to_string(&mut text)?;
        for stanza in text.split("\n\n") {
            let (mut name, mut arch, mut version, mut installed, mut multi) = (None, None, None, false, false);
            for line in stanza.lines() {
                if let Some(v) = line.strip_prefix("Package: ") {
                    name = Some(v.trim().to_owned());
                } else if let Some(v) = line.strip_prefix("Architecture: ") {
                    arch = Some(v.trim().to_owned());
                } else if let Some(v) = line.strip_prefix("Version: ") {
                    version = Some(v.trim().to_owned());
                } else if let Some(v) = line.strip_prefix("Status: ") {
                    installed = v.trim().ends_with(" installed");
                } else if let Some(v) = line.strip_prefix("Multi-Arch: ") {
                    multi = v.trim() == "same";
                }
            }
            if let (Some(n), Some(v), true) = (name, version, installed) {
                // dpkg names info files `name:arch` only for Multi-Arch: same packages.
                let key = match (multi, arch) {
                    (true, Some(a)) => format!("{n}:{a}"),
                    _ => n,
                };
                db.versions.insert(key, v);
            }
        }

        for entry in fs::read_dir(&info)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else { continue };
            if let Some(pkg) = name.strip_suffix(".list") {
                if !db.versions.contains_key(pkg) {
                    continue;
                }
                let content = fs::read_to_string(entry.path()).unwrap_or_default();
                for line in content.lines() {
                    if line.starts_with('/') && line != "/." {
                        db.owner.entry(line.to_owned()).or_insert_with(|| pkg.to_owned());
                    }
                }
            }
        }
        Ok(db)
    }

    /// Number of installed packages.
    pub fn package_count(&self) -> usize {
        self.versions.len()
    }

    /// Number of owned paths.
    pub fn path_count(&self) -> usize {
        self.owner.len()
    }

    fn manifest(&mut self, pkg: &str) -> &HashMap<String, String> {
        if !self.md5.contains_key(pkg) {
            let mut map = HashMap::new();
            let path = self.root.join(format!("var/lib/dpkg/info/{pkg}.md5sums"));
            if let Ok(text) = fs::read_to_string(path) {
                for line in text.lines() {
                    if let Some((sum, file)) = line.split_once("  ") {
                        map.insert(format!("/{file}"), sum.to_owned());
                    }
                }
            }
            self.md5.insert(pkg.to_owned(), map);
        }
        &self.md5[pkg]
    }

    /// Looks up the package owning `path` (a real, absolute path).
    pub fn ownership(&mut self, path: &str) -> Option<DpkgOwnership> {
        let candidates = [Some(path.to_owned()), strip_usrmerge(path), path.strip_prefix("/usr").map(str::to_owned)];
        for cand in candidates.into_iter().flatten() {
            if let Some(pkg) = self.owner.get(&cand).cloned() {
                let version = self.versions.get(&pkg).cloned().unwrap_or_default();
                let manifest = self.manifest(&pkg);
                let md5 = manifest
                    .get(&cand)
                    .or_else(|| manifest.get(path))
                    .or_else(|| manifest.get(&format!("/usr{cand}")))
                    .cloned();
                return Some(DpkgOwnership { package: pkg, version, manifest_md5: md5 });
            }
        }
        None
    }
}

/// MD5 of a byte slice as lowercase hex. MD5 is used only to compare against
/// dpkg's own manifests; it is not a security primitive in JLR.
#[cfg(test)]
pub fn md5_hex(data: &[u8]) -> String {
    Md5::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// MD5 of an open file's contents, read from its start.
pub fn md5_file(file: &mut fs::File) -> std::io::Result<String> {
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut h = Md5::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}
