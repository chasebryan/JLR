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

/// An index of installed packages and the paths they own.
///
/// Paths are held in one sorted byte blob and found by binary search, so a
/// lookup allocates nothing and the whole index can be cached on disk and
/// reloaded in milliseconds.
#[derive(Debug, Default)]
pub struct DpkgDb {
    root: PathBuf,
    /// `(name, version)` per package; owners index into this.
    packages: Vec<(String, String)>,
    blob: Vec<u8>,
    /// `offsets[i]..offsets[i + 1]` is path `i` inside `blob`; one extra entry closes the last path.
    offsets: Vec<u32>,
    owners: Vec<u32>,
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

const CACHE_MAGIC: &[u8; 8] = b"JLRDPKG1";

/// Fingerprint of everything the index is derived from: the status file and
/// the name, size and change times of every list and manifest file. If dpkg
/// or anyone else touches them, the fingerprint changes and the cache is rebuilt.
fn fingerprint(root: &Path) -> std::io::Result<[u8; 32]> {
    use jlr_crypto::Digest;
    use std::os::unix::fs::MetadataExt;
    let mut parts: Vec<u8> = Vec::new();
    let mut add = |name: &str, m: &fs::Metadata| {
        parts.extend_from_slice(name.as_bytes());
        for v in [m.len(), m.mtime() as u64, m.mtime_nsec() as u64, m.ctime() as u64, m.ctime_nsec() as u64, m.ino()] {
            parts.extend_from_slice(&v.to_le_bytes());
        }
    };
    add("status", &fs::metadata(root.join("var/lib/dpkg/status"))?);
    let mut names: Vec<(String, fs::Metadata)> = Vec::new();
    for e in fs::read_dir(root.join("var/lib/dpkg/info"))? {
        let e = e?;
        let n = e.file_name().to_string_lossy().into_owned();
        if n.ends_with(".list") || n.ends_with(".md5sums") {
            names.push((n, e.metadata()?));
        }
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    for (n, m) in &names {
        add(n, m);
    }
    Ok(Digest::of_parts("jlr-dpkg-index-v1", &[&parts]).0)
}

impl DpkgDb {
    /// Loads the database rooted at `root` (normally `/`) by parsing dpkg's files.
    pub fn load(root: &Path) -> std::io::Result<DpkgDb> {
        Self::build(root)
    }

    /// Loads through an on-disk cache at `cache`, rebuilding it when dpkg's
    /// files have changed. A missing, stale or damaged cache is never an error.
    pub fn load_cached(root: &Path, cache: &Path) -> std::io::Result<DpkgDb> {
        let fp = fingerprint(root)?;
        if let Some(db) = Self::read_cache(root, cache, &fp) {
            return Ok(db);
        }
        let db = Self::build(root)?;
        let _ = db.write_cache(cache, &fp); // best effort
        Ok(db)
    }

    fn build(root: &Path) -> std::io::Result<DpkgDb> {
        let info = root.join("var/lib/dpkg/info");
        let status = root.join("var/lib/dpkg/status");
        let mut db = DpkgDb { root: root.to_owned(), ..DpkgDb::default() };

        let mut text = String::new();
        fs::File::open(&status)?.read_to_string(&mut text)?;
        let mut index_of: HashMap<String, u32> = HashMap::new();
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
                index_of.insert(key.clone(), db.packages.len() as u32);
                db.packages.push((key, v));
            }
        }

        let mut pairs: Vec<(String, u32)> = Vec::new();
        for entry in fs::read_dir(&info)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else { continue };
            let Some(pkg) = name.strip_suffix(".list") else { continue };
            let Some(&idx) = index_of.get(pkg) else { continue };
            let content = fs::read_to_string(entry.path()).unwrap_or_default();
            for line in content.lines() {
                if line.starts_with('/') && line != "/." {
                    pairs.push((line.to_owned(), idx));
                }
            }
        }
        // Stable sort keeps the first package that claims a path, as before.
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        pairs.dedup_by(|later, first| later.0 == first.0);
        db.offsets.reserve(pairs.len() + 1);
        db.owners.reserve(pairs.len());
        for (path, owner) in pairs {
            db.offsets.push(db.blob.len() as u32);
            db.blob.extend_from_slice(path.as_bytes());
            db.owners.push(owner);
        }
        db.offsets.push(db.blob.len() as u32);
        Ok(db)
    }

    fn write_cache(&self, path: &Path, fp: &[u8; 32]) -> std::io::Result<()> {
        use std::io::Write;
        let mut out: Vec<u8> = Vec::with_capacity(self.blob.len() + self.offsets.len() * 8 + 4096);
        out.extend_from_slice(CACHE_MAGIC);
        out.extend_from_slice(fp);
        out.extend_from_slice(&(self.packages.len() as u32).to_le_bytes());
        for (n, v) in &self.packages {
            out.extend_from_slice(&(n.len() as u16).to_le_bytes());
            out.extend_from_slice(&(v.len() as u16).to_le_bytes());
            out.extend_from_slice(n.as_bytes());
            out.extend_from_slice(v.as_bytes());
        }
        out.extend_from_slice(&(self.owners.len() as u32).to_le_bytes());
        for o in &self.offsets {
            out.extend_from_slice(&o.to_le_bytes());
        }
        for o in &self.owners {
            out.extend_from_slice(&o.to_le_bytes());
        }
        out.extend_from_slice(&self.blob);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        fs::File::create(&tmp)?.write_all(&out)?;
        fs::rename(tmp, path)
    }

    fn read_cache(root: &Path, path: &Path, fp: &[u8; 32]) -> Option<DpkgDb> {
        let data = fs::read(path).ok()?;
        let mut r = Reader { data: &data, pos: 0 };
        if r.take(8)? != CACHE_MAGIC || r.take(32)? != fp {
            return None;
        }
        let n_pkgs = r.u32()? as usize;
        let mut packages = Vec::with_capacity(n_pkgs.min(1 << 20));
        for _ in 0..n_pkgs {
            let (nl, vl) = (r.u16()? as usize, r.u16()? as usize);
            let n = String::from_utf8(r.take(nl)?.to_vec()).ok()?;
            let v = String::from_utf8(r.take(vl)?.to_vec()).ok()?;
            packages.push((n, v));
        }
        let n_paths = r.u32()? as usize;
        let mut offsets = Vec::with_capacity(n_paths + 1);
        for _ in 0..=n_paths {
            offsets.push(r.u32()?);
        }
        let mut owners = Vec::with_capacity(n_paths);
        for _ in 0..n_paths {
            let o = r.u32()?;
            if o as usize >= packages.len() {
                return None;
            }
            owners.push(o);
        }
        let blob = data.get(r.pos..)?.to_vec();
        // Structural validation: offsets must be monotonic and within the blob.
        if offsets.first() != Some(&0)
            || *offsets.last()? as usize != blob.len()
            || offsets.windows(2).any(|w| w[0] > w[1])
        {
            return None;
        }
        Some(DpkgDb { root: root.to_owned(), packages, blob, offsets, owners, md5: HashMap::new() })
    }

    /// Number of installed packages.
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    /// Number of owned paths.
    pub fn path_count(&self) -> usize {
        self.owners.len()
    }

    fn find(&self, path: &str) -> Option<u32> {
        let target = path.as_bytes();
        let (mut lo, mut hi) = (0usize, self.owners.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            let cur = &self.blob[self.offsets[mid] as usize..self.offsets[mid + 1] as usize];
            match cur.cmp(target) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(self.owners[mid]),
            }
        }
        None
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
            if let Some(idx) = self.find(&cand) {
                let (pkg, version) = self.packages[idx as usize].clone();
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

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(s)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
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
