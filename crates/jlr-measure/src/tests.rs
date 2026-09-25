use super::*;
use jlr_model::{ArtifactClass, EvidenceKind, ProvenanceRank};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

fn write(dir: &Path, name: &str, content: &[u8], mode: u32) -> std::path::PathBuf {
    let p = dir.join(name);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::File::create(&p).unwrap().write_all(content).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    p
}

fn elf_header(e_type: u16) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[..4].copy_from_slice(b"\x7fELF");
    h[4] = 2; // 64-bit
    h[5] = 1; // little endian
    h[16..18].copy_from_slice(&e_type.to_le_bytes());
    h
}

#[test]
fn sha256_of_descriptor_matches_known_answer() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "abc", b"abc", 0o644);
    let (_f, m) = open_measured(&p, 1 << 20).unwrap();
    assert_eq!(m.digest.hex(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(m.size, 3);
    assert_eq!(m.head, b"abc");
}

#[test]
fn symlinks_and_non_regular_files_are_refused() {
    let d = tempfile::tempdir().unwrap();
    let real = write(d.path(), "real", b"x", 0o755);
    let link = d.path().join("link");
    symlink(&real, &link).unwrap();
    assert!(matches!(open_measured(&link, 1 << 20), Err(MeasureError::Symlink)));
    assert!(matches!(open_measured(d.path(), 1 << 20), Err(MeasureError::NotRegular)));
}

#[test]
fn size_limit_is_enforced() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "big", &vec![0u8; 5000], 0o644);
    assert!(matches!(open_measured(&p, 4096), Err(MeasureError::TooLarge(_))));
    assert!(open_measured(&p, 5000).is_ok());
}

#[test]
fn measured_descriptor_is_the_file_that_was_hashed_even_if_the_path_is_swapped() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "prog", b"original", 0o755);
    let (mut f, m) = open_measured(&p, 1 << 20).unwrap();
    // Replace the path after measurement, as an attacker racing the launcher would.
    fs::remove_file(&p).unwrap();
    write(d.path(), "prog", b"malicious", 0o755);
    let mut content = String::new();
    std::io::Read::read_to_string(&mut f, &mut content).unwrap();
    assert_eq!(content, "original", "the descriptor still refers to the measured bytes");
    assert_eq!(m.digest, jlr_crypto::Digest::of(b"original"));
}

#[test]
fn classification() {
    let p = |s: &str| Path::new(s).to_owned();
    assert_eq!(classify(&elf_header(2), &p("/bin/ls"), 0o755), ArtifactClass::Exe);
    assert_eq!(classify(&elf_header(3), &p("/usr/lib/libc.so.6"), 0o755), ArtifactClass::Lib);
    assert_eq!(classify(&elf_header(3), &p("/usr/bin/pie-binary"), 0o755), ArtifactClass::Exe);
    assert_eq!(classify(&elf_header(3), &p("/usr/lib/libx.so"), 0o644), ArtifactClass::Lib);
    assert_eq!(classify(&elf_header(1), &p("/usr/lib/foo.o"), 0o644), ArtifactClass::Other);
    assert_eq!(classify(&elf_header(1), &p("/lib/modules/x/foo.ko"), 0o644), ArtifactClass::Module);
    assert_eq!(classify(b"#!/bin/sh\n", &p("/usr/bin/x"), 0o755), ArtifactClass::Script);
    assert_eq!(classify(b"[Unit]", &p("/etc/systemd/system/a.service"), 0o644), ArtifactClass::Service);
    assert_eq!(classify(b"MZ", &p("/boot/vmlinuz-6.1"), 0o644), ArtifactClass::Kernel);
    assert_eq!(classify(b"..", &p("/boot/initrd.img-6.1"), 0o644), ArtifactClass::Initrd);
    assert_eq!(classify(b"..", &p("/boot/efi/EFI/BOOT/BOOTX64.efi"), 0o644), ArtifactClass::Boot);
    assert_eq!(classify(b"text", &p("/home/u/notes.txt"), 0o644), ArtifactClass::Other);
    // An executable of unknown format is governed as a script, never left unclassified.
    assert_eq!(classify(b"\x01\x02", &p("/home/u/blob"), 0o755), ArtifactClass::Script);
    assert!(is_governed(ArtifactClass::Exe) && is_governed(ArtifactClass::Script));
    assert!(!is_governed(ArtifactClass::Other) && !is_governed(ArtifactClass::Config));
}

#[test]
fn truncated_and_short_headers_do_not_panic() {
    for len in 0..20 {
        let h = &elf_header(2)[..len.min(64)];
        let _ = classify(h, Path::new("/x"), 0o755);
    }
}

fn me() -> Trust {
    Trust::current_process()
}

#[test]
fn path_facts_detect_setuid_and_untrusted_writers() {
    let d = tempfile::tempdir().unwrap();
    let f = write(d.path(), "sub/tool", b"x", 0o4755);
    // The outcome must not depend on the umask of whoever runs the tests.
    fs::set_permissions(d.path().join("sub"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let facts = path_facts(&f, &me()).unwrap();
    assert!(facts.setuid && !facts.setgid);
    assert!(!facts.writable_by_untrusted, "owned by a trusted uid, no group/other write: {facts:?}");

    // The same tree is untrusted when its owner is not trusted.
    assert!(path_facts(&f, &Trust::root_only()).unwrap().writable_by_untrusted);

    // World-writable parent directory without sticky bit.
    fs::set_permissions(d.path().join("sub"), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(path_facts(&f, &me()).unwrap().writable_by_untrusted);
    // A sticky world-writable directory (like /tmp) does not by itself let others replace files in it.
    fs::set_permissions(d.path().join("sub"), fs::Permissions::from_mode(0o1777)).unwrap();
    let g = write(d.path(), "sub/tool2", b"x", 0o755);
    assert!(!path_facts(&g, &me()).unwrap().writable_by_untrusted);
    // Other-writable file.
    fs::set_permissions(&g, fs::Permissions::from_mode(0o757)).unwrap();
    assert!(path_facts(&g, &me()).unwrap().writable_by_untrusted);
}

#[test]
fn group_write_is_trusted_only_for_trusted_groups() {
    let d = tempfile::tempdir().unwrap();
    let f = write(d.path(), "tool", b"x", 0o775);
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let mut trust = me();
    assert!(!path_facts(&f, &trust).unwrap().writable_by_untrusted, "own private group is trusted");
    trust.gids.clear();
    assert!(path_facts(&f, &trust).unwrap().writable_by_untrusted, "an unknown group with write access is not");
}

#[test]
fn symlinks_are_judged_by_where_they_lead_and_who_owns_them() {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let real = write(d.path(), "real/tool", b"x", 0o755);
    fs::set_permissions(d.path().join("real"), fs::Permissions::from_mode(0o755)).unwrap();
    let link = d.path().join("link");
    symlink(&real, &link).unwrap();
    // A symlink's own mode (always 0777) must not make its target look writable.
    assert!(!path_facts(&link, &me()).unwrap().writable_by_untrusted);
    // A link owned by someone untrusted lets that owner retarget it.
    assert!(path_facts(&link, &Trust::root_only()).unwrap().writable_by_untrusted);
}

#[test]
fn system_binaries_are_not_writable_by_untrusted() {
    // /bin is a symlink to usr/bin on merged-usr systems; /bin/sh a link to dash.
    let f = path_facts(Path::new("/bin/sh"), &Trust::root_only()).unwrap();
    assert!(!f.writable_by_untrusted, "{f:?}");
}

fn fake_dpkg(root: &Path, files: &[(&str, &[u8])]) {
    let info = root.join("var/lib/dpkg/info");
    fs::create_dir_all(&info).unwrap();
    fs::write(
        root.join("var/lib/dpkg/status"),
        "Package: coreutils\nStatus: install ok installed\nArchitecture: amd64\nVersion: 9.4-1\n\n\
         Package: removed\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 1\n",
    )
    .unwrap();
    let mut list = String::from("/.\n/usr\n/usr/bin\n");
    let mut sums = String::new();
    for (path, content) in files {
        list.push_str(&format!("{path}\n"));
        sums.push_str(&format!("{}  {}\n", dpkg::md5_hex(content), path.trim_start_matches('/')));
    }
    fs::write(info.join("coreutils.list"), list).unwrap();
    fs::write(info.join("coreutils.md5sums"), sums).unwrap();
    fs::write(info.join("removed.list"), "/usr/bin/ghost\n").unwrap();
}

#[test]
fn dpkg_ownership_and_manifest_match() {
    let root = tempfile::tempdir().unwrap();
    fake_dpkg(root.path(), &[("/usr/bin/tool", b"tool-bytes")]);
    let mut db = DpkgDb::load(root.path()).unwrap();
    assert_eq!(db.package_count(), 1, "only installed packages count");
    let own = db.ownership("/usr/bin/tool").unwrap();
    assert_eq!((own.package.as_str(), own.version.as_str()), ("coreutils", "9.4-1"));
    assert_eq!(own.manifest_md5.as_deref(), Some(dpkg::md5_hex(b"tool-bytes").as_str()));
    assert!(db.ownership("/usr/bin/ghost").is_none(), "files of removed packages are not owned");
    assert!(db.ownership("/usr/bin/other").is_none());
    // usr-merge: a request for /bin/tool resolves to the /usr/bin/tool entry.
    assert!(db.ownership("/bin/tool").is_some());
}

#[test]
fn observe_reports_manifest_match_and_mismatch_without_claiming_a_signature() {
    let sys = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let good = write(files.path(), "usr/bin/tool", b"tool-bytes", 0o755);
    let _ = files.path();
    // Map the real on-disk path into the fake database.
    let good_str = good.to_string_lossy().into_owned();
    fake_dpkg(sys.path(), &[(&good_str, b"tool-bytes")]);
    let mut db = DpkgDb::load(sys.path()).unwrap();
    let opts = ObserveOptions { trust: me(), now: 42, ..Default::default() };
    let o = observe(&good, Some(&mut db), &opts).unwrap();
    let kinds: Vec<_> = o.evidence.iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&EvidenceKind::ManagedInstaller));
    assert!(kinds.contains(&EvidenceKind::PackageManifestMatch));
    assert!(
        !kinds.contains(&EvidenceKind::PackageSignature),
        "an unauthenticated manifest must not be reported as a signature"
    );
    assert_eq!(o.record.provenance, ProvenanceRank::SourceKnown);
    assert_eq!(o.record.source.channel, "dpkg");
    assert_eq!(o.record.class, ArtifactClass::Script, "executable of unknown format");

    // Tamper with the file: it no longer matches the package manifest.
    fs::write(&good, b"evil-bytes").unwrap();
    let o = observe(&good, Some(&mut db), &opts).unwrap();
    assert!(o.evidence.iter().any(|e| e.kind == EvidenceKind::ContentDigestMismatch));
    assert!(!o.evidence.iter().any(|e| e.kind == EvidenceKind::PackageManifestMatch));
}

#[test]
fn unmanaged_files_have_unknown_provenance() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "dropper", &elf_header(2), 0o755);
    let o = observe(&p, None, &ObserveOptions::default()).unwrap();
    assert_eq!(o.record.provenance, ProvenanceRank::Unknown);
    assert_eq!(o.record.source.channel, "unmanaged");
    assert_eq!(o.record.class, ArtifactClass::Exe);
    assert!(o.evidence.iter().any(|e| e.kind == EvidenceKind::WritablePath), "owned by a non-root, non-trusted user");
}

#[test]
fn identical_bytes_at_different_paths_have_different_epns_but_equal_digests() {
    let d = tempfile::tempdir().unwrap();
    let a = write(d.path(), "a/tool", &elf_header(2), 0o755);
    let b = write(d.path(), "b/tool", &elf_header(2), 0o755);
    let oa = observe(&a, None, &ObserveOptions::default()).unwrap();
    let ob = observe(&b, None, &ObserveOptions::default()).unwrap();
    assert_eq!(oa.record.digest, ob.record.digest);
    assert_ne!(oa.record.id(), ob.record.id(), "the EPN binds the installation path");
}

#[test]
fn walk_skips_symlinks_ungoverned_files_and_is_sorted() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "bin/b", &elf_header(2), 0o755);
    write(d.path(), "bin/a", b"#!/bin/sh\n", 0o755);
    write(d.path(), "docs/readme.txt", b"hello", 0o644);
    write(d.path(), "lib/libx.so", &elf_header(3), 0o644);
    symlink(d.path().join("bin/a"), d.path().join("bin/link")).unwrap();
    symlink("/etc", d.path().join("etc-link")).unwrap();
    let found = walk(d.path(), &WalkOptions { exclude: vec![], ..Default::default() }).unwrap();
    let rel: Vec<_> = found.iter().map(|p| p.strip_prefix(d.path()).unwrap().to_string_lossy().into_owned()).collect();
    assert_eq!(rel, ["bin/a", "bin/b", "lib/libx.so"]);
    let all = walk(d.path(), &WalkOptions { exclude: vec![], governed_only: false, ..Default::default() }).unwrap();
    assert_eq!(all.len(), 4);
}

#[test]
fn walk_respects_exclusions_and_depth() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "keep/x", b"#!/bin/sh\n", 0o755);
    write(d.path(), "skip/y", b"#!/bin/sh\n", 0o755);
    write(d.path(), "a/b/c/deep", b"#!/bin/sh\n", 0o755);
    let opts = WalkOptions { exclude: vec![d.path().join("skip")], max_depth: 1, ..Default::default() };
    let found = walk(d.path(), &opts).unwrap();
    let rel: Vec<_> = found.iter().map(|p| p.strip_prefix(d.path()).unwrap().to_string_lossy().into_owned()).collect();
    assert_eq!(rel, ["keep/x"]);
}

#[test]
fn real_host_dpkg_database_loads_when_present() {
    if !Path::new("/var/lib/dpkg/status").exists() {
        return;
    }
    let mut db = DpkgDb::load(Path::new("/")).unwrap();
    assert!(db.package_count() > 10);
    let own = db.ownership("/bin/sh").or_else(|| db.ownership("/usr/bin/sh"));
    assert!(own.is_some(), "/bin/sh must be owned by a package on a Debian-family host");
}

#[test]
fn cached_index_matches_a_fresh_load_and_is_invalidated_by_changes() {
    let sys = tempfile::tempdir().unwrap();
    fake_dpkg(sys.path(), &[("/usr/bin/tool", b"tool-bytes"), ("/usr/bin/other", b"other")]);
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_dir.path().join("dpkg.idx");

    let mut fresh = DpkgDb::load(sys.path()).unwrap();
    let mut first = DpkgDb::load_cached(sys.path(), &cache).unwrap(); // builds and writes
    assert!(cache.exists());
    let mut second = DpkgDb::load_cached(sys.path(), &cache).unwrap(); // reads
    for db in [&mut fresh, &mut first, &mut second] {
        assert_eq!(db.package_count(), 1);
        let own = db.ownership("/usr/bin/tool").unwrap();
        assert_eq!(own.package, "coreutils");
        assert_eq!(own.manifest_md5.as_deref(), Some(dpkg::md5_hex(b"tool-bytes").as_str()));
        assert!(db.ownership("/usr/bin/nothing").is_none());
        assert!(db.ownership("/bin/other").is_some(), "usr-merge lookups work through the index");
    }

    // A change to dpkg's own files must invalidate the cache.
    let list = sys.path().join("var/lib/dpkg/info/coreutils.list");
    let mut text = fs::read_to_string(&list).unwrap();
    text.push_str("/usr/bin/added\n");
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(&list, text).unwrap();
    let mut third = DpkgDb::load_cached(sys.path(), &cache).unwrap();
    assert!(third.ownership("/usr/bin/added").is_some(), "stale cache was used after dpkg's files changed");
}

#[test]
fn damaged_or_truncated_caches_are_ignored_not_trusted() {
    let sys = tempfile::tempdir().unwrap();
    fake_dpkg(sys.path(), &[("/usr/bin/tool", b"x")]);
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_dir.path().join("dpkg.idx");
    DpkgDb::load_cached(sys.path(), &cache).unwrap();
    let good = fs::read(&cache).unwrap();
    for cut in [0usize, 5, 20, 45, good.len() / 2, good.len() - 1] {
        fs::write(&cache, &good[..cut]).unwrap();
        let mut db = DpkgDb::load_cached(sys.path(), &cache).unwrap();
        assert!(db.ownership("/usr/bin/tool").is_some(), "cut at {cut} must fall back to a fresh build");
    }
    // Garbage that keeps the header but corrupts offsets.
    let mut bad = good.clone();
    let n = bad.len();
    for b in &mut bad[n - 40..] {
        *b = 0xff;
    }
    fs::write(&cache, &bad).unwrap();
    let mut db = DpkgDb::load_cached(sys.path(), &cache).unwrap();
    assert!(db.ownership("/usr/bin/tool").is_some());
}

#[test]
fn an_edit_that_restores_mtime_is_still_detected_because_ctime_cannot_be_restored() {
    use std::os::unix::fs::FileExt;
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "victim", &vec![7u8; 300_000], 0o755);
    let mut f = fs::OpenOptions::new().read(true).write(true).open(&p).unwrap();
    let original_mtime = f.metadata().unwrap().modified().unwrap();
    // The worst moment: after the bytes were hashed, before the state is re-checked, the owner rewrites
    // hashed bytes and puts the old mtime back. Size and mtime are then identical to before.
    let writer = fs::OpenOptions::new().write(true).open(&p).unwrap();
    let mut evil = || {
        std::thread::sleep(std::time::Duration::from_millis(20)); // ensure ctime moves on coarse clocks
        writer.write_all_at(&[0xee; 4096], 0).unwrap();
        writer.set_modified(original_mtime).unwrap();
    };
    let r = measure_file_with(&mut f, 1 << 20, &mut evil);
    assert!(matches!(r, Err(MeasureError::ChangedWhileReading)), "mtime-restoring edit went unnoticed: {r:?}");
}

/// Rewrites the first byte of `path` from inside the measurement, after the bytes were read and before the state is
/// checked again. The pause makes sure the change lands in a later clock tick than the file's last change, which
/// matters on kernels whose timestamps are a few milliseconds coarse.
fn change_during_read(writer: &fs::File, value: u8) {
    use std::os::unix::fs::FileExt;
    std::thread::sleep(std::time::Duration::from_millis(20));
    writer.write_all_at(&[value], 0).unwrap();
}

#[test]
fn a_file_that_keeps_changing_is_reported_not_measured() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "moving", b"#!/bin/sh\n", 0o755);
    let mut f = fs::OpenOptions::new().read(true).open(&p).unwrap();
    let writer = fs::OpenOptions::new().write(true).open(&p).unwrap();
    let mut attempts = 0usize;
    // The production retry loop, with a file that changes during every attempt.
    let r = measure_file_stable_with(&mut f, 1 << 20, false, &mut |_| {
        attempts += 1;
        change_during_read(&writer, attempts as u8);
    });
    assert!(matches!(r, Err(MeasureError::ChangedWhileReading)), "{r:?}");
    assert_eq!(attempts, 2, "a small file gets one retry and no more");
}

#[test]
fn a_file_that_settles_is_measured_on_the_retry() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "settling", b"#!/bin/sh\n", 0o755);
    let mut f = fs::OpenOptions::new().read(true).open(&p).unwrap();
    let writer = fs::OpenOptions::new().write(true).open(&p).unwrap();
    // Changes during the first attempt only: the second sees a stable file and its digest is of the new content.
    let m = measure_file_stable_with(&mut f, 1 << 20, false, &mut |attempt| {
        if attempt == 0 {
            change_during_read(&writer, b'X');
        }
    })
    .expect("a file that stops changing must be measurable");
    assert_eq!(m.digest, jlr_crypto::Digest::of(&fs::read(&p).unwrap()));
    assert_eq!(fs::read(&p).unwrap()[0], b'X');
}

#[test]
fn a_large_file_that_keeps_changing_is_read_once_not_repeatedly() {
    // A file over the retry limit is read a single time: an owner who keeps touching a big file must not be able
    // to multiply the gate's hashing work.
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("big");
    let big = fs::File::create(&p).unwrap();
    big.set_len(20 * 1024 * 1024).unwrap(); // sparse
    let mut f = fs::OpenOptions::new().read(true).open(&p).unwrap();
    let writer = fs::OpenOptions::new().write(true).open(&p).unwrap();
    let mut attempts = 0usize;
    let r = measure_file_stable_with(&mut f, 1 << 30, false, &mut |_| {
        attempts += 1;
        change_during_read(&writer, 1);
    });
    assert!(matches!(r, Err(MeasureError::ChangedWhileReading)), "{r:?}");
    assert_eq!(attempts, 1);
}

#[test]
fn the_package_checksum_comes_from_the_same_read_as_the_digest() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "pkgfile", b"tool-bytes", 0o755);
    let mut f = fs::OpenOptions::new().read(true).open(&p).unwrap();
    let m = measure_file_stable_with(&mut f, 1 << 20, true, &mut |_| {}).unwrap();
    assert_eq!(m.md5_hex.as_deref(), Some(dpkg::md5_hex(b"tool-bytes").as_str()));
    let m = measure_file_stable_with(&mut f, 1 << 20, false, &mut |_| {}).unwrap();
    assert_eq!(m.md5_hex, None, "MD5 is computed only when a package manifest asks for it");
    // Because both hashes come from one pass, one stamp check covers both: a change during the read is refused
    // even though an MD5 was being computed.
    let writer = fs::OpenOptions::new().write(true).open(&p).unwrap();
    let r = measure_file_stable_with(&mut f, 1 << 20, true, &mut |_| change_during_read(&writer, b'Z'));
    assert!(matches!(r, Err(MeasureError::ChangedWhileReading)), "{r:?}");
}

#[test]
fn stamps_record_state_before_hashing() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "s", b"abc", 0o644);
    let (_f, m) = open_measured(&p, 1 << 20).unwrap();
    assert_eq!(m.stamp.size, 3);
    assert!(m.stamp.ctime_ns > 0 && m.stamp.mtime_ns > 0);
    assert_eq!(m.stamp.ino, std::os::unix::fs::MetadataExt::ino(&fs::metadata(&p).unwrap()));
}
