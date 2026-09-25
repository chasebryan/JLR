//! Boots the real JLR initramfs under QEMU/KVM and checks what it does with
//! good, tampered, mis-signed and rolled-back releases.
//!
//! Requirements (the tests skip loudly when any is missing):
//! * QEMU (`JLR_QEMU`, else ~/.local/jlr-tools/bin/qemu-system-x86_64, else PATH)
//! * a readable Linux kernel with virtio, loop, ext4 and squashfs built in
//!   (`JLR_KERNEL`, else a kernel extracted under ~/.local/jlr-tools/kernel, else /boot)
//! * the artifacts built by `boot/build.sh` (built automatically when missing)
//! * `mke2fs` and `debugfs`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use jlr_boot::{BootState, ReleaseManifest, SlotState};
use jlr_cbor::Cbor;
use jlr_crypto::{Digest, Role, SigningKeypair};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::{Duration, Instant};

struct Env {
    qemu: PathBuf,
    qemu_data: Option<PathBuf>,
    kernel: PathBuf,
    out: PathBuf,
    mke2fs: PathBuf,
    debugfs: PathBuf,
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}

fn which(name: &str) -> Option<PathBuf> {
    for dir in std::env::var("PATH").unwrap_or_default().split(':').chain(["/usr/sbin", "/sbin"]) {
        let p = Path::new(dir).join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn find_kernel() -> Option<PathBuf> {
    if let Some(k) = std::env::var_os("JLR_KERNEL") {
        return Some(PathBuf::from(k));
    }
    let extracted = home().join(".local/jlr-tools/kernel/ex/boot");
    if let Ok(rd) = fs::read_dir(&extracted) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("vmlinuz") && fs::File::open(e.path()).is_ok() {
                return Some(e.path());
            }
        }
    }
    let uname = Command::new("uname").arg("-r").output().ok()?;
    let p = PathBuf::from(format!("/boot/vmlinuz-{}", String::from_utf8_lossy(&uname.stdout).trim()));
    fs::File::open(&p).ok().map(|_| p)
}

static BUILD: Once = Once::new();

fn env() -> Option<Env> {
    let skip = |why: &str| {
        eprintln!("SKIPPED: {why}");
        None
    };
    let qemu = std::env::var_os("JLR_QEMU").map(PathBuf::from).or_else(|| {
        let p = home().join(".local/jlr-tools/bin/qemu-system-x86_64");
        p.exists().then_some(p)
    });
    let Some(qemu) = qemu.or_else(|| which("qemu-system-x86_64")) else { return skip("qemu-system-x86_64 not found") };
    let qemu_data = std::env::var_os("JLR_QEMU_DATA").map(PathBuf::from).or_else(|| {
        let p = home().join(".local/jlr-tools/root/usr/share/qemu");
        p.exists().then_some(p)
    });
    let Some(kernel) = find_kernel() else { return skip("no readable kernel (set JLR_KERNEL)") };
    let Some(mke2fs) = which("mke2fs") else { return skip("mke2fs not found") };
    let Some(debugfs) = which("debugfs") else { return skip("debugfs not found") };
    let out = std::env::var_os("JLR_BOOT_OUT").map(PathBuf::from).unwrap_or_else(|| workspace().join("out/boot"));
    BUILD.call_once(|| {
        if !out.join("initramfs.cpio.gz").exists() {
            let st = Command::new(workspace().join("boot/build.sh")).status();
            if !matches!(st, Ok(s) if s.success()) {
                eprintln!("boot/build.sh failed");
            }
        }
    });
    if !out.join("initramfs.cpio.gz").exists() {
        return skip("boot artifacts could not be built (see boot/build.sh)");
    }
    Some(Env { qemu, qemu_data, kernel, out, mke2fs, debugfs })
}

fn release_key() -> SigningKeypair {
    SigningKeypair::load(&workspace().join("out/boot/release.key")).unwrap()
}

fn other_key() -> SigningKeypair {
    SigningKeypair::load(&workspace().join("out/boot/other.key")).unwrap()
}

/// A slot to place on the boot media.
struct Slot {
    name: &'static str,
    image: Vec<u8>,
    manifest: Vec<u8>,
}

fn manifest(image: &[u8], epoch: u64, min_epoch: u64, key: &SigningKeypair) -> Vec<u8> {
    ReleaseManifest {
        schema: 1,
        name: "jlr-base".into(),
        version: format!("0.{epoch}.0"),
        epoch,
        image_digest: Digest::of(image),
        image_size: image.len() as u64,
        min_epoch,
        policy_digest: None,
        components: vec![],
    }
    .sign(key)
}

fn good_slot(env: &Env, name: &'static str, epoch: u64) -> Slot {
    let image = fs::read(env.out.join("base.sqfs")).unwrap();
    let manifest = manifest(&image, epoch, epoch, &release_key());
    Slot { name, image, manifest }
}

fn flip(mut v: Vec<u8>, at: usize) -> Vec<u8> {
    let n = v.len();
    v[at % n] ^= 0x40;
    v
}

fn build_disk(env: &Env, dir: &Path, slots: &[Slot], state: Option<&BootState>) -> PathBuf {
    build_named_disk(env, dir, "disk", slots, state, None)
}

/// Like [`build_disk`], for tests that attach several disks; `uuid` fixes the ext4 file system UUID.
fn build_named_disk(
    env: &Env,
    dir: &Path,
    name: &str,
    slots: &[Slot],
    state: Option<&BootState>,
    uuid: Option<&str>,
) -> PathBuf {
    let tree = dir.join(format!("{name}-tree"));
    for s in slots {
        let d = tree.join(format!("jlr/slot-{}", s.name));
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("manifest.cose"), &s.manifest).unwrap();
        fs::write(d.join("base.sqfs"), &s.image).unwrap();
    }
    fs::create_dir_all(tree.join("jlr")).unwrap();
    if let Some(st) = state {
        fs::write(tree.join("jlr/bootstate.cbor"), st.to_cbor()).unwrap();
    }
    let img = dir.join(format!("{name}.img"));
    let mut mk = Command::new(&env.mke2fs);
    mk.args(["-q", "-t", "ext4", "-F"]);
    if let Some(u) = uuid {
        mk.args(["-U", u]);
    }
    let st = mk.arg("-d").arg(&tree).arg(&img).arg("48M").status().unwrap();
    assert!(st.success(), "mke2fs failed");
    img
}

fn read_state(env: &Env, disk: &Path) -> BootState {
    let out = Command::new(&env.debugfs).args(["-R", "cat /jlr/bootstate.cbor"]).arg(disk).output().unwrap();
    BootState::from_cbor(&out.stdout).unwrap_or_else(|e| panic!("bootstate unreadable: {e}"))
}

struct Boot {
    lines: Vec<String>,
    timed_out: bool,
}

impl Boot {
    fn has(&self, needle: &str) -> bool {
        self.lines.iter().any(|l| l.contains(needle))
    }
    fn pos(&self, needle: &str) -> Option<usize> {
        self.lines.iter().position(|l| l.contains(needle))
    }
    fn dump(&self) -> String {
        self.lines.join("\n")
    }
}

fn boot(env: &Env, disk: Option<&Path>, extra: &str) -> Boot {
    let disks: Vec<(&Path, bool)> = disk.into_iter().map(|d| (d, false)).collect();
    boot_disks(env, &disks, extra)
}

/// Boots with any number of virtio disks, each optionally attached write-protected.
fn boot_disks(env: &Env, disks: &[(&Path, bool)], extra: &str) -> Boot {
    let kvm = fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok();
    let mut cmd = Command::new(&env.qemu);
    if let Some(d) = &env.qemu_data {
        cmd.arg("-L").arg(d);
    }
    if kvm {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-cpu", "max"]);
    }
    cmd.args(["-m", "1024", "-smp", "2", "-nographic", "-no-reboot", "-nic", "none"]);
    cmd.arg("-kernel").arg(&env.kernel).arg("-initrd").arg(env.out.join("initramfs.cpio.gz"));
    cmd.arg("-append").arg(format!("console=ttyS0 panic=-1 loglevel=1 jlr.onfail=poweroff jlr.test=poweroff {extra}"));
    for (d, read_only) in disks {
        let ro = if *read_only { ",readonly=on" } else { "" };
        cmd.arg("-drive").arg(format!("file={},format=raw,if=virtio{ro}", d.display()));
    }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + Duration::from_secs(if kvm { 60 } else { 240 });
    let mut timed_out = false;
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let raw = reader.join().unwrap();
    let text = String::from_utf8_lossy(&raw).replace('\r', "");
    let lines = text
        .lines()
        .filter(|l| l.contains("JLR-") || l.contains("GUEST:") || l.contains("Kernel panic"))
        .map(str::to_owned)
        .collect();
    if std::env::var_os("JLR_BOOT_SHOW").is_some() {
        for l in &lines {
            eprintln!("  | {l}");
        }
    }
    Boot { lines, timed_out }
}

fn assert_refused_without_running(b: &Boot, reason: &str) {
    assert!(b.has(reason), "expected {reason:?} in:\n{}", b.dump());
    assert!(b.has("state=RECOVERY-RESTRICTED"), "{}", b.dump());
    assert!(!b.has("switching root"), "the base must not start after a refusal:\n{}", b.dump());
    assert!(!b.has("JLR-STAGE2"), "no stage 2 output is possible after a refusal:\n{}", b.dump());
    assert!(!b.timed_out, "{}", b.dump());
}

#[test]
fn a_valid_signed_release_boots_from_ram_and_proves_itself() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let disk = build_disk(&env, dir.path(), &[good_slot(&env, "a", 1)], None);
    let b = boot(&env, Some(&disk), "");
    assert!(!b.timed_out, "{}", b.dump());
    for step in [
        "anchors loaded keys=1",
        "media found dev=/dev/vda",
        "slot=a manifest=verified version=0.1.0 epoch=1",
        "selected slot=a epoch=1",
        "image verified slot=a",
        "(now resident in RAM)",
        "base mounted read-only from RAM",
        "boot media released",
        "switching root",
        "JLR-STAGE2: running from the verified RAM base slot=a",
        "check root is read-only: ok",
        "check run is writable and memory backed: ok",
        "slot a marked successful",
        "JLR-STAGE2: ready",
    ] {
        assert!(b.has(step), "missing {step:?} in:\n{}", b.dump());
    }
    assert!(!b.has("REFUSED") && !b.has("FAILED"), "{}", b.dump());
    // The order is part of the security argument: verify, then load into RAM, then release the media, then run.
    let order = [
        "manifest=verified",
        "image verified",
        "base mounted read-only from RAM",
        "boot media released",
        "switching root",
        "JLR-STAGE2: ready",
    ];
    let positions: Vec<usize> = order.iter().map(|s| b.pos(s).unwrap()).collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{positions:?}\n{}", b.dump());
    // The state on the media now records success.
    let st = read_state(&env, &disk);
    assert!(st.slots.iter().any(|s| s.name == "a" && s.successful), "{st:?}");
}

#[test]
fn a_tampered_image_is_refused_before_anything_from_it_runs() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut slot = good_slot(&env, "a", 1);
    slot.image = flip(slot.image, 200_000); // one flipped bit, deep inside the image
    let disk = build_disk(&env, dir.path(), &[slot], None);
    let b = boot(&env, Some(&disk), "");
    assert_refused_without_running(&b, "image digest mismatch");
    assert!(b.has("no slot passed verification"), "{}", b.dump());
    let st = read_state(&env, &disk);
    assert!(st.slots.iter().any(|s| s.name == "a" && s.priority == 0), "the failed slot must be marked bad: {st:?}");
}

#[test]
fn a_truncated_image_is_refused() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut slot = good_slot(&env, "a", 1);
    slot.image.truncate(slot.image.len() - 4096);
    let disk = build_disk(&env, dir.path(), &[slot], None);
    assert_refused_without_running(&boot(&env, Some(&disk), ""), "image size mismatch");
}

#[test]
fn a_tampered_manifest_is_refused() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut slot = good_slot(&env, "a", 1);
    slot.manifest = flip(slot.manifest, 60);
    let disk = build_disk(&env, dir.path(), &[slot], None);
    let b = boot(&env, Some(&disk), "");
    assert_refused_without_running(&b, "slot=a REFUSED");
    assert!(b.has("no slot passed verification"), "{}", b.dump());
}

#[test]
fn a_release_signed_by_an_unknown_key_is_refused() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let image = fs::read(env.out.join("base.sqfs")).unwrap();
    let slot = Slot { name: "a", manifest: manifest(&image, 1, 1, &other_key()), image };
    let disk = build_disk(&env, dir.path(), &[slot], None);
    assert_refused_without_running(&boot(&env, Some(&disk), ""), "is not trusted");
}

#[test]
fn a_release_signed_by_a_key_with_the_wrong_role_is_refused() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    // The trusted key is a release key, but a signature over a *policy* record type must not pass.
    let image = fs::read(env.out.join("base.sqfs")).unwrap();
    let m = ReleaseManifest {
        schema: 1,
        name: "x".into(),
        version: "0".into(),
        epoch: 1,
        image_digest: Digest::of(&image),
        image_size: image.len() as u64,
        min_epoch: 1,
        policy_digest: None,
        components: vec![],
    };
    let confused = jlr_crypto::Envelope::sign(jlr_model::record_type::POLICY, "*", &m.to_cbor(), &release_key());
    let disk = build_disk(&env, dir.path(), &[Slot { name: "a", image, manifest: confused }], None);
    assert_refused_without_running(&boot(&env, Some(&disk), ""), "slot=a REFUSED");
    let _ = Role::Release;
}

#[test]
fn rollback_below_the_floor_is_refused_even_with_a_valid_signature() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let state =
        BootState { floor: 5, slots: vec![SlotState { name: "a".into(), priority: 15, tries: 0, successful: true }] };
    let disk = build_disk(&env, dir.path(), &[good_slot(&env, "a", 1)], Some(&state));
    let b = boot(&env, Some(&disk), "");
    assert_refused_without_running(&b, "release epoch 1 is below the rollback floor 5");
}

#[test]
fn a_broken_update_falls_back_to_the_proven_slot() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let a = good_slot(&env, "a", 1);
    let mut b_slot = good_slot(&env, "b", 2);
    b_slot.image = flip(b_slot.image, 100_000); // B's manifest is valid but its image is corrupt
    let mut state = BootState::fresh();
    state.install("b");
    let disk = build_disk(&env, dir.path(), &[a, b_slot], Some(&state));
    let b = boot(&env, Some(&disk), "");
    assert!(!b.timed_out, "{}", b.dump());
    let sel_b = b.pos("trying slot=b").expect("B is tried first");
    let bad_b = b.pos("slot=b REFUSED image").expect("B's image is refused");
    let sel_a = b.pos("selected slot=a").expect("then A is selected");
    assert!(sel_b < bad_b && bad_b < sel_a, "{}", b.dump());
    assert!(b.has("JLR-STAGE2: ready"), "{}", b.dump());
    let st = read_state(&env, &disk);
    let sb = st.slots.iter().find(|s| s.name == "b").unwrap();
    let sa = st.slots.iter().find(|s| s.name == "a").unwrap();
    assert_eq!(sb.priority, 0, "the corrupt slot must never be tried again: {st:?}");
    assert!(sa.successful);
}

#[test]
fn a_good_update_boots_proves_itself_and_raises_the_rollback_floor() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut state = BootState::fresh();
    state.install("b");
    let disk = build_disk(&env, dir.path(), &[good_slot(&env, "a", 1), good_slot(&env, "b", 2)], Some(&state));
    let b = boot(&env, Some(&disk), "");
    assert!(b.has("selected slot=b epoch=2"), "{}", b.dump());
    assert!(b.has("slot b marked successful; rollback floor is now 2"), "{}", b.dump());
    let st = read_state(&env, &disk);
    assert_eq!(st.floor, 2);
    assert!(st.slots.iter().find(|s| s.name == "b").unwrap().successful);
    // The next boot still uses B, and A (epoch 1) is now below the floor and is refused outright.
    let b2 = boot(&env, Some(&disk), "");
    assert!(b2.has("slot=a REFUSED rollback"), "{}", b2.dump());
    assert!(b2.has("selected slot=b"), "{}", b2.dump());
    assert!(b2.has("JLR-STAGE2: ready"), "{}", b2.dump());
}

#[test]
fn missing_media_is_refused() {
    let Some(env) = env() else { return };
    let b = boot(&env, None, "");
    assert_refused_without_running(&b, "no boot media");
}

#[test]
fn media_without_a_jlr_directory_is_not_trusted() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("t");
    fs::create_dir_all(&tree).unwrap();
    fs::write(tree.join("README"), "not a JLR disk").unwrap();
    let img = dir.path().join("d.img");
    assert!(
        Command::new(&env.mke2fs)
            .args(["-q", "-t", "ext4", "-F", "-d"])
            .arg(&tree)
            .arg(&img)
            .arg("16M")
            .status()
            .unwrap()
            .success()
    );
    assert_refused_without_running(&boot(&env, Some(&img), ""), "no boot media");
}

#[test]
fn governance_works_inside_the_verified_ram_base_under_a_real_kernel() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let disk = build_disk(&env, dir.path(), &[good_slot(&env, "a", 1)], None);
    // Run the guest self-test as the payload after stage 2 proves the slot.
    let b = boot(&env, Some(&disk), "jlr.exec=/usr/lib/jlr/guest-test.sh");
    assert!(!b.timed_out, "{}", b.dump());
    for step in [
        "GUEST: uid=0",
        "root_is_ro=1",
        "GUEST: init ok",
        "GUEST: scan ok",
        "GUEST: posture proven",
        "GUEST: cell stdout=hello-from-cell",
        "GUEST: cell decision: OBSERVED in CELL-0 network=NONE",
        "GUEST: in-cell: cell-uid=65534",
        "GUEST: in-cell: state-hidden",
        "GUEST: in-cell: NoNewPrivs: 1",
        "GUEST: in-cell: CapEff: 0000000000000000",
        "GUEST: in-cell: usr-readonly",
        "GUEST: ledger ok",
        "GUEST: done",
    ] {
        assert!(b.has(step), "missing {step:?} in:\n{}", b.dump());
    }
    assert!(!b.has("FAILED"), "{}", b.dump());
}

#[test]
fn the_exec_gate_audits_then_enforces_and_notices_tampering_under_a_real_kernel() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let disk = build_disk(&env, dir.path(), &[good_slot(&env, "a", 1)], None);
    let b = boot(&env, Some(&disk), "jlr.exec=/usr/lib/jlr/guest-gate.sh");
    assert!(!b.timed_out, "{}", b.dump());
    let in_order = [
        "GUEST: init ok",
        "GUEST: baseline initial-host:",
        "GUEST: gate: exec gate active on",
        "GUEST: mode: exec gate audit",
        // Audit: nothing is blocked, but the stranger is recorded.
        "GUEST: audit known: ran",
        "GUEST: audit stranger: ran",
        "GUEST: log: 1 audit line(s) for the stranger",
        "GUEST: enforce on",
        // Enforce: the enrolled binary keeps running, unknown ones are denied by the kernel.
        "GUEST: enforce known: ran",
        "GUEST: enforce stranger: BLOCKED",
        "GUEST: enforce stranger2: BLOCKED",
        "GUEST: enforce system tool: ran",
        // A file the gate cannot measure is denied, and so is anything on a file system mounted later.
        "GUEST: enforce unmeasurable: BLOCKED",
        "GUEST: late mount stranger: BLOCKED",
        "GUEST: remounted stranger: BLOCKED",
        "GUEST: odd name stranger: BLOCKED",
        // Tampering with an enrolled binary revokes its standing.
        "GUEST: tampered known: BLOCKED",
        // A blocked program can still run, confined.
        "GUEST: jlr run: confined-ok",
        "GUEST: jlr run: OBSERVED in CELL-0",
        // When the daemon stops the kernel releases the gate.
        "GUEST: after stop stranger: ran",
        "GUEST: ledger ok",
        "GUEST: done",
    ];
    let mut last = 0usize;
    for step in in_order {
        let pos = b.lines.iter().skip(last).position(|l| l.contains(step)).map(|p| p + last);
        match pos {
            Some(p) => last = p + 1,
            None => panic!("missing (or out of order) {step:?} in:\n{}", b.dump()),
        }
    }
    assert!(b.has("Operation not permitted"), "a denied exec must fail with EPERM:\n{}", b.dump());
}

// ---- adversarial-review follow-ups: several media, read-only media, transient failures ----------------------

/// A state with slot `a` proven at the given floor.
fn proven_state(floor: u64) -> BootState {
    BootState { floor, slots: vec![SlotState { name: "a".into(), priority: 15, tries: 0, successful: true }] }
}

fn file_digest(p: &Path) -> Digest {
    Digest::of(&fs::read(p).unwrap())
}

#[test]
fn filesystem_ids_agree_with_what_mke2fs_writes() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let uuid = "6f1b2c3d-0000-4444-8888-123456789abc";
    let disk = build_named_disk(&env, dir.path(), "id", &[good_slot(&env, "a", 1)], None, Some(uuid));
    let head = fs::read(&disk).unwrap();
    assert_eq!(jlr_boot::media::filesystem_id(&head[..jlr_boot::media::HEAD_LEN]).as_deref(), Some(uuid));
}

#[test]
fn a_second_disk_with_an_older_release_cannot_downgrade_the_machine() {
    let Some(env) = env() else { return };
    // The real medium has proven epoch 2 (floor 2). The other disk carries a validly signed but older public
    // release with no state file, which reads as floor zero when looked at on its own.
    for attacker_first in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let real = build_named_disk(&env, dir.path(), "real", &[good_slot(&env, "a", 2)], Some(&proven_state(2)), None);
        let old = build_named_disk(&env, dir.path(), "old", &[good_slot(&env, "a", 1)], None, None);
        let old_before = file_digest(&old);
        let disks: Vec<(&Path, bool)> =
            if attacker_first { vec![(&old, false), (&real, false)] } else { vec![(&real, false), (&old, false)] };
        let b = boot_disks(&env, &disks, "");
        assert!(!b.timed_out, "{}", b.dump());
        assert!(
            b.has("selected slot=a epoch=2"),
            "the current release must boot (attacker first: {attacker_first}):\n{}",
            b.dump()
        );
        assert!(!b.has("selected slot=a epoch=1"), "an older release booted:\n{}", b.dump());
        assert!(b.has("media=2 rollback floor=2"), "the highest floor on any medium applies:\n{}", b.dump());
        assert!(b.has("examining /dev/vda") && b.has("examining /dev/vdb"), "unpinned, every disk is looked at");
        if attacker_first {
            // The old disk is looked at first and refused on the floor learned from the other one.
            assert!(b.has("slot=a REFUSED rollback"), "the old release is refused as a rollback:\n{}", b.dump());
        }
        assert!(b.has("JLR-STAGE2: ready"), "{}", b.dump());
        assert_eq!(file_digest(&old), old_before, "a disk that held nothing bootable must not be written to");
    }
}

#[test]
fn an_unpinned_boot_says_so_in_the_log() {
    let Some(env) = env() else { return };
    // With no real medium attached there is no floor to consult: this is the residual risk the pin removes, and
    // it must still be visible in the log rather than silent.
    let dir = tempfile::tempdir().unwrap();
    let old = build_named_disk(&env, dir.path(), "old", &[good_slot(&env, "a", 1)], None, None);
    let b = boot(&env, Some(&old), "");
    assert!(b.has("boot media is not pinned"), "the unpinned state must be announced:\n{}", b.dump());
}

#[test]
fn a_pinned_boot_never_uses_or_mounts_another_disk() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let real_uuid = "6f1b2c3d-0000-4444-8888-123456789abc";
    let real =
        build_named_disk(&env, dir.path(), "real", &[good_slot(&env, "a", 2)], Some(&proven_state(2)), Some(real_uuid));
    let other = build_named_disk(
        &env,
        dir.path(),
        "other",
        &[good_slot(&env, "a", 3)],
        None,
        Some("11111111-2222-3333-4444-555555555555"),
    );
    let other_before = file_digest(&other);
    let b = boot_disks(&env, &[(&other, false), (&real, false)], &format!("jlr.media=uuid={real_uuid}"));
    assert!(!b.timed_out, "{}", b.dump());
    assert!(b.has(&format!("boot media is pinned to id={real_uuid}")), "{}", b.dump());
    assert!(b.has("ignoring /dev/vda: not the pinned boot medium"), "{}", b.dump());
    assert!(b.has("media found dev=/dev/vdb"), "{}", b.dump());
    // The other disk carries a *newer*, validly signed release; the pin still keeps it out.
    assert!(b.has("selected slot=a epoch=2") && !b.has("epoch=3"), "{}", b.dump());
    assert!(b.has("JLR-STAGE2: ready"), "{}", b.dump());
    // The boot log says which devices were opened to look for a /jlr tree; the other disk must not be one of them.
    assert!(b.has("examining /dev/vdb for a /jlr tree"), "{}", b.dump());
    assert!(
        !b.has("examining /dev/vda"),
        "the disk that is not the pinned medium must never be mounted:\n{}",
        b.dump()
    );
    assert_eq!(file_digest(&other), other_before, "and it must not have been written");

    // A pin that matches nothing attached is a refusal, never a fall back to whatever is there.
    let b = boot_disks(&env, &[(&other, false), (&real, false)], "jlr.media=uuid=99999999-9999-9999-9999-999999999999");
    assert_refused_without_running(&b, "no boot media");
}

#[test]
fn a_write_protected_medium_boots_its_proven_slot_and_skips_an_unproven_one() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    // B is a fresh, unproven update that would be tried first, which needs a durable "try spent" record.
    let mut state = BootState::fresh();
    state.install("b");
    let disk = build_named_disk(
        &env,
        dir.path(),
        "ro",
        &[good_slot(&env, "a", 1), good_slot(&env, "b", 2)],
        Some(&state),
        None,
    );
    let b = boot_disks(&env, &[(&disk, true)], "");
    assert!(!b.timed_out, "{}", b.dump());
    assert!(b.has("slot=b skipped: cannot record the boot attempt"), "{}", b.dump());
    // The image is read and verified first; only then is the try recorded (and here, refused).
    let (verified, skipped) = (b.pos("image verified slot=b"), b.pos("slot=b skipped: cannot record"));
    assert!(
        verified.is_some() && verified < skipped,
        "a try must not be spent before the image was read:\n{}",
        b.dump()
    );
    assert!(b.has("selected slot=a epoch=1"), "the proven slot must still boot:\n{}", b.dump());
    assert!(!b.has("selected slot=b"), "an update must not run without its try being recorded:\n{}", b.dump());
    assert!(b.has("JLR-STAGE2: ready"), "{}", b.dump());
    // (The drive is attached `readonly=on`, so QEMU itself keeps the image unchanged; what this test shows is what
    // the boot does about a medium it cannot write.)
}

#[test]
fn an_unreadable_boot_state_stops_the_boot_instead_of_resetting_the_floor() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("t");
    fs::create_dir_all(tree.join("jlr/slot-a")).unwrap();
    let slot = good_slot(&env, "a", 1);
    fs::write(tree.join("jlr/slot-a/manifest.cose"), &slot.manifest).unwrap();
    fs::write(tree.join("jlr/slot-a/base.sqfs"), &slot.image).unwrap();
    // A state file that is present but does not parse, as a torn or damaged write leaves it.
    fs::write(tree.join("jlr/bootstate.cbor"), b"\xa1\x01").unwrap();
    let img = dir.path().join("d.img");
    assert!(
        Command::new(&env.mke2fs)
            .args(["-q", "-t", "ext4", "-F", "-d"])
            .arg(&tree)
            .arg(&img)
            .arg("48M")
            .status()
            .unwrap()
            .success()
    );
    let b = boot(&env, Some(&img), "");
    assert_refused_without_running(&b, "boot state of /dev/vda cannot be read");
}

#[test]
fn the_highest_floor_on_any_medium_is_written_to_the_medium_that_boots() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    // The booting disk's release has epoch 6 but a `min_epoch` of only 4, and its own state says floor 0. The other
    // disk recorded floor 5. After the boot proves itself, the booting disk must record 5, not the 4 that its own
    // release would raise it to: the floor that applied to this boot must not be lost from the medium that ran it.
    let image = fs::read(env.out.join("base.sqfs")).unwrap();
    let slot = Slot { name: "a", manifest: manifest(&image, 6, 4, &release_key()), image };
    let booting = build_named_disk(&env, dir.path(), "boot", &[slot], None, None);
    let other = build_named_disk(&env, dir.path(), "other", &[good_slot(&env, "a", 5)], Some(&proven_state(5)), None);
    let b = boot_disks(&env, &[(&booting, false), (&other, false)], "");
    assert!(!b.timed_out, "{}", b.dump());
    assert!(b.has("media=2 rollback floor=5"), "{}", b.dump());
    assert!(b.has("selected slot=a epoch=6"), "{}", b.dump());
    assert!(b.has("slot a marked successful; rollback floor is now 5"), "{}", b.dump());
    assert_eq!(read_state(&env, &booting).floor, 5);
}
