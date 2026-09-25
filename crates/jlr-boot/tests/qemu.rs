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
    let tree = dir.join("disk-tree");
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
    let img = dir.join("disk.img");
    let st = Command::new(&env.mke2fs)
        .args(["-q", "-t", "ext4", "-F", "-d"])
        .arg(&tree)
        .arg(&img)
        .arg("48M")
        .status()
        .unwrap();
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
    if let Some(d) = disk {
        cmd.arg("-drive").arg(format!("file={},format=raw,if=virtio", d.display()));
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
    let sel_b = b.pos("selected slot=b").expect("B is tried first");
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
