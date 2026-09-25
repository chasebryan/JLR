//! The JLR initramfs init.
//!
//! Stage 1 (PID 1 of the initramfs): find boot media, verify each slot's signed
//! manifest against the trust anchors in the initramfs, pick a slot with the
//! A/B rules, copy its base image into RAM while hashing it, mount the RAM
//! copy read-only as the new root, and switch to it. Any failure ends in
//! RECOVERY-RESTRICTED: nothing from the media is executed.
//!
//! Stage 2 (same binary, as `/sbin/init` of the base): run health checks, mark
//! the slot successful, and hand over.
//!
//! Every decision is printed as a `JLR-BOOT:` or `JLR-STAGE2:` line so the
//! result can be checked from the serial console.

#![forbid(unsafe_code)]

use jlr_boot::sys::{loop_attach, poweroff, restart};
use jlr_boot::{BootError, BootState, ReleaseManifest, SlotState, choose, verify_image, verify_manifest};
use jlr_cbor::Cbor;
use jlr_crypto::{Digest, TrustAnchors};
use nix::fcntl::{FcntlArg, SealFlag, fcntl};
use nix::mount::{MsFlags, mount, umount};
use nix::sys::memfd::{MFdFlags, memfd_create};
use nix::unistd::{chdir, chroot};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const ANCHORS: &str = "/etc/jlr/anchors.cbor";
/// Where stage 1 mounts the boot media (inside the initramfs).
const MEDIA: &str = "/mnt/boot";
/// Where stage 2 mounts it again (the base image is read-only; `/run` is tmpfs).
const MEDIA2: &str = "/run/jlr/media";
const NEWROOT: &str = "/newroot";
const HANDOFF: &str = "/run/jlr/boot.env";

fn log(line: &str) {
    println!("JLR-BOOT: {line}");
    let _ = std::io::stdout().flush();
}

fn log2(line: &str) {
    println!("JLR-STAGE2: {line}");
    let _ = std::io::stdout().flush();
}

fn cmdline_flag(key: &str) -> Option<String> {
    let cmdline = fs::read_to_string("/proc/cmdline").ok()?;
    cmdline.split_whitespace().find_map(|t| t.strip_prefix(&format!("{key}=")).map(str::to_owned))
}

/// Ends boot in the restricted recovery state. Nothing from the media has been executed.
fn refuse(reason: &str) -> ! {
    log(&format!("REFUSED reason={reason}"));
    log("state=RECOVERY-RESTRICTED: the base image was not started; boot from independent recovery media");
    match cmdline_flag("jlr.onfail").as_deref() {
        Some("poweroff") => {
            let e = poweroff();
            log(&format!("poweroff failed: {e}"));
        }
        Some("reboot") => {
            std::thread::sleep(Duration::from_secs(10));
            let e = restart();
            log(&format!("reboot failed: {e}"));
        }
        _ => {}
    }
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn mount_pseudo() {
    for (src, dst, fs) in [("proc", "/proc", "proc"), ("sysfs", "/sys", "sysfs"), ("devtmpfs", "/dev", "devtmpfs")] {
        let _ = fs::create_dir_all(dst);
        if let Err(e) = mount(Some(src), dst, Some(fs), MsFlags::empty(), None::<&str>) {
            // devtmpfs may already be mounted by the kernel (CONFIG_DEVTMPFS_MOUNT).
            if e != nix::errno::Errno::EBUSY {
                log(&format!("warning: mount {dst}: {e}"));
            }
        }
    }
}

fn candidate_devices() -> Vec<String> {
    let text = fs::read_to_string("/proc/partitions").unwrap_or_default();
    let mut v: Vec<String> = text
        .lines()
        .skip(2)
        .filter_map(|l| l.split_whitespace().nth(3))
        .filter(|n| !n.starts_with("loop") && !n.starts_with("ram"))
        .map(str::to_owned)
        .collect();
    // Prefer partitions (which end in a digit) over whole disks that hold them.
    v.sort_by_key(|n| std::cmp::Reverse(n.chars().last().is_some_and(|c| c.is_ascii_digit())));
    v
}

/// Mounts the first device that carries a `/jlr` directory and returns its device path and file system.
fn find_media(rw: bool) -> Option<(String, &'static str)> {
    let _ = fs::create_dir_all(MEDIA);
    for _ in 0..50 {
        for name in candidate_devices() {
            let dev = format!("/dev/{name}");
            for fstype in ["ext4", "vfat", "iso9660"] {
                let flags = if rw && fstype != "iso9660" {
                    MsFlags::MS_NOSUID | MsFlags::MS_NODEV
                } else {
                    MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV
                };
                if mount(Some(dev.as_str()), MEDIA, Some(fstype), flags, None::<&str>).is_ok() {
                    if Path::new(&format!("{MEDIA}/jlr")).is_dir() {
                        return Some((dev, fstype));
                    }
                    let _ = umount(MEDIA);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn write_state(media: &str, state: &BootState) -> Result<(), String> {
    let path = format!("{media}/jlr/bootstate.cbor");
    let tmp = format!("{path}.new");
    let mut f = File::create(&tmp).map_err(|e| e.to_string())?;
    f.write_all(&state.to_cbor()).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    File::open(format!("{media}/jlr")).and_then(|d| d.sync_all()).map_err(|e| e.to_string())
}

fn read_state(media: &str) -> BootState {
    match fs::read(format!("{media}/jlr/bootstate.cbor")) {
        Ok(b) => match BootState::from_cbor(&b) {
            Ok(s) => s,
            Err(e) => refuse(&format!("boot state is damaged: {e}")),
        },
        Err(_) => BootState {
            floor: 0,
            slots: vec![SlotState { name: "a".into(), priority: 15, tries: 0, successful: true }],
        },
    }
}

fn stage1() -> ! {
    log("start assurance=prototype (no Secure Boot or TPM anchor: the initramfs itself is not authenticated)");
    mount_pseudo();

    let anchors = match fs::read(ANCHORS)
        .map_err(|e| e.to_string())
        .and_then(|b| TrustAnchors::from_cbor(&b).map_err(|e| e.to_string()))
    {
        Ok(a) if !a.is_empty() => a,
        Ok(_) => refuse("no trust anchors in the initramfs"),
        Err(e) => refuse(&format!("cannot load trust anchors: {e}")),
    };
    log(&format!("anchors loaded keys={}", anchors.len()));

    let Some((dev, fstype)) = find_media(true) else { refuse("no boot media with a /jlr directory was found") };
    log(&format!("media found dev={dev} fs={fstype}"));
    let mut state = read_state(MEDIA);
    log(&format!("state floor={} slots={}", state.floor, state.slots.len()));

    // Verify every slot's manifest first; image hashing happens only for the chosen slot.
    let mut verified: Vec<(String, ReleaseManifest, Vec<u8>)> = Vec::new();
    for s in state.slots.clone() {
        let path = format!("{MEDIA}/jlr/slot-{}/manifest.cose", s.name);
        match fs::read(&path) {
            Err(e) => log(&format!("slot={} manifest unreadable: {e}", s.name)),
            Ok(bytes) => match verify_manifest(&bytes, &anchors, state.floor) {
                Ok(m) => {
                    log(&format!(
                        "slot={} manifest=verified version={} epoch={} manifest_sha256={}",
                        s.name,
                        m.version,
                        m.epoch,
                        Digest::of(&bytes).hex()
                    ));
                    verified.push((s.name.clone(), m, bytes));
                }
                Err(e @ BootError::Rollback { .. }) => log(&format!("slot={} REFUSED rollback: {e}", s.name)),
                Err(e) => log(&format!("slot={} REFUSED: {e}", s.name)),
            },
        }
    }

    // Try slots in the A/B order until one verifies end to end.
    let (slot, manifest, manifest_bytes, backing) = loop {
        let list: Vec<(String, ReleaseManifest)> = verified.iter().map(|(n, m, _)| (n.clone(), m.clone())).collect();
        let choice = match choose(&state, &list) {
            Ok(c) => c,
            Err(_) => refuse("no slot passed verification with tries remaining"),
        };
        // The try is spent durably BEFORE the slot is used: a crash from here on falls back next boot.
        state = choice.next;
        if let Err(e) = write_state(MEDIA, &state) {
            refuse(&format!("cannot record the boot attempt: {e}"));
        }
        let (_, m, mb) = verified.iter().find(|(n, _, _)| *n == choice.slot).cloned().expect("chosen slot is verified");
        log(&format!("selected slot={} epoch={}", choice.slot, m.epoch));

        let image_path = format!("{MEDIA}/jlr/slot-{}/base.sqfs", choice.slot);
        let mem = match memfd_create("jlr-base", MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING) {
            Ok(fd) => File::from(fd),
            Err(e) => refuse(&format!("cannot allocate RAM for the base image: {e}")),
        };
        let mut sink = mem;
        let result = File::open(&image_path)
            .map_err(|e| BootError::Io(format!("{image_path}: {e}")))
            .and_then(|mut src| verify_image(&m, &mut src, &mut sink));
        match result {
            Ok(n) => {
                log(&format!(
                    "image verified slot={} bytes={n} sha256={} (now resident in RAM)",
                    choice.slot,
                    m.image_digest.hex()
                ));
                if let Err(e) = fcntl(
                    &sink,
                    FcntlArg::F_ADD_SEALS(
                        SealFlag::F_SEAL_SEAL
                            | SealFlag::F_SEAL_SHRINK
                            | SealFlag::F_SEAL_GROW
                            | SealFlag::F_SEAL_WRITE,
                    ),
                ) {
                    refuse(&format!("cannot seal the RAM image: {e}"));
                }
                break (choice.slot, m, mb, sink);
            }
            Err(e) => {
                log(&format!("slot={} REFUSED image: {e}", choice.slot));
                state.mark_bad(&choice.slot);
                let _ = write_state(MEDIA, &state);
                verified.retain(|(n, _, _)| *n != choice.slot);
                // The memfd is dropped here, discarding the unverified bytes.
            }
        }
    };

    let loopdev = match loop_attach(&backing) {
        Ok(d) => d,
        Err(e) => refuse(&format!("cannot attach the RAM image to a loop device: {e}")),
    };
    let _ = fs::create_dir_all(NEWROOT);
    if let Err(e) = mount(
        Some(loopdev.as_str()),
        NEWROOT,
        Some("squashfs"),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None::<&str>,
    ) {
        refuse(&format!("cannot mount the verified image: {e}"));
    }
    log(&format!("base mounted read-only from RAM at {NEWROOT} via {loopdev}"));

    // The base needs somewhere to write, and stage 2 needs to know how to mark success.
    for d in ["run", "tmp"] {
        let _ = mount(
            Some("tmpfs"),
            format!("{NEWROOT}/{d}").as_str(),
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("mode=0755,size=64m"),
        );
    }
    let _ = fs::create_dir_all(format!("{NEWROOT}/run/jlr"));
    let env = format!("slot={slot}\nmedia_dev={dev}\nmedia_fs={fstype}\nfloor={}\n", state.floor);
    let _ = fs::write(format!("{NEWROOT}{HANDOFF}"), env);
    let _ = fs::write(format!("{NEWROOT}/run/jlr/manifest.cose"), &manifest_bytes);
    let _ = fs::write(format!("{NEWROOT}/run/jlr/anchors.cbor"), fs::read(ANCHORS).unwrap_or_default());

    // The media is no longer needed: the base lives in RAM.
    let _ = umount(MEDIA);
    log(&format!("boot media released; running {} {} from RAM", manifest.name, manifest.version));

    for d in ["proc", "sys", "dev"] {
        let _ = fs::create_dir_all(format!("{NEWROOT}/{d}"));
        if let Err(e) = mount(
            Some(format!("/{d}").as_str()),
            format!("{NEWROOT}/{d}").as_str(),
            None::<&str>,
            MsFlags::MS_MOVE,
            None::<&str>,
        ) {
            log(&format!("warning: move /{d}: {e}"));
        }
    }
    log("switching root");
    // Keep the loop device's backing file open across the switch: leak the descriptor on purpose.
    std::mem::forget(backing);
    if chdir(NEWROOT).is_err()
        || mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>).is_err()
        || chroot(".").is_err()
        || chdir("/").is_err()
    {
        refuse("switch_root failed");
    }
    let err = Command::new("/sbin/init").arg0("init").exec();
    refuse(&format!("cannot execute /sbin/init in the verified base: {err}"));
}

fn env_value(key: &str) -> Option<String> {
    fs::read_to_string(HANDOFF).ok()?.lines().find_map(|l| l.strip_prefix(&format!("{key}=")).map(str::to_owned))
}

fn stage2() -> ! {
    let slot = env_value("slot").unwrap_or_default();
    log2(&format!("running from the verified RAM base slot={slot}"));

    // Health checks. Each one failing keeps the slot unproven, so the next boot falls back.
    let mut healthy = true;
    let mut check = |name: &str, ok: bool| {
        log2(&format!("check {name}: {}", if ok { "ok" } else { "FAILED" }));
        healthy &= ok;
    };
    check("root is read-only", File::create("/jlr-write-test").is_err());
    check("run is writable and memory backed", fs::write("/run/jlr/health", b"ok").is_ok());
    check("verified manifest present", Path::new("/run/jlr/manifest.cose").exists());
    check(
        "jlr tools present",
        Path::new("/usr/bin/jlr").exists()
            || Path::new("/usr/bin/jlr-release").exists()
            || Path::new("/bin/busybox").exists(),
    );

    if !healthy {
        log2("unhealthy: slot stays unproven and will fall back after its remaining tries");
        std::thread::sleep(Duration::from_secs(1));
        if cmdline_flag("jlr.test").as_deref() == Some("poweroff")
            || cmdline_flag("jlr.onfail").as_deref() == Some("poweroff")
        {
            let _ = poweroff();
        }
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    // Prove the slot: mark it successful and raise the rollback floor.
    let dev = env_value("media_dev").unwrap_or_default();
    let fstype = env_value("media_fs").unwrap_or_default();
    let anchors = fs::read("/run/jlr/anchors.cbor").ok().and_then(|b| TrustAnchors::from_cbor(&b).ok());
    let manifest_bytes = fs::read("/run/jlr/manifest.cose").unwrap_or_default();
    if let Some(anchors) = anchors
        && let Ok(m) = verify_manifest(&manifest_bytes, &anchors, 0)
    {
        let _ = fs::create_dir_all(MEDIA2);
        match mount(
            Some(dev.as_str()),
            MEDIA2,
            Some(fstype.as_str()),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            None::<&str>,
        ) {
            Ok(()) => {
                let mut state = read_state(MEDIA2);
                state.mark_successful(&slot, &m);
                match write_state(MEDIA2, &state) {
                    Ok(()) => log2(&format!("slot {slot} marked successful; rollback floor is now {}", state.floor)),
                    Err(e) => log2(&format!("could not record success: {e}")),
                }
                let _ = umount(MEDIA2);
            }
            Err(e) => log2(&format!("could not remount the media to record success: {e}")),
        }
    }

    log2("ready");
    // A payload runs as a child so that PID 1 stays alive; its status is reported, then any
    // requested power-off follows.
    if let Some(exec) = cmdline_flag("jlr.exec") {
        match Command::new(&exec).status() {
            Ok(st) => log2(&format!("payload {exec} exited with {st}")),
            Err(e) => log2(&format!("cannot execute {exec}: {e}")),
        }
    }
    if cmdline_flag("jlr.test").as_deref() == Some("poweroff") {
        let e = poweroff();
        log2(&format!("poweroff failed: {e}"));
    }
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn main() {
    // In the initramfs there is no /run/jlr/boot.env yet; in the verified base there is.
    if Path::new(HANDOFF).exists() {
        stage2();
    }
    stage1();
}
