//! The in-cell helper.
//!
//! `jlr-cell-init stage1 <spec>` runs single-threaded in a fresh process. It
//! unshares the namespaces and starts `stage2` as a child; because it
//! `unshare`d the PID namespace first, that child is PID 1 of the new
//! namespace and can mount a matching `/proc`. Stage 2 builds the private
//! root, applies every control, writes the [`EnforcementReport`] to the
//! parent, and only then `exec`s the sealed program. If a mandatory control
//! is missing, stage 2 reports `Refused` and exits without running anything.
//!
//! Inherited descriptors: 3 is the sealed executable, 4 is the report pipe.

use crate::landlock_rules::{LandlockPlan, apply as apply_landlock};
use crate::seccomp;
use crate::spec::{CellSpec, Control, EnforcementReport, Status};
use crate::sys;
use jlr_cbor::Cbor;
use jlr_model::{Capability, NetworkMode};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, unshare};
use nix::sys::resource::{Resource, setrlimit};
use nix::sys::signal::Signal;
use nix::sys::statvfs::{FsFlags, statvfs};
use nix::unistd::{chdir, pivot_root, sethostname};
use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const EXE_FD: i32 = 3;
const REPORT_FD: i32 = 4;
/// Exit status when the cell could not be established.
const EXIT_REFUSED: i32 = 126;
/// Exit status when `exec` of the workload failed.
const EXIT_EXEC: i32 = 127;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Encodes a spec for the helper's command line.
pub(crate) fn encode_spec(spec: &CellSpec) -> String {
    hex(&spec.to_cbor())
}

/// Accumulates what was and was not established.
struct Builder {
    spec: CellSpec,
    active: Vec<Control>,
    unavailable: Vec<(Control, String)>,
    landlock_abi: Option<u32>,
    seccomp_denied: u32,
    /// Capability grants that could not be applied (missing path, hidden path). They make the report Partial.
    skipped: Vec<String>,
}

impl Builder {
    fn new(spec: CellSpec) -> Self {
        Builder {
            spec,
            active: Vec::new(),
            unavailable: Vec::new(),
            // The kernel's Landlock ABI is a fact about the machine, so every report carries it, including a
            // refusal that happens before Landlock is applied.
            landlock_abi: sys::landlock_abi(),
            seccomp_denied: 0,
            skipped: Vec::new(),
        }
    }

    fn ok(&mut self, c: Control) {
        if !self.active.contains(&c) {
            self.active.push(c);
        }
    }

    fn fail(&mut self, c: Control, why: impl Into<String>) {
        self.unavailable.push((c, why.into()));
    }

    fn finish(&self) -> EnforcementReport {
        let requested = self.spec.requested_controls();
        let mut missing_mandatory = Vec::new();
        for m in self.spec.mandatory_controls() {
            if !self.active.contains(&m) {
                missing_mandatory.push(m.as_str().to_owned());
            }
        }
        let mut unavailable: Vec<String> = self.unavailable.iter().map(|(c, w)| format!("{c}: {w}")).collect();
        for c in &requested {
            if !self.active.contains(c) && !self.unavailable.iter().any(|(u, _)| u == c) {
                unavailable.push(format!("{c}: not established"));
            }
        }
        unavailable.extend(self.skipped.iter().map(|s| format!("capability: {s}")));
        let all_requested_active = requested.iter().all(|c| self.active.contains(c)) && self.skipped.is_empty();
        let status = if !missing_mandatory.is_empty() {
            Status::Refused
        } else if all_requested_active {
            Status::Full
        } else {
            Status::Partial
        };
        let mut active: Vec<Control> = self.active.clone();
        active.sort();
        EnforcementReport {
            kernel: sys::kernel_release(),
            requested: requested.iter().map(|c| c.as_str().to_owned()).collect(),
            active: active.iter().map(|c| c.as_str().to_owned()).collect(),
            unavailable,
            mandatory_missing: missing_mandatory,
            status,
            landlock_abi: self.landlock_abi,
            seccomp_denied: self.seccomp_denied,
        }
    }
}

/// Writes a length-prefixed report to the parent.
fn send_report(r: &EnforcementReport) {
    // SAFETY: descriptor 4 is the report pipe the parent placed here for us; nothing else uses it.
    #[allow(unsafe_code)]
    let fd = match unsafe { sys::adopt_fd(REPORT_FD) } {
        Ok(fd) => fd,
        Err(_) => return,
    };
    let body = r.to_cbor();
    let mut f = std::fs::File::from(fd);
    let mut msg = (body.len() as u32).to_be_bytes().to_vec();
    msg.extend_from_slice(&body);
    let _ = f.write_all(&msg);
}

fn refuse(mut b: Builder, why: &str) -> i32 {
    b.unavailable.push((Control::MountNs, why.to_owned()));
    let mut r = b.finish();
    r.status = Status::Refused;
    if r.mandatory_missing.is_empty() {
        r.mandatory_missing.push("setup".into());
    }
    send_report(&r);
    eprintln!("jlr-cell: {why}");
    EXIT_REFUSED
}

// ---------------------------------------------------------------------------
// Stage 1
// ---------------------------------------------------------------------------

fn stage1(spec: CellSpec, spec_hex: &str) -> i32 {
    // Only descriptors 0-2 (the workload's standard streams), 3 (the sealed program) and 4 (the report pipe) may
    // cross into the cell. Anything else the caller left open is closed before anything else happens.
    sys::close_from(REPORT_FD + 1);
    let _ = nix::sys::prctl::set_pdeathsig(Signal::SIGKILL);
    // A new session removes the caller's controlling terminal. Without this the workload can use terminal
    // ioctls on a shared tty (TIOCSTI types into the operator's shell after the cell exits).
    if let Err(e) = nix::unistd::setsid() {
        return refuse(Builder::new(spec), &format!("cannot detach from the controlling terminal: {e}"));
    }
    let (euid, egid) = sys::effective_ids();
    let use_userns = euid != 0;
    let netns = matches!(spec.network, NetworkMode::None | NetworkMode::LoopbackOnly);

    let mut flags =
        CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWUTS;
    if netns {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    if use_userns {
        flags |= CloneFlags::CLONE_NEWUSER;
    }
    let mut b = Builder::new(spec.clone());
    if let Err(e) = unshare(flags) {
        for c in [Control::UserNs, Control::MountNs, Control::PidNs, Control::IpcNs, Control::UtsNs, Control::NetNs] {
            b.fail(c, format!("unshare: {e}"));
        }
        return refuse(b, &format!("cannot create namespaces: {e}"));
    }
    if use_userns {
        let write = |path: &str, content: String| fs::write(path, content);
        let r = write("/proc/self/setgroups", "deny".into())
            .and_then(|()| write("/proc/self/uid_map", format!("0 {euid} 1")))
            .and_then(|()| write("/proc/self/gid_map", format!("0 {egid} 1")));
        if let Err(e) = r {
            b.fail(Control::UserNs, format!("id mapping: {e}"));
            return refuse(b, &format!("cannot map ids: {e}"));
        }
    }

    let cgroup_name = format!("jlr-cell-{}", std::process::id());
    let ns_note = format!("{}{}", if use_userns { "u" } else { "-" }, if netns { "n" } else { "-" });
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return refuse(b, &format!("cannot locate helper: {e}")),
    };
    let mut child = match Command::new(exe).arg("stage2").arg(spec_hex).arg(&ns_note).arg(&cgroup_name).spawn() {
        Ok(c) => c,
        Err(e) => return refuse(b, &format!("cannot start stage 2: {e}")),
    };

    let deadline = spec.wall_secs.map(|s| Instant::now() + Duration::from_secs(s));
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {}
            Err(_) => return EXIT_REFUSED,
        }
        if let Some(d) = deadline
            && Instant::now() >= d
        {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("jlr-cell: wall-clock limit reached; cell killed");
            return 137;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    cleanup_cgroup(&cgroup_name);
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(c), _) => c,
        (None, Some(s)) => 128 + s,
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// cgroup v2 (best effort)
// ---------------------------------------------------------------------------

fn own_cgroup_dir() -> Result<std::path::PathBuf, String> {
    let text = fs::read_to_string("/proc/self/cgroup").map_err(|e| e.to_string())?;
    let path = text.lines().find_map(|l| l.strip_prefix("0::")).ok_or("cgroup v2 is not in use")?;
    Ok(Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
}

fn setup_cgroup(spec: &CellSpec, name: &str) -> Result<(), String> {
    let dir = own_cgroup_dir()?.join(name);
    fs::create_dir(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let put = |file: &str, v: String| fs::write(dir.join(file), v).map_err(|e| format!("{file}: {e}"));
    if let Some(m) = spec.memory_bytes {
        put("memory.max", m.to_string())?;
        let _ = put("memory.swap.max", "0".into());
    }
    if let Some(p) = spec.pids_max {
        put("pids.max", p.to_string())?;
    }
    put("cgroup.procs", "0".into())
}

fn cleanup_cgroup(name: &str) {
    if let Ok(dir) = own_cgroup_dir() {
        let _ = fs::remove_dir(dir.join(name));
    }
}

// ---------------------------------------------------------------------------
// Stage 2: private root
// ---------------------------------------------------------------------------

struct Layout {
    read: Vec<String>,
    write: Vec<String>,
    /// Grants that were not applied, with the reason.
    skipped: Vec<String>,
}

/// Picks the directory the private root is assembled in. The tmpfs mounted there hides whatever was below it
/// in this mount namespace, so it must not be, or contain, any path a capability grants.
fn assembly_dir(spec: &CellSpec) -> Result<&'static str, String> {
    let granted: Vec<&str> = spec
        .capabilities
        .iter()
        .filter_map(|c| match c {
            Capability::FsRead(p) | Capability::FsWrite(p) => Some(p.as_str()),
            _ => None,
        })
        .collect();
    let overlaps = |dir: &str, p: &str| {
        // `/` contains every path, and `strip_prefix("/")` leaves a remainder that does not start with a slash.
        let within = |a: &str, b: &str| b == "/" || a == b || a.strip_prefix(b).is_some_and(|r| r.starts_with('/'));
        within(p, dir) || within(dir, p)
    };
    ["/tmp", "/mnt", "/media", "/srv", "/opt", "/run"]
        .into_iter()
        .find(|d| fs::metadata(d).is_ok_and(|m| m.is_dir()) && !granted.iter().any(|p| overlaps(d, p)))
        .ok_or_else(|| "no directory is free to assemble the private root in (every candidate overlaps a grant)".into())
}

fn none() -> Option<&'static str> {
    None
}

fn bind_flags(src: &str) -> MsFlags {
    let mut f = MsFlags::empty();
    if let Ok(v) = statvfs(src) {
        let s = v.flags();
        if s.contains(FsFlags::ST_NOSUID) {
            f |= MsFlags::MS_NOSUID;
        }
        if s.contains(FsFlags::ST_NODEV) {
            f |= MsFlags::MS_NODEV;
        }
        if s.contains(FsFlags::ST_NOEXEC) {
            f |= MsFlags::MS_NOEXEC;
        }
        if s.contains(FsFlags::ST_NOATIME) {
            f |= MsFlags::MS_NOATIME;
        }
        if s.contains(FsFlags::ST_NODIRATIME) {
            f |= MsFlags::MS_NODIRATIME;
        }
        // ST_RELATIME is 0x1000 on Linux but is not exported for every libc target.
        if s.bits() & 0x1000 != 0 {
            f |= MsFlags::MS_RELATIME;
        }
    }
    f
}

/// Creates `dst` to match `src` (a directory or a file) so it can be a mount point.
fn make_target(src: &str, dst: &str) -> Result<(), String> {
    let meta = fs::metadata(src).map_err(|e| format!("{src}: {e}"))?;
    if meta.is_dir() {
        fs::create_dir_all(dst).map_err(|e| format!("{dst}: {e}"))
    } else {
        if let Some(parent) = Path::new(dst).parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        fs::File::create(dst).map(drop).map_err(|e| format!("{dst}: {e}"))
    }
}

/// Bind-mounts `src` at `dst`. Read-only binds are non-recursive with the
/// source's own locked flags preserved, which an unprivileged remount requires.
fn bind(src: &str, dst: &str, read_only: bool) -> Result<(), String> {
    make_target(src, dst)?;
    let recursive = if read_only { MsFlags::empty() } else { MsFlags::MS_REC };
    mount(Some(src), dst, none(), MsFlags::MS_BIND | recursive, none()).map_err(|e| format!("bind {src}: {e}"))?;
    if read_only {
        let flags = MsFlags::MS_BIND
            | MsFlags::MS_REMOUNT
            | MsFlags::MS_RDONLY
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NODEV
            | bind_flags(src);
        mount(none(), dst, none(), flags, none()).map_err(|e| format!("remount ro {src}: {e}"))?;
    }
    Ok(())
}

fn tmpfs(dst: &str, opts: &str, extra: MsFlags) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("{dst}: {e}"))?;
    mount(Some("tmpfs"), dst, Some("tmpfs"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV | extra, Some(opts))
        .map_err(|e| format!("tmpfs {dst}: {e}"))
}

fn build_root(spec: &CellSpec) -> Result<Layout, String> {
    mount(none(), "/", none(), MsFlags::MS_REC | MsFlags::MS_PRIVATE, none())
        .map_err(|e| format!("make / private: {e}"))?;
    // The private root is assembled on a tmpfs that is only visible in this mount namespace.
    let nr = assembly_dir(spec)?;
    tmpfs(nr, "mode=0755,size=4m", MsFlags::MS_NOEXEC)?;
    for d in ["usr", "etc", "dev", "proc", "tmp", "run", ".old"] {
        fs::create_dir_all(format!("{nr}/{d}")).map_err(|e| format!("mkdir {d}: {e}"))?;
    }

    // Merged-usr layout: recreate host symlinks, or bind real directories.
    for d in ["bin", "sbin", "lib", "lib32", "lib64", "libx32"] {
        let host = format!("/{d}");
        match fs::symlink_metadata(&host) {
            Ok(m) if m.file_type().is_symlink() => {
                let target = fs::read_link(&host).map_err(|e| e.to_string())?;
                symlink(&target, format!("{nr}/{d}")).map_err(|e| format!("symlink {d}: {e}"))?;
            }
            Ok(m) if m.is_dir() => bind(&host, &format!("{nr}/{d}"), true)?,
            _ => {}
        }
    }
    bind("/usr", &format!("{nr}/usr"), true)?;

    let networked = !matches!(spec.network, NetworkMode::None | NetworkMode::LoopbackOnly);
    let mut etc = vec![
        "ld.so.cache",
        "ld.so.conf",
        "ld.so.conf.d",
        "passwd",
        "group",
        "nsswitch.conf",
        "localtime",
        "alternatives",
    ];
    if networked {
        etc.extend(["resolv.conf", "hosts", "ssl", "ca-certificates", "ca-certificates.conf"]);
    }
    for f in etc {
        let src = format!("/etc/{f}");
        if fs::metadata(&src).is_ok() {
            bind(&src, &format!("{nr}/etc/{f}"), true)?;
        }
    }

    // /dev with only the harmless character devices.
    tmpfs(&format!("{nr}/dev"), "mode=0755,size=64k", MsFlags::MS_NOEXEC)?;
    for d in ["null", "zero", "full", "random", "urandom"] {
        bind(&format!("/dev/{d}"), &format!("{nr}/dev/{d}"), false)?;
    }
    for (link, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        symlink(target, format!("{nr}/dev/{link}")).map_err(|e| format!("dev/{link}: {e}"))?;
    }
    tmpfs(&format!("{nr}/dev/shm"), "mode=1777,size=16m", MsFlags::MS_NOEXEC)?;

    mount(
        Some("proc"),
        format!("{nr}/proc").as_str(),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        none(),
    )
    .map_err(|e| format!("mount /proc: {e}"))?;
    tmpfs(&format!("{nr}/tmp"), &format!("mode=1777,size={}m", spec.tmp_mib), MsFlags::MS_NOEXEC)?;
    tmpfs(&format!("{nr}/run"), "mode=0755,size=4m", MsFlags::MS_NOEXEC)?;

    // Paths granted by capabilities (never for CELL-0, which has none).
    let mut layout = Layout { read: Vec::new(), write: Vec::new(), skipped: Vec::new() };
    for c in &spec.capabilities {
        match c {
            Capability::FsRead(p) | Capability::FsWrite(p) => {
                // Paths were validated (absolute, normalised) when the spec was decoded, so what can go wrong
                // here is the world: the path does not exist, or cannot be examined.
                let write = matches!(c, Capability::FsWrite(_));
                if let Err(e) = fs::metadata(p) {
                    layout.skipped.push(format!("{c} not applied: {e}"));
                } else {
                    bind(p, &format!("{nr}{p}"), !write)?;
                    if write { layout.write.push(p.clone()) } else { layout.read.push(p.clone()) }
                }
            }
            _ => {}
        }
    }

    pivot_root(nr, format!("{nr}/.old").as_str()).map_err(|e| format!("pivot_root: {e}"))?;
    chdir("/").map_err(|e| format!("chdir: {e}"))?;
    umount2("/.old", MntFlags::MNT_DETACH).map_err(|e| format!("umount old root: {e}"))?;
    fs::remove_dir("/.old").map_err(|e| format!("rmdir old root: {e}"))?;
    mount(
        none(),
        "/",
        none(),
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        none(),
    )
    .map_err(|e| format!("remount / read-only: {e}"))?;

    layout.read.extend(
        ["/usr", "/etc", "/proc", "/dev", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"].map(String::from),
    );
    layout.write.extend(
        ["/tmp", "/dev/shm", "/run", "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"]
            .map(String::from),
    );
    Ok(layout)
}

/// Unprivileged identity used for workloads when the launcher itself is root.
const NOBODY: u32 = 65534;

/// Drops every capability. When `switch_to_nobody` is set (real root, no user
/// namespace), the workload is also moved to an unprivileged uid, so it
/// cannot use root's file permissions on any path it can reach.
///
/// Order matters: the bounding set can only be edited while `CAP_SETPCAP` is
/// still held, and changing uid from 0 clears the effective set.
fn drop_capabilities(switch_to_nobody: bool) -> Result<(), String> {
    use caps::{CapSet, Capability};
    for cap in caps::all() {
        // A capability that does not exist on this kernel cannot be dropped; that is fine.
        let _ = caps::drop(None, CapSet::Bounding, cap);
    }
    if switch_to_nobody {
        use nix::unistd::{Gid, Uid, setgroups, setresgid, setresuid};
        setgroups(&[]).map_err(|e| format!("setgroups: {e}"))?;
        setresgid(Gid::from_raw(NOBODY), Gid::from_raw(NOBODY), Gid::from_raw(NOBODY))
            .map_err(|e| format!("setresgid: {e}"))?;
        setresuid(Uid::from_raw(NOBODY), Uid::from_raw(NOBODY), Uid::from_raw(NOBODY))
            .map_err(|e| format!("setresuid: {e}"))?;
        // Changing uid makes the process non-dumpable, which would hide /proc/self from it
        // (and from `exec` of a script through /proc/self/fd).
        let _ = nix::sys::prctl::set_dumpable(true);
    }
    for set in [CapSet::Effective, CapSet::Permitted, CapSet::Inheritable, CapSet::Ambient] {
        caps::clear(None, set).map_err(|e| format!("clear {set:?}: {e}"))?;
    }
    // Verify rather than assume.
    for cap in
        [Capability::CAP_SYS_ADMIN, Capability::CAP_NET_ADMIN, Capability::CAP_SYS_PTRACE, Capability::CAP_SETUID]
    {
        if caps::has_cap(None, CapSet::Effective, cap).unwrap_or(true)
            || caps::has_cap(None, CapSet::Bounding, cap).unwrap_or(true)
        {
            return Err(format!("{cap:?} is still held"));
        }
    }
    Ok(())
}

fn ports(spec: &CellSpec) -> (Vec<u16>, Vec<u16>) {
    let mut connect = Vec::new();
    let mut bind = Vec::new();
    for c in &spec.capabilities {
        match c {
            Capability::NetConnect(_, p) => connect.push(*p),
            Capability::NetListen(_, p) => bind.push(*p),
            _ => {}
        }
    }
    (connect, bind)
}

fn stage2(spec: CellSpec, ns_note: &str, cgroup_name: &str) -> i32 {
    let mut b = Builder::new(spec.clone());
    let _ = nix::sys::prctl::set_pdeathsig(Signal::SIGKILL);

    // Namespaces were established by stage 1; being PID 1 here confirms the PID namespace.
    let (used_userns, used_netns) = (ns_note.starts_with('u'), ns_note.ends_with('n'));
    if used_userns {
        b.ok(Control::UserNs);
    }
    b.ok(Control::IpcNs);
    b.ok(Control::UtsNs);
    if std::process::id() == 1 {
        b.ok(Control::PidNs);
    } else {
        b.fail(Control::PidNs, "helper is not PID 1 of a new namespace");
    }
    if used_netns {
        b.ok(Control::NetNs);
        if spec.network == NetworkMode::LoopbackOnly
            && let Err(e) = sys::loopback_up()
        {
            eprintln!("jlr-cell: loopback could not be brought up: {e}");
        }
    }

    match nix::sys::prctl::set_no_new_privs() {
        Ok(()) => b.ok(Control::NoNewPrivs),
        Err(e) => b.fail(Control::NoNewPrivs, e.to_string()),
    }
    if let Err(e) = sethostname(&spec.hostname) {
        b.fail(Control::UtsNs, format!("sethostname: {e}"));
    }

    // cgroup limits must be arranged before the root is replaced, while /sys is still visible.
    if spec.memory_bytes.is_some() || spec.pids_max.is_some() {
        match setup_cgroup(&spec, cgroup_name) {
            Ok(()) => b.ok(Control::Cgroup),
            Err(e) => b.fail(Control::Cgroup, e),
        }
    }

    let layout = match build_root(&spec) {
        Ok(l) => {
            b.ok(Control::MountNs);
            b.skipped.extend(l.skipped.iter().cloned());
            l
        }
        Err(e) => {
            b.fail(Control::MountNs, e.clone());
            let r = b.finish();
            send_report(&r);
            eprintln!("jlr-cell: cannot build private root: {e}");
            return EXIT_REFUSED;
        }
    };

    // Resource limits.
    let mut rl_ok = true;
    let mut lim = |res: Resource, v: u64| {
        if setrlimit(res, v, v).is_err() {
            rl_ok = false;
        }
    };
    lim(Resource::RLIMIT_CORE, 0);
    if let Some(n) = spec.nofile {
        lim(Resource::RLIMIT_NOFILE, n);
    }
    if let Some(s) = spec.cpu_secs {
        lim(Resource::RLIMIT_CPU, s);
    }
    if rl_ok {
        b.ok(Control::Rlimits);
    } else {
        b.fail(Control::Rlimits, "setrlimit failed");
    }

    // Landlock.
    let (connect, bind_ports) = ports(&spec);
    let plan = LandlockPlan {
        write: &layout.write,
        tcp: (spec.network == NetworkMode::DestinationAllowlist).then_some((connect.as_slice(), bind_ports.as_slice())),
    };
    match apply_landlock(&plan) {
        Ok(o) => {
            if o.fs {
                b.ok(Control::LandlockFs);
            } else {
                b.fail(Control::LandlockFs, "kernel does not enforce Landlock");
            }
            if plan.tcp.is_some() {
                if o.net {
                    b.ok(Control::LandlockNet);
                } else {
                    b.fail(
                        Control::LandlockNet,
                        match b.landlock_abi {
                            Some(v) if v >= 4 => format!("TCP rules were not fully enforced (kernel ABI {v})"),
                            Some(v) => format!("kernel Landlock ABI {v} has no TCP rules (needs 4)"),
                            None => "Landlock is not available".into(),
                        },
                    );
                }
            }
        }
        Err(e) => {
            b.fail(Control::LandlockFs, e.clone());
            if plan.tcp.is_some() {
                b.fail(Control::LandlockNet, e);
            }
        }
    }

    match drop_capabilities(!used_userns) {
        Ok(()) => b.ok(Control::CapDrop),
        Err(e) => b.fail(Control::CapDrop, e),
    }

    match seccomp::cell_filters().and_then(|f| {
        b.seccomp_denied = f.denied;
        seccomp::install(&f)
    }) {
        Ok(()) => b.ok(Control::Seccomp),
        Err(e) => b.fail(Control::Seccomp, e),
    }

    let report = b.finish();
    send_report(&report);
    if report.status == Status::Refused {
        eprintln!("jlr-cell: refusing to start: mandatory controls missing: {}", report.mandatory_missing.join(", "));
        return EXIT_REFUSED;
    }

    // Descriptor 4 was closed when the report was sent; sweep anything else opened during setup. Descriptor 3
    // stays: it is the sealed program, and a script's interpreter opens it through /proc/self/fd/3.
    sys::close_from(REPORT_FD);
    let _ = chdir("/tmp");
    let mut argv = spec.argv.iter();
    let name = argv.next().cloned().unwrap_or_else(|| "cell".into());
    let mut cmd = Command::new(format!("/proc/self/fd/{EXE_FD}"));
    cmd.arg0(&name).args(argv).env_clear();
    for kv in &spec.env {
        if let Some((k, v)) = kv.split_once('=') {
            cmd.env(k, v);
        }
    }
    let err = cmd.exec();
    eprintln!("jlr-cell: exec failed: {err}");
    EXIT_EXEC
}

/// Entry point of the `jlr-cell-init` binary. Returns the process exit status.
pub fn cell_main() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    let (Some(stage), Some(spec_hex)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: jlr-cell-init stage1|stage2 <spec-hex> [...]");
        return 2;
    };
    let Some(bytes) = unhex(spec_hex) else {
        eprintln!("jlr-cell: malformed spec");
        return 2;
    };
    let spec = match CellSpec::from_cbor(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("jlr-cell: invalid spec: {e}");
            return 2;
        }
    };
    match stage.as_str() {
        "stage1" => stage1(spec, spec_hex),
        "stage2" => stage2(spec, args.get(3).map_or("--", String::as_str), args.get(4).map_or("", String::as_str)),
        other => {
            eprintln!("jlr-cell: unknown stage {other}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jlr_model::{AdmissionState, Basis, CellClass, Decision, ReasonCode};

    fn spec_with(caps: &[&str]) -> CellSpec {
        let d = Decision {
            state: AdmissionState::Verified,
            cell: CellClass::Cell1,
            network: NetworkMode::None,
            capabilities: caps.iter().map(|c| Capability::parse(c).unwrap()).collect(),
            reasons: vec![ReasonCode::DefaultTier],
            basis: Basis::None,
            needs_user: None,
            policy: jlr_crypto::Digest::ZERO,
        };
        CellSpec::from_decision(&d, vec!["x".into()], vec![]).unwrap()
    }

    #[test]
    fn the_private_root_is_never_assembled_over_a_granted_path() {
        assert_eq!(assembly_dir(&spec_with(&[])).unwrap(), "/tmp", "without grants /tmp is the first choice");
        for grant in ["FS_WRITE:/tmp/data", "FS_READ:/tmp", "FS_WRITE:/tmp/a/b/c"] {
            let dir = assembly_dir(&spec_with(&[grant])).unwrap();
            assert_ne!(dir, "/tmp", "{grant} would be hidden by a tmpfs mounted over /tmp");
        }
        // A grant that contains a candidate hides it too, as does one that contains all of them.
        for grant in ["FS_READ:/", "FS_WRITE:/"] {
            let r = assembly_dir(&spec_with(&[grant]));
            assert!(r.is_err(), "{grant} contains every candidate directory, so none is free: {r:?}");
        }
    }
}
