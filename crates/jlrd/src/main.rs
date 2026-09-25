//! The JLR daemon.
//!
//! * **Exec gate.** A fanotify `FAN_OPEN_EXEC_PERM` mark on each real file
//!   system holds every `exec` until the daemon answers. Files it has already
//!   judged are answered from a cache keyed by inode and validated by size,
//!   mtime and ctime; anything new goes to the engine, which measures the very
//!   descriptor the kernel delivered.
//! * **State watcher.** inotify on the policy, approval and baseline
//!   directories clears the cache the moment a signed object changes.
//! * **Rescan.** A background thread re-measures governed files in small
//!   slices, so drift is noticed even for files nobody executes and the
//!   ledger is never held for long.
//!
//! Modes: `audit` records what would have been denied and lets everything
//! run; `enforce` denies artifacts that may not run normally. The mode comes
//! from the signed policy (`enforce_exec`), so switching it on is an
//! auditable policy epoch. `--audit` forces audit regardless.
//!
//! Failure behaviour: an internal error never blocks the machine unless
//! `--fail-closed` is given; it is recorded as a DEGRADED event. If the daemon
//! dies the kernel releases every held `exec`, so the gate opens, and the
//! ledger says when it was last running.
//!
//! Known limits, stated plainly: the gate sees `exec`, not `mmap`, so
//! `ld.so /path/to/file` runs a file without an exec event; and code that
//! already runs as root can stop the daemon. Both need the supervisor
//! deployment (verified boot plus IPE or fs-verity) to close.

#![forbid(unsafe_code)]

use jlr_engine::{Config, Engine, EngineError, Paths, ScanOptions, list_artifacts};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::fanotify::{EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response};
use nix::sys::inotify::{AddWatchFlags, InitFlags as InoInit, Inotify};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PSEUDO_FS: &[&str] = &[
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "devpts",
    "devtmpfs",
    "mqueue",
    "debugfs",
    "tracefs",
    "securityfs",
    "pstore",
    "bpf",
    "autofs",
    "binfmt_misc",
    "configfs",
    "fusectl",
    "hugetlbfs",
    "rpc_pipefs",
    "nsfs",
    "efivarfs",
    "selinuxfs",
    "fuse.gvfsd-fuse",
    "fuse.portal",
];

struct Args {
    state: Paths,
    marks: Vec<PathBuf>,
    scan_roots: Vec<PathBuf>,
    scan_every: u64,
    force_audit: bool,
    fail_closed: bool,
    lock_wait: Duration,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        state: Paths::default_location(),
        marks: Vec::new(),
        scan_roots: Vec::new(),
        scan_every: 3600,
        force_audit: false,
        fail_closed: false,
        lock_wait: Duration::from_secs(3),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--state" => a.state = Paths::new(val("--state")?),
            "--mark" => a.marks.push(PathBuf::from(val("--mark")?)),
            "--scan-root" => a.scan_roots.push(PathBuf::from(val("--scan-root")?)),
            "--scan-every" => a.scan_every = val("--scan-every")?.parse().map_err(|_| "bad --scan-every")?,
            "--audit" => a.force_audit = true,
            "--fail-closed" => a.fail_closed = true,
            "--lock-wait-ms" => {
                a.lock_wait = Duration::from_millis(val("--lock-wait-ms")?.parse().map_err(|_| "bad --lock-wait-ms")?)
            }
            "-h" | "--help" => {
                println!(
                    "usage: jlrd [--state DIR] [--mark PATH]... [--scan-root PATH]... [--scan-every SECS] [--audit] [--fail-closed]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if a.scan_roots.is_empty() {
        a.scan_roots =
            ["/usr", "/bin", "/sbin", "/lib", "/opt"].iter().map(PathBuf::from).filter(|p| p.exists()).collect();
    }
    Ok(a)
}

/// Real file systems to mark, one path per distinct device.
fn discover_marks() -> Vec<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((pre, post)) = line.split_once(" - ") else { continue };
        let fstype = post.split_whitespace().next().unwrap_or("");
        if PSEUDO_FS.contains(&fstype) {
            continue;
        }
        let mountpoint = pre.split_whitespace().nth(4).unwrap_or("");
        let mountpoint = mountpoint.replace("\\040", " ");
        let Ok(meta) = std::fs::metadata(&mountpoint) else { continue };
        if seen.insert(meta.dev()) {
            out.push(PathBuf::from(mountpoint));
        }
    }
    out
}

#[derive(Clone)]
struct CacheEntry {
    stamp: (u64, i64, i64),
    generation: u64,
    allow: bool,
    /// A verdict is never reused past the policy's evidence age limit.
    expires: Instant,
}

#[derive(Default)]
struct Tally {
    path: String,
    audited: u64,
    denied: u64,
}

fn say(msg: &str) {
    use std::io::Write;
    println!("jlrd: {msg}");
    let _ = std::io::stdout().flush();
}

fn open_engine(paths: &Paths, wait: Duration) -> Result<Engine, EngineError> {
    Engine::open_wait(paths.clone(), Config::default(), wait)
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(sig, shutdown.clone()).map_err(|e| e.to_string())?;
    }
    let generation = Arc::new(AtomicU64::new(1));

    // Fail early and loudly if the state directory is not usable.
    {
        let mut e = open_engine(&args.state, Duration::from_secs(10)).map_err(|e| e.to_string())?;
        let mode = if e.policy().enforce_exec && !args.force_audit { "enforce" } else { "audit" };
        e.record_degraded(&format!("exec gate starting in {mode} mode; the gate is removed if this daemon stops")).ok();
        say(&format!("state ok, policy {} epoch {}", e.policy().name, e.policy().epoch));
    }

    // ---- exec gate ----
    let fan = Fanotify::init(
        InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_NONBLOCK,
        EventFFlags::O_RDONLY | EventFFlags::O_LARGEFILE | EventFFlags::O_CLOEXEC,
    )
    .map_err(|e| format!("fanotify_init: {e} (needs root / CAP_SYS_ADMIN)"))?;
    let marks = if args.marks.is_empty() { discover_marks() } else { args.marks.clone() };
    let root = File::open("/").map_err(|e| e.to_string())?;
    let mut marked = 0;
    for m in &marks {
        match fan.mark(
            MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
            MaskFlags::FAN_OPEN_EXEC_PERM,
            &root,
            Some(m),
        ) {
            Ok(()) => marked += 1,
            Err(e) => say(&format!("cannot mark {}: {e}", m.display())),
        }
    }
    if marked == 0 {
        return Err("no file system could be marked".into());
    }
    say(&format!("exec gate active on {marked} file systems"));

    // ---- state watcher ----
    let ino = Inotify::init(InoInit::IN_CLOEXEC | InoInit::IN_NONBLOCK).map_err(|e| e.to_string())?;
    for d in [
        args.state.policy().parent().map(Path::to_path_buf),
        Some(args.state.approvals()),
        Some(args.state.baselines()),
    ]
    .into_iter()
    .flatten()
    {
        ino.add_watch(&d, AddWatchFlags::IN_MOVED_TO | AddWatchFlags::IN_CLOSE_WRITE | AddWatchFlags::IN_DELETE)
            .map_err(|e| format!("watch {}: {e}", d.display()))?;
    }

    // ---- background rescan ----
    if args.scan_every > 0 {
        let (paths, roots, gen_) = (args.state.clone(), args.scan_roots.clone(), generation.clone());
        let (every, sd) = (args.scan_every, shutdown.clone());
        std::thread::spawn(move || rescan_loop(paths, roots, every, gen_, sd));
    }

    // ---- main loop ----
    let self_pid = std::process::id() as i32;
    let mut cache: HashMap<(u64, u64), CacheEntry> = HashMap::new();
    let mut tally: HashMap<jlr_model::EpnId, Tally> = HashMap::new();
    let mut last_flush = Instant::now();
    let mut seen_gen = generation.load(Ordering::SeqCst);
    while !shutdown.load(Ordering::SeqCst) {
        let mut fds = [PollFd::new(fan.as_fd(), PollFlags::POLLIN), PollFd::new(ino.as_fd(), PollFlags::POLLIN)];
        let _ = poll(&mut fds, PollTimeout::from(250u16));
        if fds[1].revents().is_some_and(|r| r.contains(PollFlags::POLLIN)) {
            let _ = ino.read_events();
            generation.fetch_add(1, Ordering::SeqCst);
            say("signed state changed: cache cleared");
        }
        let g = generation.load(Ordering::SeqCst);
        if g != seen_gen {
            cache.clear();
            seen_gen = g;
        }
        if fds[0].revents().is_some_and(|r| r.contains(PollFlags::POLLIN)) {
            let events = match fan.read_events() {
                Ok(e) => e,
                Err(nix::errno::Errno::EAGAIN) => continue,
                Err(e) => return Err(format!("read_events: {e}")),
            };
            for ev in events {
                let Some(fd) = ev.fd() else { continue };
                let respond = |allow: bool| {
                    let r = if allow { Response::FAN_ALLOW } else { Response::FAN_DENY };
                    let _ = fan.write_response(FanotifyResponse::new(fd, r));
                };
                if ev.pid() == self_pid {
                    respond(true);
                    continue;
                }
                let Ok(owned) = fd.try_clone_to_owned() else {
                    respond(!args.fail_closed);
                    continue;
                };
                let file = File::from(owned);
                let Ok(meta) = file.metadata() else {
                    respond(!args.fail_closed);
                    continue;
                };
                let key = (meta.dev(), meta.ino());
                let stamp = (
                    meta.len(),
                    meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
                    meta.ctime() * 1_000_000_000 + meta.ctime_nsec(),
                );
                if let Some(c) = cache.get(&key)
                    && c.stamp == stamp
                    && c.generation == g
                    && Instant::now() < c.expires
                {
                    respond(c.allow);
                    continue;
                }
                let path = std::fs::read_link(format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&fd)))
                    .unwrap_or_else(|_| PathBuf::from("<unknown>"));
                let allow = match decide(&args, &path, file) {
                    Ok((v, allow)) => {
                        let first = !tally.contains_key(&v.id);
                        let t = tally.entry(v.id).or_default();
                        t.path = path.display().to_string();
                        if !v.allowed {
                            if allow {
                                t.audited += 1;
                            } else {
                                t.denied += 1;
                            }
                        }
                        if first && !v.allowed {
                            let verdict = if allow { "audit: would deny" } else { "denied" };
                            if let Ok(mut e) = open_engine(&args.state, args.lock_wait) {
                                let _ = e.record_exec(&v.id, &t.path, verdict, &v.decision);
                            }
                            say(&format!("{verdict} {}", t.path));
                        }
                        // Only real verdicts are cached, so an error is retried on the next attempt.
                        let expires = Instant::now() + Duration::from_secs(v.max_age_secs.min(3600));
                        cache.insert(key, CacheEntry { stamp, generation: g, allow, expires });
                        allow
                    }
                    Err(msg) => {
                        say(&format!(
                            "internal error for {}: {msg} (fail-{})",
                            path.display(),
                            if args.fail_closed { "closed" } else { "open" }
                        ));
                        if let Ok(mut e) = open_engine(&args.state, Duration::from_millis(500)) {
                            let _ = e.record_degraded(&format!("exec gate error for {}: {msg}", path.display()));
                        }
                        !args.fail_closed
                    }
                };
                respond(allow);
            }
        }
        // Summarise repeated attempts so a denied binary in a loop is visible without flooding the ledger.
        if last_flush.elapsed() > Duration::from_secs(30) && !tally.is_empty() {
            if let Ok(mut e) = open_engine(&args.state, args.lock_wait) {
                for (id, t) in tally.iter().filter(|(_, t)| t.audited + t.denied > 0) {
                    let _ = e.record_degraded(&format!(
                        "exec gate summary {id} {}: audited {} denied {}",
                        t.path, t.audited, t.denied
                    ));
                }
            }
            tally.values_mut().for_each(|t| {
                t.audited = 0;
                t.denied = 0;
            });
            last_flush = Instant::now();
        }
    }
    say("shutting down; the exec gate is removed");
    if let Ok(mut e) = open_engine(&args.state, Duration::from_secs(2)) {
        let _ = e.record_degraded("exec gate stopped");
    }
    Ok(())
}

/// Asks the engine, and turns its verdict into allow/deny according to the mode.
fn decide(args: &Args, path: &Path, file: File) -> Result<(jlr_engine::ExecVerdict, bool), String> {
    let mut engine = open_engine(&args.state, args.lock_wait).map_err(|e| e.to_string())?;
    let v = engine.decide_exec(file, path).map_err(|e| e.to_string())?;
    let deny = v.enforce && !args.force_audit && !v.allowed;
    Ok((v, !deny))
}

fn rescan_loop(paths: Paths, roots: Vec<PathBuf>, every: u64, generation: Arc<AtomicU64>, shutdown: Arc<AtomicBool>) {
    let opts = ScanOptions::default();
    let sleep = |secs: u64, sd: &AtomicBool| {
        for _ in 0..secs * 4 {
            if sd.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    };
    sleep(5, &shutdown);
    while !shutdown.load(Ordering::SeqCst) {
        match list_artifacts(&roots, &opts) {
            Ok(files) => {
                let mut changed = 0usize;
                for chunk in files.chunks(100) {
                    if shutdown.load(Ordering::SeqCst) {
                        return;
                    }
                    match open_engine(&paths, Duration::from_secs(5)).and_then(|mut e| e.scan_files(chunk, &opts)) {
                        Ok(r) => {
                            changed += r.transitions;
                            for d in &r.degraded {
                                say(&format!("DEGRADED {} changed after it was trusted", d.display()));
                            }
                        }
                        Err(e) => say(&format!("rescan slice failed: {e}")),
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                if changed > 0 {
                    generation.fetch_add(1, Ordering::SeqCst);
                }
                say(&format!("rescan complete: {} files, {changed} state changes", files.len()));
            }
            Err(e) => say(&format!("rescan listing failed: {e}")),
        }
        sleep(every, &shutdown);
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("jlrd: {e}");
        std::process::exit(1);
    }
}
