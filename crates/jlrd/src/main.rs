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

mod budget;

use budget::Budgets;
use jlr_engine::{Config, Engine, EngineError, Paths, ScanOptions, list_artifacts};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::fanotify::{EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response};
use nix::sys::inotify::{AddWatchFlags, InitFlags as InoInit, Inotify};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
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
    /// Slow-path seconds each non-root user may spend per minute before their unknown executions are
    /// answered by policy without being measured.
    slow_budget: Duration,
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
        slow_budget: Duration::from_secs(10),
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
            "--slow-budget-secs" => {
                a.slow_budget =
                    Duration::from_secs(val("--slow-budget-secs")?.parse().map_err(|_| "bad --slow-budget-secs")?)
            }
            "--lock-wait-ms" => {
                a.lock_wait = Duration::from_millis(val("--lock-wait-ms")?.parse().map_err(|_| "bad --lock-wait-ms")?)
            }
            "-h" | "--help" => {
                println!(
                    "usage: jlrd [--state DIR] [--mark PATH]... [--scan-root PATH]... [--scan-every SECS] [--audit] [--fail-closed] \
                     [--lock-wait-ms N] [--slow-budget-secs N]"
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

/// Decodes the octal escapes `/proc/self/mountinfo` uses for a space (`\040`), tab (`\011`), newline (`\012`) and
/// backslash (`\134`) in a mount point. Decoding only the space would leave a file system mounted at any other
/// name unmarked, and unmarked means ungated. Works on bytes, because every other byte of a mount point is written
/// as it is and need not be UTF-8.
fn unescape_mountinfo(field: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        if field[i] == b'\\' && i + 3 < field.len() && field[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let v = u32::from(field[i + 1] - b'0') * 64
                + u32::from(field[i + 2] - b'0') * 8
                + u32::from(field[i + 3] - b'0');
            out.push((v & 0xff) as u8);
            i += 4;
        } else {
            out.push(field[i]);
            i += 1;
        }
    }
    PathBuf::from(std::ffi::OsString::from_vec(out))
}

/// The mount points and file system types in the text of `/proc/self/mountinfo`. The table is bytes, not text: the
/// kernel escapes only space, tab, newline and backslash, so a mount point, a label or a FUSE subtype may hold any
/// other byte, and treating the file as UTF-8 would turn one odd name into "no mounts at all".
fn parse_mountinfo(table: &[u8]) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    for line in table.split(|b| *b == b'\n') {
        // id parent major:minor root mountpoint options [optional fields] - fstype source super-options
        let Some(sep) = line.windows(3).position(|w| w == b" - ") else { continue };
        let (pre, post) = (&line[..sep], &line[sep + 3..]);
        let Some(mountpoint) = pre.split(|b| *b == b' ').nth(4) else { continue };
        let fstype = post.split(|b| *b == b' ').next().unwrap_or(b"");
        out.push((unescape_mountinfo(mountpoint), String::from_utf8_lossy(fstype).into_owned()));
    }
    out
}

/// Reports a condition once per distinct message, so an unexaminable mount does not repeat on every mount-table
/// change (which a user can trigger at will).
fn say_once(msg: &str) {
    static SEEN: std::sync::Mutex<Option<HashSet<String>>> = std::sync::Mutex::new(None);
    let Ok(mut guard) = SEEN.lock() else { return };
    let seen = guard.get_or_insert_with(HashSet::new);
    if seen.len() < 256 && seen.insert(msg.to_owned()) {
        say(msg);
    }
}

/// The mount table, opened and armed: the kernel raises `POLLPRI` on it whenever the table changes after the last
/// read, so it is opened **before** the first marking and nothing mounted in between can be missed.
struct MountTable {
    file: File,
}

impl MountTable {
    fn open() -> Result<MountTable, String> {
        let mut t = MountTable { file: File::open("/proc/self/mountinfo").map_err(|e| format!("mountinfo: {e}"))? };
        t.read()?;
        Ok(t)
    }

    /// Reads the whole table from the start, which also re-arms the change notification.
    fn read(&mut self) -> Result<Vec<u8>, String> {
        self.file.seek(SeekFrom::Start(0)).map_err(|e| format!("mountinfo: {e}"))?;
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes).map_err(|e| format!("mountinfo: {e}"))?;
        Ok(bytes)
    }

    fn wait_changed(&self, timeout_ms: u16) -> bool {
        let mut fds = [PollFd::new(self.file.as_fd(), PollFlags::POLLPRI | PollFlags::POLLERR)];
        let _ = poll(&mut fds, PollTimeout::from(timeout_ms));
        fds[0].revents().is_some_and(|r| r.intersects(PollFlags::POLLPRI | PollFlags::POLLERR))
    }
}

/// Real file systems to mark, one path per distinct device in the current mount table. A table that cannot be read
/// is an error, never "no mounts": marking nothing would leave every later mount ungated.
fn discover_marks(table: &mut MountTable) -> Result<Vec<PathBuf>, String> {
    let bytes = table.read()?;
    let mut seen: HashSet<u64> = HashSet::new();
    let mut out = Vec::new();
    for (mountpoint, fstype) in parse_mountinfo(&bytes) {
        if PSEUDO_FS.contains(&fstype.as_str()) {
            continue;
        }
        match std::fs::metadata(&mountpoint) {
            Ok(meta) => {
                if seen.insert(meta.dev()) {
                    out.push(mountpoint);
                }
            }
            // A real file system that root cannot examine (a FUSE mount without `allow_other`) cannot be marked
            // by path either, so it stays ungated; say so, once.
            Err(e) => say_once(&format!(
                "cannot examine mount point {}: {e}; executables there are not gated",
                jlr_model::sanitize(&mountpoint.display().to_string())
            )),
        }
    }
    Ok(out)
}

#[derive(Clone)]
struct CacheEntry {
    stamp: (u64, i64, i64),
    generation: u64,
    allow: bool,
    /// A verdict is answered from the cache for at most an hour.
    expires: Instant,
    /// The verdict's real lifetime: the earlier of the evidence age limit and the expiry of the approval or baseline
    /// it relied on. A verdict past this is never honoured, not even for a throttled user.
    valid_until: Instant,
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
        say(&format!("state ok, policy {} epoch {}", jlr_model::sanitize(&e.policy().name), e.policy().epoch));
    }

    // ---- exec gate ----
    let fan = Fanotify::init(
        InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_NONBLOCK,
        EventFFlags::O_RDONLY | EventFFlags::O_LARGEFILE | EventFFlags::O_CLOEXEC,
    )
    .map_err(|e| format!("fanotify_init: {e} (needs root / CAP_SYS_ADMIN)"))?;
    let fan = Arc::new(fan);
    let root = Arc::new(File::open("/").map_err(|e| e.to_string())?);
    let explicit = !args.marks.is_empty();
    // Armed before the first marking, so a mount that happens meanwhile is not missed.
    let mut table = if explicit { None } else { Some(MountTable::open()?) };
    let marks = match table.as_mut() {
        Some(t) => discover_marks(t)?,
        None => args.marks.clone(),
    };
    let marked = mark_filesystems(&fan, &root, &marks);
    if marked == 0 {
        return Err("no file system could be marked".into());
    }
    say(&format!("exec gate active on {marked} file systems"));
    // A file system mounted after this point is invisible to the gate until it is marked.
    if let Some(table) = table {
        let (f, r, sd) = (fan.clone(), root.clone(), shutdown.clone());
        std::thread::spawn(move || mount_watcher(f, r, table, sd));
    }

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
    let mut tally: HashMap<String, Tally> = HashMap::new();
    // Each user may spend `slow_budget` of slow-path time a minute; all unprivileged users together may spend half of
    // the gate's time, so that many accounts (subordinate ids, user namespaces) cannot multiply the allowance.
    let mut budgets = Budgets::new(args.slow_budget, Duration::from_secs(30), Duration::from_secs(60));
    let mut throttled_noted: HashSet<u32> = HashSet::new();
    let mut throttled_count: HashMap<u32, u64> = HashMap::new();
    // Records that could not be written because the ledger was busy; written at the next opportunity.
    let mut pending_events: Vec<String> = Vec::new();
    let mut last_flush = Instant::now();
    let mut seen_gen = generation.load(Ordering::SeqCst);
    // The mode the policy last said; used only to answer throttled events, which are never measured.
    let mut enforce_hint =
        open_engine(&args.state, Duration::from_secs(5)).map(|e| e.policy().enforce_exec).unwrap_or(false)
            && !args.force_audit;
    // The caches are bounded so that unique files cannot grow the daemon without limit.
    const CACHE_LIMIT: usize = 100_000;
    const TALLY_LIMIT: usize = 50_000;
    while !shutdown.load(Ordering::SeqCst) {
        // Readiness is copied out so the poll array (which borrows the descriptors) is dropped before
        // any of them is read or written.
        let (fan_ready, ino_ready) = {
            let mut fds = [PollFd::new(fan.as_fd(), PollFlags::POLLIN), PollFd::new(ino.as_fd(), PollFlags::POLLIN)];
            let _ = poll(&mut fds, PollTimeout::from(250u16));
            (
                fds[0].revents().is_some_and(|r| r.contains(PollFlags::POLLIN)),
                fds[1].revents().is_some_and(|r| r.contains(PollFlags::POLLIN)),
            )
        };
        if ino_ready {
            let _ = ino.read_events();
            generation.fetch_add(1, Ordering::SeqCst);
            enforce_hint = open_engine(&args.state, Duration::from_secs(2))
                .map(|e| e.policy().enforce_exec)
                .unwrap_or(enforce_hint)
                && !args.force_audit;
            say("signed state changed: cache cleared");
        }
        let g = generation.load(Ordering::SeqCst);
        if g != seen_gen || cache.len() > CACHE_LIMIT {
            cache.clear();
            seen_gen = g;
        }
        if fan_ready {
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
                let shown = jlr_model::sanitize(&path.display().to_string());

                // A user who has spent their slow-path allowance does not get to make others wait: their
                // unmeasured execution is answered by policy without doing any work for it.
                let uid = uid_of_pid(ev.pid());
                if uid != 0 && budgets.exhausted(uid, Instant::now()) {
                    if throttled_noted.insert(uid) {
                        say(&format!(
                            "uid {uid} exceeded its slow-path budget; unknown executions are answered by policy, unmeasured"
                        ));
                    }
                    if throttled_count.contains_key(&uid) || throttled_count.len() < 4096 {
                        *throttled_count.entry(uid).or_default() += 1;
                    }
                    // A file this daemon already judged allowable, and that has not changed since, is not made
                    // to pay for its user's other executions: its cached verdict merely aged out of the hour
                    // it is kept. Its real lifetime (evidence age, approval or baseline expiry) still applies.
                    let known_good = cache.get(&key).is_some_and(|c| {
                        c.stamp == stamp && c.generation == g && c.allow && Instant::now() < c.valid_until
                    });
                    respond(known_good || !enforce_hint);
                    continue;
                }
                let mut worked = Duration::ZERO;
                let outcome = decide(&args, &path, file, &mut worked);
                if uid != 0 {
                    budgets.charge(uid, worked, Instant::now());
                }
                if throttled_noted.len() > 1024 {
                    throttled_noted.clear();
                }
                let allow = match outcome {
                    Ok((v, allow)) => {
                        enforce_hint = v.enforce && !args.force_audit;
                        let tally_key = v.id.map_or_else(|| format!("unmeasurable:{shown}"), |i| i.to_string());
                        let first = !tally.contains_key(&tally_key);
                        if tally.len() > TALLY_LIMIT {
                            tally.clear();
                        }
                        let t = tally.entry(tally_key).or_default();
                        t.path = shown.clone();
                        if !v.allowed {
                            if allow {
                                t.audited += 1;
                            } else {
                                t.denied += 1;
                            }
                        }
                        if first && !v.allowed {
                            let verdict = match (&v.unmeasurable, allow) {
                                (Some(_), true) => "audit: would deny (unmeasurable)",
                                (Some(_), false) => "denied (unmeasurable)",
                                (None, true) => "audit: would deny",
                                (None, false) => "denied",
                            };
                            if let Ok(mut e) = open_engine(&args.state, args.lock_wait) {
                                let _ = e.record_exec(v.id.as_ref(), &t.path, verdict, &v.decision);
                            }
                            say(&format!("{verdict} {}", t.path));
                        }
                        // Only real verdicts are cached, so an error is retried on the next attempt.
                        let now = Instant::now();
                        let expires = now + Duration::from_secs(v.max_age_secs.min(3600));
                        let valid_until = now + Duration::from_secs(v.max_age_secs);
                        cache.insert(key, CacheEntry { stamp, generation: g, allow, expires, valid_until });
                        allow
                    }
                    Err(msg) => {
                        say(&format!(
                            "internal error for {shown}: {msg} (fail-{})",
                            if args.fail_closed { "closed" } else { "open" }
                        ));
                        let text = format!("exec gate error for {shown}: {msg}");
                        match open_engine(&args.state, Duration::from_millis(500)) {
                            Ok(mut e) => {
                                let _ = e.record_degraded(&text);
                            }
                            // The usual cause is the ledger lock, which whoever holds it will release; the record
                            // is kept and written at the next opportunity instead of being lost.
                            Err(_) if pending_events.len() < 256 => pending_events.push(text),
                            Err(_) => {}
                        }
                        !args.fail_closed
                    }
                };
                respond(allow);
            }
        }
        // Summarise repeated attempts so a denied binary in a loop is visible without flooding the ledger.
        if last_flush.elapsed() > Duration::from_secs(30)
            && (!tally.is_empty() || !pending_events.is_empty() || !throttled_count.is_empty())
        {
            if let Ok(mut e) = open_engine(&args.state, args.lock_wait) {
                write_summaries(&mut e, &mut pending_events, &mut throttled_count, &tally);
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
        // What was queued or counted must not vanish with the daemon.
        write_summaries(&mut e, &mut pending_events, &mut throttled_count, &tally);
        let _ = e.record_degraded("exec gate stopped");
    }
    Ok(())
}

/// The most individual summary events written per flush; the rest are folded into one line.
const SUMMARY_EVENTS: usize = 20;

/// Writes what the daemon has been holding back (unrecorded errors, throttling, repeated denials) as a **bounded**
/// number of events with a single durable flush. One event per throttled user or per denied file would let a person
/// with thousands of uids or files keep the gate thread busy in syncs, stalling every `exec` on the machine.
fn write_summaries(
    e: &mut Engine,
    pending: &mut Vec<String>,
    throttled: &mut HashMap<u32, u64>,
    tally: &HashMap<String, Tally>,
) {
    let extra = pending.len().saturating_sub(SUMMARY_EVENTS);
    let mut lines: Vec<String> = pending.drain(..).take(SUMMARY_EVENTS).collect();
    if extra > 0 {
        lines.push(format!("exec gate: {extra} more internal errors were not recorded individually"));
    }
    if !throttled.is_empty() {
        let total: u64 = throttled.values().sum();
        let mut top: Vec<(&u32, &u64)> = throttled.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let worst: Vec<String> = top.iter().take(3).map(|(u, n)| format!("uid {u}: {n}")).collect();
        lines.push(format!(
            "exec gate: {total} executions from {} users exceeded the slow-path budget and were answered by policy without being measured (most: {})",
            throttled.len(),
            worst.join(", ")
        ));
        throttled.clear();
    }
    let mut repeated: Vec<(&String, &Tally)> = tally.iter().filter(|(_, t)| t.audited + t.denied > 0).collect();
    repeated.sort_by(|a, b| (b.1.audited + b.1.denied).cmp(&(a.1.audited + a.1.denied)).then(a.0.cmp(b.0)));
    for (id, t) in repeated.iter().take(SUMMARY_EVENTS) {
        lines.push(format!(
            "exec gate summary {id} {}: audited {} denied {}",
            jlr_model::sanitize_to(&t.path, 300),
            t.audited,
            t.denied
        ));
    }
    if repeated.len() > SUMMARY_EVENTS {
        lines.push(format!(
            "exec gate summary: {} more files were audited or denied repeatedly",
            repeated.len() - SUMMARY_EVENTS
        ));
    }
    if !lines.is_empty() {
        let _ = e.record_degraded_many(&lines);
    }
}

/// Marks the file system under each path. Marking is idempotent, so it is repeated for every mount-table change
/// instead of being skipped for a device number seen before: the mark belongs to the superblock and disappears with
/// it, while a device number is reused by the next file system mounted (the next stick is `sdb1` again), so
/// remembering numbers would leave a replacement file system ungated. Returns how many marks succeeded.
fn mark_filesystems(fan: &Fanotify, root: &File, paths: &[PathBuf]) -> usize {
    let mut n = 0;
    for m in paths {
        match fan.mark(
            MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
            MaskFlags::FAN_OPEN_EXEC_PERM,
            root,
            Some(m),
        ) {
            Ok(()) => n += 1,
            Err(e) => say(&format!("cannot mark {}: {e}", jlr_model::sanitize(&m.display().to_string()))),
        }
    }
    n
}

/// Watches the mount table on its own thread, so a file system mounted while the gate is busy with a batch of
/// events (each of which can take a while) is still marked promptly.
fn mount_watcher(fan: Arc<Fanotify>, root: Arc<File>, mut table: MountTable, shutdown: Arc<AtomicBool>) {
    let mut known: HashSet<PathBuf> = HashSet::new();
    // Refresh once straight away: anything mounted between the first marking and this thread starting raised no
    // event, because the table was armed before that marking and read again since.
    let mut retry = true;
    while !shutdown.load(Ordering::SeqCst) {
        let changed = table.wait_changed(if retry { 1000 } else { 250 });
        if !(changed || retry) {
            continue;
        }
        match discover_marks(&mut table) {
            Ok(now) => {
                retry = false;
                // Everything currently mounted is marked again; only the message depends on what looks new.
                let n = mark_filesystems(&fan, &root, &now);
                let fresh = now.iter().filter(|p| !known.contains(*p)).count();
                if fresh > 0 && !known.is_empty() {
                    say(&format!("marked {fresh} newly mounted file system(s) ({n} marks refreshed)"));
                }
                known = now.into_iter().collect();
            }
            // Keep the marks that exist and try again shortly: the failure may be momentary, and the kernel raises
            // no second event for a change that was already seen.
            Err(e) => {
                say_once(&format!("cannot read the mount table ({e}); keeping the current marks and retrying"));
                retry = true;
            }
        }
    }
}

/// The owner of the process's `/proc` entry, which is its effective uid. A process that has already exited
/// falls into a shared "unknown" bucket rather than being mistaken for root.
fn uid_of_pid(pid: i32) -> u32 {
    std::fs::metadata(format!("/proc/{pid}")).map(|m| m.uid()).unwrap_or(u32::MAX)
}

/// Asks the engine, and turns its verdict into allow/deny according to the mode.
///
/// `worked` receives the time spent doing the work (opening the engine and deciding), **not** the time spent waiting
/// for the ledger lock, which the user did not cause and must not be charged for.
fn decide(
    args: &Args,
    path: &Path,
    file: File,
    worked: &mut Duration,
) -> Result<(jlr_engine::ExecVerdict, bool), String> {
    let (mut engine, open_time) =
        Engine::open_wait_timed(args.state.clone(), Config::default(), args.lock_wait).map_err(|e| e.to_string())?;
    *worked = open_time;
    let started = Instant::now();
    let v = engine.decide_exec(file, path);
    *worked += started.elapsed();
    let v = v.map_err(|e| e.to_string())?;
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
                                say(&format!(
                                    "DEGRADED {} changed after it was trusted",
                                    jlr_model::sanitize(&d.display().to_string())
                                ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn every_mountinfo_escape_is_decoded_so_no_file_system_is_left_unmarked() {
        // The kernel writes a space, tab, newline and backslash in a mount point as octal escapes.
        for (escaped, plain) in [
            ("/mnt/plain", "/mnt/plain"),
            ("/mnt/sp\\040ace", "/mnt/sp ace"),
            ("/mnt/tab\\011x", "/mnt/tab\tx"),
            ("/mnt/nl\\012z", "/mnt/nl\nz"),
            ("/mnt/bs\\134y", "/mnt/bs\\y"),
            ("/mnt/a\\040b\\011c\\012d\\134e", "/mnt/a b\tc\nd\\e"),
            ("/mnt/trailing\\", "/mnt/trailing\\"),
            ("/mnt/short\\04", "/mnt/short\\04"),
            ("/mnt/notoctal\\089", "/mnt/notoctal\\089"),
        ] {
            assert_eq!(unescape_mountinfo(escaped.as_bytes()).as_os_str().as_bytes(), plain.as_bytes(), "{escaped}");
        }
    }

    #[test]
    fn a_mount_table_with_bytes_that_are_not_utf8_is_still_parsed() {
        // Only space, tab, newline and backslash are escaped by the kernel; any other byte in a mount point, a label
        // or a FUSE subtype appears as it is. Reading the table as text turned one such name into "no mounts at all".
        let mut table: Vec<u8> = Vec::new();
        table.extend_from_slice(b"36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n");
        table.extend_from_slice(b"100 1 0:50 / /mnt/m\xffnt rw - fuse.sshfs user@host:/ rw\n");
        table.extend_from_slice(b"101 1 0:51 / /mnt/sp\\040ace rw shared:2 - tmpfs a - b rw\n");
        table.extend_from_slice(b"garbage without a separator\n");
        table.extend_from_slice(b"102 1 0:52 / /mnt/\xff\xfe\\011tab rw - ext4 /dev/\xffdisk rw\n");
        let entries = parse_mountinfo(&table);
        let got: Vec<(&[u8], &str)> = entries.iter().map(|(p, t)| (p.as_os_str().as_bytes(), t.as_str())).collect();
        assert_eq!(
            got,
            vec![
                (&b"/mnt2"[..], "ext3"),
                (&b"/mnt/m\xffnt"[..], "fuse.sshfs"),
                (&b"/mnt/sp ace"[..], "tmpfs"),
                (&b"/mnt/\xff\xfe\ttab"[..], "ext4"),
            ]
        );
    }

    #[test]
    fn the_live_mount_table_can_be_read_and_parsed_into_real_mounts() {
        let mut table = MountTable::open().expect("this machine has /proc/self/mountinfo");
        let marks = discover_marks(&mut table).expect("a readable table is not an error");
        assert!(!marks.is_empty(), "a running machine has at least one real file system");
        assert!(marks.iter().all(|p| p.is_absolute()));
    }
}
