//! The `jlr` command-line tool.

#![forbid(unsafe_code)]

mod policy_source;

use clap::{Args, Parser, Subcommand};
use jlr_cell::{CellSpec, Control, SealedExe, Stdio3, launch};
use jlr_engine::{Config, Engine, EngineError, EnrollOptions, Paths, PolicyKind, ScanOptions, init};
use jlr_model::{AdmissionState, Capability, CellClass, Decision, NetworkMode};
use jlr_policy::RevocationKind;
use policy_source::PolicySource;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "jlr", version, about = "JLR security governance", long_about = None)]
struct Cli {
    /// State directory (default: $JLR_STATE, /var/lib/jlr as root, else ~/.local/state/jlr).
    #[arg(long, global = true)]
    state: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create keys, the first policy and the evidence ledger.
    Init {
        /// Install the strict policy: quarantine everything without strong evidence.
        #[arg(long)]
        strict: bool,
    },
    /// Show trust posture, policy, artifact counts and ledger state.
    Status,
    /// Check what this machine can actually enforce, by launching a live test cell.
    Doctor,
    /// Measure and classify governed artifacts below the given paths.
    Scan {
        #[arg(default_value = "/usr")]
        paths: Vec<PathBuf>,
        /// Re-hash every file even if its metadata is unchanged.
        #[arg(long)]
        full: bool,
        /// Directory to skip (repeatable).
        #[arg(long)]
        exclude: Vec<PathBuf>,
    },
    /// Explain what JLR thinks of one file, without changing anything.
    Explain { path: PathBuf },
    /// Run a program in the cell its trust decision prescribes.
    Run {
        /// Capability the program requests (repeatable), for example FS_READ:/home/me/data.
        #[arg(long = "cap")]
        caps: Vec<String>,
        /// Program followed by its arguments.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Baselines: an operator-signed statement of the machine's initial state.
    Baseline {
        #[command(subcommand)]
        cmd: BaselineCmd,
    },
    /// Approve one known artifact for a scoped cell.
    Approve(ApproveArgs),
    /// Revoke by content digest, signer or EPN.
    Revoke(RevokeArgs),
    /// Policy management.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Evidence ledger.
    Ledger {
        #[command(subcommand)]
        cmd: LedgerCmd,
    },
}

#[derive(Subcommand)]
enum BaselineCmd {
    /// Enrol package-managed software below the given paths as the initial host state.
    Enroll {
        #[arg(default_value = "/usr")]
        paths: Vec<PathBuf>,
        #[arg(long, default_value = "initial-host")]
        name: String,
        #[arg(long, default_value = "CELL-2")]
        cell: String,
        #[arg(long, default_value = "FULL_USER_NETWORK")]
        network: String,
        #[arg(long, default_value_t = 365)]
        ttl_days: u64,
        #[arg(long, default_value = "operator")]
        by: String,
        #[arg(long)]
        exclude: Vec<PathBuf>,
        /// Also enrol files no package manager vouches for: "trust what is on disk now".
        /// Meant for installers whose base image is itself the verified trust root.
        #[arg(long)]
        include_unmanaged: bool,
    },
}

#[derive(Args)]
struct ApproveArgs {
    /// EPN identifier of a known artifact.
    epn: String,
    #[arg(long, default_value = "CELL-1")]
    cell: String,
    #[arg(long, default_value = "NONE")]
    network: String,
    #[arg(long = "cap")]
    caps: Vec<String>,
    #[arg(long, default_value_t = 24)]
    ttl_hours: u64,
    #[arg(long, default_value = "operator")]
    by: String,
}

#[derive(Args)]
struct RevokeArgs {
    /// Content digest, `sha256:<hex>`.
    #[arg(long, conflicts_with_all = ["signer", "epn"])]
    digest: Option<String>,
    /// Signer identifier.
    #[arg(long, conflicts_with_all = ["digest", "epn"])]
    signer: Option<String>,
    /// EPN identifier.
    #[arg(long, conflicts_with_all = ["digest", "signer"])]
    epn: Option<String>,
    #[arg(long)]
    reason: String,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Print the active policy as TOML.
    Show,
    /// Compile, validate, sign and install a policy from a TOML file.
    Set { file: PathBuf },
    /// Turn the exec gate's enforcement on or off by installing a new signed policy epoch.
    Enforce {
        #[arg(value_parser = ["on", "off"])]
        mode: String,
    },
}

#[derive(Subcommand)]
enum LedgerCmd {
    /// Verify every signature, link and checkpoint.
    Verify {
        /// A checkpoint envelope kept outside this machine.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
    },
    /// Show recent events.
    Log {
        #[arg(short, default_value_t = 20)]
        n: usize,
    },
    /// Write a signed checkpoint and print or save it for off-machine storage.
    Checkpoint {
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn parse_named<T>(what: &str, s: &str, f: impl Fn(&str) -> Option<T>) -> Result<T, String> {
    f(s).ok_or_else(|| format!("unknown {what}: {s}"))
}

fn caps_of(v: &[String]) -> Result<Vec<Capability>, String> {
    v.iter().map(|c| Capability::parse(c).map_err(|e| e.to_string())).collect()
}

fn open(cli: &Cli) -> Result<Engine, EngineError> {
    let paths = cli.state.clone().map_or_else(Paths::default_location, Paths::new);
    // The daemon holds the ledger only briefly, so wait for it instead of failing.
    Engine::open_wait(paths, Config::default(), std::time::Duration::from_secs(20))
}

fn describe(d: &Decision) -> String {
    let reasons: Vec<String> = d.reasons.iter().map(ToString::to_string).collect();
    format!("{} in {} network={} basis={} reasons={}", d.state, d.cell, d.network, d.basis, reasons.join(","))
}

fn run(cli: Cli) -> Result<u8, String> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let e = |x: EngineError| x.to_string();
    match &cli.cmd {
        Cmd::Init { strict } => {
            let paths = cli.state.clone().map_or_else(Paths::default_location, Paths::new);
            let kind = if *strict { PolicyKind::Strict } else { PolicyKind::Workstation };
            let r = init(&paths, kind, now).map_err(e)?;
            println!("Initialised {}", paths.root().display());
            println!("  node        {}", r.node.node_id);
            println!("  mode        {} (assurance: companion; host root can subvert this installation)", r.node.mode);
            for (role, kid) in &r.keys {
                println!("  key         {role:<8} kid:{kid}");
            }
            println!("  policy      {}", r.policy_digest);
            println!(
                "\nThe policy key can approve software and replace policy. Move keys/policy.jlrkey to a separate device"
            );
            println!(
                "and keep a copy of the first ledger checkpoint (`jlr ledger checkpoint --out FILE`) off this machine."
            );
            Ok(0)
        }
        Cmd::Doctor => doctor(),
        Cmd::Status => {
            let eng = open(&cli).map_err(e)?;
            let s = eng.status();
            println!("node        {}", s.node_id);
            println!("assurance   {}   (what this report can honestly claim)", s.assurance);
            println!("posture     {}   scope: {}", s.posture, s.scope);
            println!("policy      {} epoch {}  {}", s.policy_name, s.policy_epoch, s.policy_digest);
            println!(
                "exec gate   {}",
                if s.enforce_exec {
                    "enforce (unknown software may not run natively)"
                } else {
                    "audit (records what it would deny; nothing is blocked)"
                }
            );
            println!("revocations {} entries, epoch {}", s.revocations, s.revocations_epoch);
            println!("trust       {} keys", s.anchors);
            let states: Vec<String> = s.by_state.iter().map(|(k, v)| format!("{k}={v}")).collect();
            println!("artifacts   {}", if states.is_empty() { "none yet".into() } else { states.join("  ") });
            for (name, n) in &s.baselines {
                println!("baseline    {name}: {n} members");
            }
            println!("approvals   {}", s.approvals);
            println!("ledger      {} events, {} checkpoints, root {}", s.ledger_events, s.checkpoints, s.ledger_root);
            if s.torn_tail_bytes > 0 {
                println!(
                    "warning     {} bytes of an incomplete ledger record were quarantined at start",
                    s.torn_tail_bytes
                );
            }
            Ok(0)
        }
        Cmd::Scan { paths, full, exclude } => {
            let mut eng = open(&cli).map_err(e)?;
            let opts = ScanOptions { full: *full, exclude: exclude.clone(), ..ScanOptions::default() };
            let started = std::time::Instant::now();
            let r = eng.scan(paths, &opts).map_err(e)?;
            println!(
                "scanned {} files ({} unchanged) in {:.1}s",
                r.examined + r.unchanged,
                r.unchanged,
                started.elapsed().as_secs_f64()
            );
            println!("new artifacts {}   state changes {}", r.new_artifacts, r.transitions);
            let states: Vec<String> = r.by_state.iter().map(|(k, v)| format!("{k}={v}")).collect();
            println!("results       {}", states.join("  "));
            for p in &r.degraded {
                println!("DEGRADED      {} changed after it was trusted", p.display());
            }
            for (p, err) in r.errors.iter().take(5) {
                println!("unreadable    {}: {err}", p.display());
            }
            if r.errors.len() > 5 {
                println!("              ... and {} more", r.errors.len() - 5);
            }
            Ok(u8::from(!r.degraded.is_empty()))
        }
        Cmd::Explain { path } => {
            let eng = open(&cli).map_err(e)?;
            let x = eng.explain(path).map_err(e)?;
            println!("{}", x.record.id());
            println!("  class       {}   size {}   sha256 {}", x.record.class, x.record.size, x.record.digest.hex());
            println!("  source      {} {}", x.record.source.channel, x.record.source.origin.as_deref().unwrap_or(""));
            println!("  provenance  {}", x.record.provenance);
            println!("  recorded    {}", x.prior.map_or("never seen".to_owned(), |s| s.to_string()));
            println!("  decision    {}", describe(&x.decision));
            println!("  evidence:");
            for i in &x.evidence {
                println!("    {:<24} {:<8} {}", i.kind.to_string(), i.source, i.detail);
            }
            if let Some(q) = &x.decision.needs_user {
                println!("  needs you   {q}");
            }
            Ok(0)
        }
        Cmd::Run { caps, command } => {
            let mut eng = open(&cli).map_err(e)?;
            let requested = caps_of(caps)?;
            let env: Vec<String> = ["PATH", "HOME", "LANG", "TERM"]
                .iter()
                .filter_map(|k| std::env::var(k).ok().map(|v| format!("{k}={v}")))
                .collect();
            let prog = Path::new(&command[0]);
            let path = if prog.components().count() > 1 {
                prog.to_owned()
            } else {
                which(&command[0]).ok_or_else(|| format!("{} not found in PATH", command[0]))?
            };
            let path = std::fs::canonicalize(&path).map_err(|x| x.to_string())?;
            match eng.run(&path, &command[1..], &env, &requested, false) {
                Ok(r) => {
                    eprintln!(
                        "jlr: {} enforcement={:?} unavailable=[{}]",
                        describe(&r.decision),
                        r.report.status,
                        r.report.unavailable.join("; ")
                    );
                    Ok(r.exit_code.clamp(0, 255) as u8)
                }
                Err(EngineError::NotRunnable(d)) => {
                    eprintln!("jlr: denied: {}", describe(&d));
                    if let Some(q) = &d.needs_user {
                        eprintln!("jlr: {q}");
                        eprintln!("jlr: to allow it: jlr explain {} ; jlr approve <EPN>", path.display());
                    }
                    Ok(126)
                }
                Err(x) => Err(x.to_string()),
            }
        }
        Cmd::Baseline {
            cmd: BaselineCmd::Enroll { paths, name, cell, network, ttl_days, by, exclude, include_unmanaged },
        } => {
            let mut eng = open(&cli).map_err(e)?;
            let cell = parse_named("cell", cell, CellClass::parse)?;
            let network = parse_named("network mode", network, NetworkMode::parse)?;
            let opts = ScanOptions { exclude: exclude.clone(), full: true, ..ScanOptions::default() };
            let enroll = EnrollOptions {
                name: name.clone(),
                cell,
                network,
                ttl_secs: ttl_days * 86400,
                granted_by: by.clone(),
                include_unmanaged: *include_unmanaged,
            };
            let (r, members) = eng.enroll_baseline(paths, &enroll, &opts).map_err(e)?;
            println!("baseline {name}: {members} members of {} artifacts examined", r.examined);
            let states: Vec<String> = r.by_state.iter().map(|(k, v)| format!("{k}={v}")).collect();
            println!("results  {}", states.join("  "));
            println!("Baseline members are recorded as manual overrides: authority, not proof.");
            Ok(0)
        }
        Cmd::Approve(a) => {
            let mut eng = open(&cli).map_err(e)?;
            let d = eng
                .approve(
                    &a.epn,
                    parse_named("cell", &a.cell, CellClass::parse)?,
                    parse_named("network mode", &a.network, NetworkMode::parse)?,
                    caps_of(&a.caps)?,
                    a.ttl_hours * 3600,
                    &a.by,
                )
                .map_err(e)?;
            println!("{}", describe(&d));
            Ok(0)
        }
        Cmd::Revoke(a) => {
            let mut eng = open(&cli).map_err(e)?;
            let (kind, target) = match (&a.digest, &a.signer, &a.epn) {
                (Some(d), None, None) => (RevocationKind::Digest, d.clone()),
                (None, Some(s), None) => (RevocationKind::Signer, s.clone()),
                (None, None, Some(p)) => (RevocationKind::Epn, p.clone()),
                _ => return Err("give exactly one of --digest, --signer or --epn".into()),
            };
            let n = eng.revoke(kind, &target, &a.reason).map_err(e)?;
            println!("revoked {target}; {n} known artifacts moved to REVOKED");
            Ok(0)
        }
        Cmd::Policy { cmd: PolicyCmd::Show } => {
            let eng = open(&cli).map_err(e)?;
            print!("{}", toml::to_string_pretty(&PolicySource::from_policy(eng.policy())).map_err(|x| x.to_string())?);
            Ok(0)
        }
        Cmd::Policy { cmd: PolicyCmd::Set { file } } => {
            let text = std::fs::read_to_string(file).map_err(|x| format!("{}: {x}", file.display()))?;
            let src: PolicySource = toml::from_str(&text).map_err(|x| format!("{}: {x}", file.display()))?;
            let policy = src.compile().map_err(|x| format!("policy refused: {x}"))?;
            let mut eng = open(&cli).map_err(e)?;
            let digest = eng.set_policy(policy).map_err(e)?;
            println!("policy installed: epoch {} {digest}", src.epoch);
            Ok(0)
        }
        Cmd::Policy { cmd: PolicyCmd::Enforce { mode } } => {
            let mut eng = open(&cli).map_err(e)?;
            let mut p = eng.policy().clone();
            p.enforce_exec = mode == "on";
            p.epoch += 1;
            let epoch = p.epoch;
            let digest = eng.set_policy(p).map_err(e)?;
            println!("exec gate enforcement {mode}: policy epoch {epoch} {digest}");
            Ok(0)
        }
        Cmd::Ledger { cmd } => {
            let mut eng = open(&cli).map_err(e)?;
            match cmd {
                LedgerCmd::Verify { checkpoint } => {
                    let ext = checkpoint
                        .as_ref()
                        .map(|p| std::fs::read(p).map_err(|x| format!("{}: {x}", p.display())))
                        .transpose()?;
                    let r = eng.verify_ledger(ext.as_deref()).map_err(e)?;
                    println!("ledger OK: {} events, {} checkpoints, root {}", r.events, r.checkpoints, r.root);
                    println!(
                        "anchor: {}",
                        match r.anchor {
                            Some(a) => format!("{a:?} counter (not hardware-backed unless TPM)"),
                            None => "no checkpoint yet".into(),
                        }
                    );
                    println!(
                        "external checkpoint: {}",
                        if r.external_checkpoint_matched {
                            "matched"
                        } else {
                            "none supplied; rollback of this whole directory would not be detected"
                        }
                    );
                    Ok(0)
                }
                LedgerCmd::Log { n } => {
                    for ev in eng.recent_events(*n).map_err(e)? {
                        let t = match (ev.old_state, ev.new_state) {
                            (Some(o), Some(n)) => format!("{o}->{n}"),
                            (None, Some(n)) => format!("->{n}"),
                            _ => String::new(),
                        };
                        let subj = ev.subject.as_deref().map(|s| &s[..s.len().min(24)]).unwrap_or("");
                        println!(
                            "{:>6} {:<11} {:<24} {:<26} {:<14} {}",
                            ev.seq,
                            ev.kind.to_string(),
                            subj,
                            t,
                            ev.basis.to_string(),
                            ev.detail
                        );
                    }
                    Ok(0)
                }
                LedgerCmd::Checkpoint { out } => {
                    let cp = eng.checkpoint().map_err(e)?;
                    match out {
                        Some(p) => {
                            std::fs::write(p, &cp).map_err(|x| x.to_string())?;
                            println!(
                                "checkpoint written to {} ({} bytes). Store it OFF this machine.",
                                p.display(),
                                cp.len()
                            );
                        }
                        None => println!("{}", cp.iter().map(|b| format!("{b:02x}")).collect::<String>()),
                    }
                    Ok(0)
                }
            }
        }
    }
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?.to_string_lossy().split(':').map(|d| Path::new(d).join(name)).find(|p| p.is_file())
}

/// Launches a trivial sealed program in a CELL-0 and reports what was enforced.
fn doctor() -> Result<u8, String> {
    println!("kernel      {}", read("/proc/sys/kernel/osrelease"));
    let lsm = read("/sys/kernel/security/lsm");
    println!("LSMs        {}", if lsm.is_empty() { "unknown".into() } else { lsm.clone() });
    println!("landlock    {}", if lsm.contains("landlock") { "present" } else { "NOT present" });
    println!(
        "cgroup v2   {}",
        if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() { "mounted" } else { "not mounted" }
    );
    println!("TPM 2.0     {}", if Path::new("/dev/tpmrm0").exists() { "device present" } else { "no device" });
    println!("Secure Boot {}", secure_boot());
    println!("IMA         {}", if Path::new("/sys/kernel/security/ima").exists() { "present" } else { "absent" });
    println!(
        "userns      restrict_unprivileged_userns={}",
        read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    );

    let helper = Config::default().helper;
    if !helper.exists() {
        return Err(format!("cell helper {} not found; build with `cargo build --release`", helper.display()));
    }
    let exe_path = std::fs::canonicalize("/bin/true").map_err(|x| x.to_string())?;
    let (mut f, m) = jlr_measure::open_measured(&exe_path, 1 << 28).map_err(|x| x.to_string())?;
    let sealed = SealedExe::seal(&mut f, &m.digest, 1 << 28).map_err(|x| x.to_string())?;
    let decision = Decision {
        state: AdmissionState::Observed,
        cell: CellClass::Cell0,
        network: NetworkMode::None,
        capabilities: vec![],
        reasons: vec![],
        basis: jlr_model::Basis::None,
        needs_user: None,
        policy: jlr_crypto::Digest::ZERO,
    };
    let spec = CellSpec::from_decision(&decision, vec!["true".into()], vec![]).map_err(|x| x.to_string())?;
    println!("\nlive CELL-0 test with /bin/true:");
    match launch(&helper, &sealed, &spec, Stdio3::null()) {
        Ok(running) => {
            let o = running.wait().map_err(|x| x.to_string())?;
            let r = &o.report;
            println!("  status      {:?}", r.status);
            for c in Control::ALL {
                let name = c.as_str();
                let mark = if r.active.iter().any(|a| a == name) {
                    "active".to_owned()
                } else if let Some(u) = r.unavailable.iter().find(|u| u.starts_with(&format!("{name}:"))) {
                    format!("UNAVAILABLE ({})", u.split_once(": ").map_or("", |x| x.1))
                } else {
                    "not requested".to_owned()
                };
                println!("  {name:<13} {mark}");
            }
            println!("  seccomp     denies {} syscalls", r.seccomp_denied);
            Ok(0)
        }
        Err(jlr_cell::CellError::Refused(r)) => {
            println!("  REFUSED: mandatory controls missing: {}", r.mandatory_missing.join(", "));
            for u in &r.unavailable {
                println!("    {u}");
            }
            println!(
                "This machine cannot host JLR cells as this user. On Ubuntu 24.04 set kernel.apparmor_restrict_unprivileged_userns=0 or run jlrd as root."
            );
            Ok(2)
        }
        Err(x) => Err(x.to_string()),
    }
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).map(|s| s.trim().to_owned()).unwrap_or_default()
}

fn secure_boot() -> String {
    let dir = Path::new("/sys/firmware/efi/efivars");
    if !dir.exists() {
        return "not an EFI boot".into();
    }
    match std::fs::read_dir(dir)
        .ok()
        .and_then(|rd| rd.filter_map(Result::ok).find(|e| e.file_name().to_string_lossy().starts_with("SecureBoot-")))
    {
        Some(e) => match std::fs::read(e.path()) {
            Ok(b) if b.last() == Some(&1) => "enabled".into(),
            Ok(_) => "disabled".into(),
            Err(_) => "unreadable".into(),
        },
        None => "variable absent".into(),
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(msg) => {
            eprintln!("jlr: {msg}");
            ExitCode::from(1)
        }
    }
}
