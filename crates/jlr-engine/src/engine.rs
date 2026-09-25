//! The engine.

use crate::error::{EngineError, runnable};
use crate::paths::Paths;
use crate::setup::hex;
use crate::store::{
    IndexFile, IndexRow, NodeInfo, get_object, has_object, load_index, put_object, save_index, sync_fs, write_atomic,
};
use jlr_cbor::{Cbor, Value};
use jlr_cell::{CellSpec, EnforcementReport, SealedExe, Stdio3, launch};
use jlr_crypto::{Digest, Envelope, SigningKeypair, TrustAnchors, random_bytes};
use jlr_ledger::{EventDraft, Ledger};
use jlr_measure::{DpkgDb, Observation, ObserveOptions, Trust, WalkOptions, observe, observe_open, walk};
use jlr_model::{
    AdmissionState, Assurance, Basis, Capability, CellClass, Decision, EpnId, EpnRecord, EventKind, EvidenceItem,
    EvidenceKind, NetworkMode, Posture, record_type,
};
use jlr_policy::{
    Approval, Baseline, Facts, Policy, RevocationEntry, RevocationKind, Revocations, VerifiedApproval,
    VerifiedBaseline, evaluate,
};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A checkpoint is written after this many events, so that opening the ledger
/// verifies at most this many signatures.
const CHECKPOINT_EVERY: u64 = 256;

/// Engine configuration.
#[derive(Clone)]
pub struct Config {
    /// Path of the `jlr-cell-init` helper binary.
    pub helper: PathBuf,
    /// Owners and groups treated as trusted writers.
    pub trust: Trust,
    /// Clock returning seconds since the Unix epoch.
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// Root of the package database to consult (`None` means `/`).
    pub dpkg_root: Option<PathBuf>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config").field("helper", &self.helper).field("trust", &self.trust).finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        let helper = std::env::var_os("JLR_CELL_INIT").map(PathBuf::from).unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("jlr-cell-init")))
                .unwrap_or_else(|| PathBuf::from("jlr-cell-init"))
        });
        Config {
            helper,
            trust: Trust::current_process(),
            clock: Arc::new(|| {
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
            }),
            dpkg_root: None,
        }
    }
}

/// Options for [`Engine::enroll_baseline`].
#[derive(Clone, Debug)]
pub struct EnrollOptions {
    /// Baseline name: alphanumeric, `-` or `_`.
    pub name: String,
    /// Cell members may run in.
    pub cell: CellClass,
    /// Network policy for that cell.
    pub network: NetworkMode,
    /// Validity in seconds.
    pub ttl_secs: u64,
    /// Operator identity for the audit trail.
    pub granted_by: String,
    /// Also enrol files no package manager vouches for.
    pub include_unmanaged: bool,
}

/// Options for [`Engine::scan`].
#[derive(Clone, Debug)]
pub struct ScanOptions {
    /// Re-hash every file even when its metadata is unchanged.
    pub full: bool,
    /// Stay on one file system per root.
    pub one_file_system: bool,
    /// Extra directories to skip.
    pub exclude: Vec<PathBuf>,
    /// Largest file to measure.
    pub max_size: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { full: false, one_file_system: true, exclude: Vec::new(), max_size: 512 << 20 }
    }
}

/// Result of a scan.
#[derive(Debug, Default)]
pub struct ScanReport {
    /// Files measured.
    pub examined: usize,
    /// Files skipped because their metadata was unchanged.
    pub unchanged: usize,
    /// Artifacts seen for the first time.
    pub new_artifacts: usize,
    /// State transitions recorded.
    pub transitions: usize,
    /// Artifacts whose content changed since they were trusted.
    pub degraded: Vec<PathBuf>,
    /// Count of artifacts in each state after the scan (only those touched or already known).
    pub by_state: BTreeMap<AdmissionState, usize>,
    /// Files that could not be measured.
    pub errors: Vec<(PathBuf, String)>,
}

/// Result of running a program.
#[derive(Debug)]
pub struct RunResult {
    /// The decision that governed the run.
    pub decision: Decision,
    /// What the jail fabric enforced.
    pub report: EnforcementReport,
    /// Exit code of the program.
    pub exit_code: i32,
    /// Captured standard output, when requested.
    pub stdout: Vec<u8>,
    /// Captured standard error, when requested.
    pub stderr: Vec<u8>,
}

/// A read-only explanation of what the engine thinks of one file.
#[derive(Debug)]
pub struct Explanation {
    /// Identity record.
    pub record: EpnRecord,
    /// Evidence gathered now.
    pub evidence: Vec<EvidenceItem>,
    /// State recorded in the ledger, if any.
    pub prior: Option<AdmissionState>,
    /// What the policy would decide now.
    pub decision: Decision,
}

/// Overall status.
#[derive(Debug)]
pub struct Status {
    /// Node identity.
    pub node_id: String,
    /// What the report may honestly claim.
    pub assurance: Assurance,
    /// Trust posture of the named scope.
    pub posture: Posture,
    /// Scope the posture applies to.
    pub scope: String,
    /// Active policy name.
    pub policy_name: String,
    /// Active policy epoch.
    pub policy_epoch: u64,
    /// Active policy digest.
    pub policy_digest: Digest,
    /// Whether the exec gate enforces (denies) or only audits.
    pub enforce_exec: bool,
    /// Revocation list epoch.
    pub revocations_epoch: u64,
    /// Number of revocation entries.
    pub revocations: usize,
    /// Artifacts per state.
    pub by_state: BTreeMap<AdmissionState, usize>,
    /// Loaded baselines with member counts.
    pub baselines: Vec<(String, usize)>,
    /// Loaded operator approvals.
    pub approvals: usize,
    /// Ledger events.
    pub ledger_events: u64,
    /// Ledger Merkle root.
    pub ledger_root: Digest,
    /// Checkpoints written so far.
    pub checkpoints: u64,
    /// Bytes of an incomplete ledger record that were quarantined at start.
    pub torn_tail_bytes: u64,
    /// Trusted keys.
    pub anchors: usize,
}

/// The engine's verdict on one attempted `exec`.
#[derive(Debug)]
pub struct ExecVerdict {
    /// Identity of what is being executed.
    pub id: EpnId,
    /// The trust decision.
    pub decision: Decision,
    /// Whether the decision permits running outside an observation cell.
    pub allowed: bool,
    /// Whether the active policy enforces (denies) rather than only audits.
    pub enforce: bool,
    /// Seconds after which this verdict must be re-derived (the policy's evidence age limit).
    pub max_age_secs: u64,
}

struct Processed {
    decision: Decision,
    transitions: usize,
    is_new: bool,
    /// A previously trusted artifact at this path was degraded because its content changed.
    degraded_prior: bool,
}

struct Seen {
    path: String,
    record: EpnRecord,
    evidence: Vec<EvidenceItem>,
    row: IndexRow,
}

/// The engine.
pub struct Engine {
    paths: Paths,
    cfg: Config,
    node: NodeInfo,
    anchors: TrustAnchors,
    policy: Policy,
    revocations: Revocations,
    baselines: Vec<(String, VerifiedBaseline)>,
    approvals: HashMap<EpnId, VerifiedApproval>,
    ledger: Ledger,
    states: HashMap<EpnId, AdmissionState>,
    index: BTreeMap<String, IndexRow>,
    checkpoints: u64,
    torn_tail_bytes: u64,
}

fn now_ns(secs: i64, nsec: i64) -> u64 {
    (secs.max(0) as u64).saturating_mul(1_000_000_000).saturating_add(nsec.max(0) as u64)
}

fn row_of(path: &str, epn: &EpnId, m: &std::fs::Metadata, measured_at: u64) -> IndexRow {
    IndexRow {
        path: path.to_owned(),
        epn: epn.to_string(),
        size: m.len(),
        mtime_ns: now_ns(m.mtime(), m.mtime_nsec()),
        ctime_ns: now_ns(m.ctime(), m.ctime_nsec()),
        ino: m.ino(),
        dev: m.dev(),
        measured_at,
    }
}

/// Shortest legal route through the admission state machine.
fn route(from: AdmissionState, to: AdmissionState) -> Option<Vec<AdmissionState>> {
    if from == to {
        return Some(vec![]);
    }
    let mut prev: HashMap<AdmissionState, AdmissionState> = HashMap::new();
    let mut q = VecDeque::from([from]);
    while let Some(s) = q.pop_front() {
        for &n in AdmissionState::ALL {
            if n != s && n != from && !prev.contains_key(&n) && s.can_become(n) {
                prev.insert(n, s);
                if n == to {
                    let mut path = vec![to];
                    let mut cur = to;
                    while let Some(&p) = prev.get(&cur) {
                        if p == from {
                            break;
                        }
                        path.push(p);
                        cur = p;
                    }
                    path.reverse();
                    return Some(path);
                }
                q.push_back(n);
            }
        }
    }
    None
}

fn parse_epoch(detail: &str) -> Option<u64> {
    detail.split("epoch=").nth(1)?.split_whitespace().next()?.parse().ok()
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").field("node", &self.node.node_id).field("artifacts", &self.states.len()).finish()
    }
}

impl Engine {
    /// Like [`Engine::open`], but waits up to `timeout` for the ledger lock.
    ///
    /// Long-lived programs (the daemon) never hold the engine for long, so a
    /// short wait lets the command line and the daemon share one state directory.
    pub fn open_wait(paths: Paths, cfg: Config, timeout: std::time::Duration) -> Result<Engine, EngineError> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match Engine::open(paths.clone(), cfg.clone()) {
                Err(EngineError::Ledger(jlr_ledger::LedgerError::Locked)) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(15));
                }
                other => return other,
            }
        }
    }

    /// Opens an initialised state directory, verifying everything it loads.
    ///
    /// Any signed object that fails verification aborts the open. The engine
    /// never substitutes a default for a policy it could not verify.
    pub fn open(paths: Paths, cfg: Config) -> Result<Engine, EngineError> {
        let node_bytes = std::fs::read(paths.node()).map_err(|_| EngineError::NotInitialised)?;
        let node =
            NodeInfo::from_cbor(&node_bytes).map_err(|e| EngineError::Verification(format!("node record: {e}")))?;
        let anchors_bytes = std::fs::read(paths.anchors())?;
        let anchors = TrustAnchors::from_cbor(&anchors_bytes)
            .map_err(|e| EngineError::Verification(format!("trust anchors: {e}")))?;

        let policy_env = std::fs::read(paths.policy())?;
        let v = Envelope::verify(
            &policy_env,
            record_type::POLICY,
            "*",
            &anchors,
            record_type::allowed_signers(record_type::POLICY),
        )
        .map_err(|e| EngineError::Verification(format!("policy: {e}")))?;
        let policy =
            Policy::from_cbor(&v.payload).map_err(|e| EngineError::Verification(format!("policy payload: {e}")))?;
        policy.validate().map_err(|e| EngineError::Verification(e.to_string()))?;

        let rev_env = std::fs::read(paths.revocations())?;
        let v = Envelope::verify(
            &rev_env,
            record_type::REVOCATIONS,
            "*",
            &anchors,
            record_type::allowed_signers(record_type::REVOCATIONS),
        )
        .map_err(|e| EngineError::Verification(format!("revocations: {e}")))?;
        let revocations = Revocations::from_cbor(&v.payload)
            .map_err(|e| EngineError::Verification(format!("revocations payload: {e}")))?;

        let device = SigningKeypair::load(&paths.device_key())
            .map_err(|e| EngineError::Verification(format!("device key: {e}")))?;
        let boot = random_bytes::<16>().map_err(|e| EngineError::Invalid(e.to_string()))?;
        let (mut ledger, report, events) =
            Ledger::open_with_events(&paths.ledger(), &node.node_id, device, &anchors, boot)?;

        // State is derived from the ledger, never from a cache.
        let mut states: HashMap<EpnId, AdmissionState> = HashMap::new();
        let mut policy_floor = 0u64;
        let mut rev_floor = 0u64;
        for e in &events {
            if let (Some(subject), Some(new)) = (&e.subject, e.new_state)
                && let Some(id) = EpnId::parse(subject)
            {
                states.insert(id, new);
            }
            match e.kind {
                EventKind::PolicyLoad => policy_floor = policy_floor.max(parse_epoch(&e.detail).unwrap_or(0)),
                EventKind::Revocation => rev_floor = rev_floor.max(parse_epoch(&e.detail).unwrap_or(0)),
                _ => {}
            }
        }
        if policy.epoch < policy_floor {
            return Err(EngineError::Rollback(format!(
                "policy epoch {} is older than the recorded epoch {policy_floor}",
                policy.epoch
            )));
        }
        if revocations.epoch < rev_floor {
            return Err(EngineError::Rollback(format!(
                "revocation epoch {} is older than the recorded epoch {rev_floor}",
                revocations.epoch
            )));
        }

        let mut baselines = Vec::new();
        let mut approvals = HashMap::new();
        let mut problems: Vec<String> = Vec::new();
        for entry in read_dir_sorted(&paths.baselines()) {
            match std::fs::read(&entry)
                .map_err(|e| e.to_string())
                .and_then(|b| Baseline::verify(&b, &node.node_id, &anchors).map_err(|e| e.to_string()))
            {
                Ok(b) => baselines.push((b.get().name.clone(), b)),
                Err(e) => problems.push(format!("baseline {}: {e}", entry.display())),
            }
        }
        for entry in read_dir_sorted(&paths.approvals()) {
            match std::fs::read(&entry)
                .map_err(|e| e.to_string())
                .and_then(|b| Approval::verify(&b, &node.node_id, &anchors).map_err(|e| e.to_string()))
            {
                Ok(a) => {
                    if let Some(id) = EpnId::parse(&a.get().epn) {
                        approvals.insert(id, a);
                    }
                }
                Err(e) => problems.push(format!("approval {}: {e}", entry.display())),
            }
        }

        if report.torn_tail_bytes > 0 {
            let mut d = EventDraft::new(
                "jlr-engine",
                EventKind::Degraded,
                &format!(
                    "recovered an incomplete ledger record of {} bytes; kept in a quarantine file",
                    report.torn_tail_bytes
                ),
            );
            d.policy = policy.digest();
            ledger.append(d)?;
        }
        for p in &problems {
            // A signed object that does not verify grants nothing and is reported.
            let mut d =
                EventDraft::new("jlr-engine", EventKind::Degraded, &format!("ignored unverifiable object: {p}"));
            d.policy = policy.digest();
            ledger.append(d)?;
        }

        let index = load_index(&paths).rows.into_iter().map(|r| (r.path.clone(), r)).collect();
        Ok(Engine {
            paths,
            cfg,
            node,
            anchors,
            policy,
            revocations,
            baselines,
            approvals,
            ledger,
            states,
            index,
            checkpoints: report.checkpoints,
            torn_tail_bytes: report.torn_tail_bytes,
        })
    }

    fn now(&self) -> u64 {
        (self.cfg.clock)()
    }

    /// Makes every object durable, then the ledger. The order matters: an event
    /// must never reference an object that a crash could still lose.
    fn flush(&mut self) -> Result<(), EngineError> {
        sync_fs(self.paths.root())?;
        // Keep the tail that must be verified in full at the next start short.
        if self.ledger.events_since_checkpoint() >= CHECKPOINT_EVERY {
            self.ledger.checkpoint()?;
            self.checkpoints += 1;
        }
        self.ledger.sync()?;
        Ok(())
    }

    fn load_dpkg(&self) -> Option<DpkgDb> {
        let root = self.cfg.dpkg_root.as_deref().unwrap_or(Path::new("/"));
        DpkgDb::load_cached(root, &self.paths.cache().join("dpkg.idx")).ok()
    }

    /// Reads the most recent ledger events, oldest first, after full verification.
    pub fn recent_events(&self, n: usize) -> Result<Vec<jlr_model::Event>, EngineError> {
        let mut all = jlr_ledger::read_events(&self.paths.ledger(), &self.node.node_id, &self.anchors)?;
        let skip = all.len().saturating_sub(n);
        Ok(all.split_off(skip))
    }

    /// Node identity.
    pub fn node_id(&self) -> &str {
        &self.node.node_id
    }

    /// The active policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// State of an artifact according to the ledger.
    pub fn state_of(&self, id: &EpnId) -> Option<AdmissionState> {
        self.states.get(id).copied()
    }

    #[allow(clippy::too_many_arguments)]
    fn log(
        &mut self,
        kind: EventKind,
        subject: Option<&EpnId>,
        old: Option<AdmissionState>,
        new: Option<AdmissionState>,
        evidence: Vec<Digest>,
        basis: Basis,
        detail: &str,
    ) -> Result<(), EngineError> {
        let mut d = EventDraft::new("jlr-engine", kind, detail);
        d.subject = subject.map(ToString::to_string);
        d.old_state = old;
        d.new_state = new;
        d.evidence = evidence;
        d.basis = basis;
        d.policy = self.policy.digest();
        self.ledger.append(d)?;
        Ok(())
    }

    fn approval_for(&self, id: &EpnId, now: u64) -> Option<VerifiedApproval> {
        if let Some(a) = self.approvals.get(id).filter(|a| a.applies_to(id, now)) {
            return Some(a.clone());
        }
        self.baselines.iter().find_map(|(_, b)| b.approval_for(id, now))
    }

    fn store_evidence(&self, items: &[EvidenceItem]) -> Result<Digest, EngineError> {
        let v = Value::Array(items.iter().map(Cbor::to_value).collect());
        Ok(put_object(&self.paths, "evidence", &jlr_cbor::encode(&v))?)
    }

    /// Applies a decision to the ledger, one legal step at a time.
    fn apply_decision(
        &mut self,
        id: &EpnId,
        decision: &Decision,
        evidence: Digest,
        detail: &str,
    ) -> Result<usize, EngineError> {
        let prior = self.states.get(id).copied();
        let from = prior.unwrap_or(AdmissionState::Unknown);
        if prior == Some(decision.state) {
            return Ok(0);
        }
        let steps = route(from, decision.state)
            .ok_or_else(|| EngineError::Invalid(format!("no legal route {from} -> {}", decision.state)))?;
        let n = steps.len();
        let reasons: Vec<String> = decision.reasons.iter().map(ToString::to_string).collect();
        let mut cur = prior;
        for (i, step) in steps.into_iter().enumerate() {
            // Intermediate steps of a manual promotion carry the manual basis too.
            let d = format!("{detail} [{}] step {}/{}", reasons.join(","), i + 1, n);
            self.log(EventKind::Transition, Some(id), cur, Some(step), vec![evidence], decision.basis, &d)?;
            self.states.insert(*id, step);
            cur = Some(step);
        }
        Ok(n)
    }

    fn evaluate_now(&self, record: &EpnRecord, evidence: &[EvidenceItem], requested: &[Capability]) -> Decision {
        let id = record.id();
        let now = self.now();
        let approval = self.approval_for(&id, now);
        evaluate(
            &self.policy,
            &Facts {
                artifact: record,
                evidence,
                requested,
                prior: self.states.get(&id).copied(),
                revocations: &self.revocations,
                approval: approval.as_ref(),
            },
            now,
        )
    }

    fn store_record(&mut self, record: &EpnRecord) -> Result<bool, EngineError> {
        let id = record.id();
        if has_object(&self.paths, "epn", &id.digest) {
            return Ok(false);
        }
        put_object(&self.paths, "epn", &record.to_cbor())?;
        Ok(true)
    }

    fn load_record(&self, id: &EpnId) -> Option<EpnRecord> {
        get_object(&self.paths, "epn", &id.digest).ok().and_then(|b| EpnRecord::from_cbor(&b).ok())
    }

    /// Handles a path whose content changed since it was last measured.
    fn on_replaced(&mut self, old: &EpnId, path: &str) -> Result<(usize, bool), EngineError> {
        let Some(old_state) = self.states.get(old).copied() else { return Ok((0, false)) };
        if matches!(old_state, AdmissionState::Revoked | AdmissionState::Degraded | AdmissionState::Quarantined) {
            return Ok((0, false));
        }
        let Some(record) = self.load_record(old) else { return Ok((0, false)) };
        let mismatch = EvidenceItem {
            kind: EvidenceKind::ContentDigestMismatch,
            source: "measure".into(),
            at: self.now(),
            detail: format!("content at {path} no longer matches {old}"),
            digest: None,
        };
        let ev = self.store_evidence(std::slice::from_ref(&mismatch))?;
        self.log(
            EventKind::Mismatch,
            Some(old),
            Some(old_state),
            None,
            vec![ev],
            Basis::None,
            &format!("content at {path} changed"),
        )?;
        let decision = self.evaluate_now(&record, std::slice::from_ref(&mismatch), &[]);
        let n = self.apply_decision(old, &decision, ev, &format!("content changed at {path}"))?;
        Ok((n, self.states.get(old) == Some(&AdmissionState::Degraded)))
    }

    fn process(&mut self, seen: &Seen, requested: &[Capability]) -> Result<Processed, EngineError> {
        let id = seen.record.id();
        let mut transitions = 0;
        let mut degraded_prior = false;
        if let Some(old) = self.index.get(&seen.path).and_then(|r| EpnId::parse(&r.epn))
            && old != id
        {
            let (n, degraded) = self.on_replaced(&old, &seen.path)?;
            transitions += n;
            degraded_prior = degraded;
        }
        let is_new = self.store_record(&seen.record)?;
        let ev = self.store_evidence(&seen.evidence)?;
        let known = self.states.contains_key(&id);
        if is_new || !known {
            self.log(
                EventKind::Discover,
                Some(&id),
                None,
                None,
                vec![ev],
                Basis::None,
                &format!("{} {} at {}", seen.record.class, seen.record.name, seen.path),
            )?;
        }
        let decision = self.evaluate_now(&seen.record, &seen.evidence, requested);
        transitions += self.apply_decision(&id, &decision, ev, &format!("{} at {}", seen.record.name, seen.path))?;
        self.index.insert(seen.path.clone(), seen.row.clone());
        Ok(Processed { decision, transitions, is_new: is_new || !known, degraded_prior })
    }

    fn observe_opts(&self) -> ObserveOptions {
        ObserveOptions { trust: self.cfg.trust.clone(), now: self.now(), ..ObserveOptions::default() }
    }

    fn seen_from(&self, obs: &Observation) -> Result<Seen, EngineError> {
        let path = obs.path.to_string_lossy().into_owned();
        let meta = obs.file.metadata()?;
        Ok(Seen {
            row: row_of(&path, &obs.record.id(), &meta, self.now()),
            path,
            record: obs.record.clone(),
            evidence: obs.evidence.clone(),
        })
    }

    /// Measures and admits every governed artifact below `roots`.
    pub fn scan(&mut self, roots: &[PathBuf], opts: &ScanOptions) -> Result<ScanReport, EngineError> {
        self.scan_inner(roots, opts, None).map(|(r, _)| r)
    }

    fn scan_inner(
        &mut self,
        roots: &[PathBuf],
        opts: &ScanOptions,
        collect: Option<&mut Vec<Seen>>,
    ) -> Result<(ScanReport, ()), EngineError> {
        let files = list_artifacts(roots, opts)?;
        self.scan_files_inner(&files, opts, collect)
    }

    /// Measures and admits the given files. Use with [`list_artifacts`] to scan in bounded slices
    /// so that no single call holds the ledger for long.
    pub fn scan_files(&mut self, files: &[PathBuf], opts: &ScanOptions) -> Result<ScanReport, EngineError> {
        self.scan_files_inner(files, opts, None).map(|(r, _)| r)
    }

    fn scan_files_inner(
        &mut self,
        files: &[PathBuf],
        opts: &ScanOptions,
        mut collect: Option<&mut Vec<Seen>>,
    ) -> Result<(ScanReport, ()), EngineError> {
        let mut report = ScanReport::default();
        let mut dpkg = self.load_dpkg();
        let observe_opts = ObserveOptions { max_size: opts.max_size, ..self.observe_opts() };
        self.ledger.set_sync(false);
        let result = (|| -> Result<(), EngineError> {
            for path in files {
                let pstr = path.to_string_lossy().into_owned();
                let Ok(meta) = std::fs::symlink_metadata(path) else { continue };
                if !opts.full
                    && collect.is_none()
                    && let Some(row) = self.index.get(&pstr)
                    && row.size == meta.len()
                    && row.mtime_ns == now_ns(meta.mtime(), meta.mtime_nsec())
                    && row.ctime_ns == now_ns(meta.ctime(), meta.ctime_nsec())
                    && row.ino == meta.ino()
                    && row.dev == meta.dev()
                    && self.now().saturating_sub(row.measured_at) < self.policy.evidence_max_age_secs
                    && EpnId::parse(&row.epn).is_some_and(|id| self.states.contains_key(&id))
                {
                    report.unchanged += 1;
                    continue;
                }
                match observe(path, dpkg.as_mut(), &observe_opts) {
                    Ok(obs) => {
                        report.examined += 1;
                        let seen = self.seen_from(&obs)?;
                        drop(obs);
                        if let Some(c) = collect.as_deref_mut() {
                            c.push(seen);
                        } else {
                            let p = self.process(&seen, &[])?;
                            report.transitions += p.transitions;
                            report.new_artifacts += usize::from(p.is_new);
                            *report.by_state.entry(p.decision.state).or_default() += 1;
                            if p.degraded_prior || p.decision.state == AdmissionState::Degraded {
                                report.degraded.push(path.clone());
                            }
                        }
                    }
                    Err(e) => report.errors.push((path.clone(), e.to_string())),
                }
            }
            Ok(())
        })();
        self.ledger.set_sync(true);
        self.flush()?;
        self.save_index()?;
        result?;
        Ok((report, ()))
    }

    /// Decides whether an `exec` of the open file `file` may proceed.
    ///
    /// The bytes are measured through the descriptor the kernel delivered, so a
    /// path swapped afterwards changes nothing. Discoveries and transitions are
    /// recorded exactly as for a scan.
    pub fn decide_exec(&mut self, file: std::fs::File, path: &Path) -> Result<ExecVerdict, EngineError> {
        let mut dpkg = self.load_dpkg();
        let obs = observe_open(file, path, dpkg.as_mut(), &self.observe_opts())?;
        let id = obs.record.id();
        let seen = self.seen_from(&obs)?;
        drop(obs);
        let p = self.process(&seen, &[])?;
        self.save_index()?;
        self.flush()?;
        Ok(ExecVerdict {
            id,
            allowed: p.decision.state.permits_normal_execution(),
            decision: p.decision,
            enforce: self.policy.enforce_exec,
            max_age_secs: self.policy.evidence_max_age_secs,
        })
    }

    /// Records the outcome of an exec decision in the ledger.
    pub fn record_exec(
        &mut self,
        id: &EpnId,
        path: &str,
        verdict: &str,
        decision: &Decision,
    ) -> Result<(), EngineError> {
        let reasons: Vec<String> = decision.reasons.iter().map(ToString::to_string).collect();
        let detail = format!("exec gate: {verdict} {path}: state {} [{}]", decision.state, reasons.join(","));
        self.log(EventKind::Enforcement, Some(id), None, None, vec![], Basis::Policy, &detail)?;
        self.flush()
    }

    /// Records a degraded condition of a component such as the exec gate.
    pub fn record_degraded(&mut self, detail: &str) -> Result<(), EngineError> {
        self.log(EventKind::Degraded, None, None, None, vec![], Basis::None, detail)?;
        self.flush()
    }

    fn save_index(&self) -> Result<(), EngineError> {
        let file = IndexFile { rows: self.index.values().cloned().collect() };
        save_index(&self.paths, &file)?;
        Ok(())
    }

    /// Enrols the artifacts below `roots` as an operator-signed baseline.
    ///
    /// Only artifacts the local package database vouches for and whose bytes
    /// match its manifest become members; everything else is processed under
    /// ordinary policy. The baseline is authority, not proof, and members are
    /// recorded as manual overrides.
    pub fn enroll_baseline(
        &mut self,
        roots: &[PathBuf],
        enroll: &EnrollOptions,
        opts: &ScanOptions,
    ) -> Result<(ScanReport, usize), EngineError> {
        let EnrollOptions { name, cell, network, ttl_secs, granted_by, include_unmanaged } = enroll.clone();
        let (name, granted_by) = (name.as_str(), granted_by.as_str());
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(EngineError::Invalid("baseline name must be alphanumeric, '-' or '_'".into()));
        }
        let key = SigningKeypair::load(&self.paths.policy_key())
            .map_err(|e| EngineError::Verification(format!("policy key: {e}")))?;
        let mut seen: Vec<Seen> = Vec::new();
        let (mut report, ()) = self.scan_inner(roots, opts, Some(&mut seen))?;
        let members: Vec<Digest> = seen
            .iter()
            .filter(|s| {
                let has = |k| s.evidence.iter().any(|e| e.kind == k);
                let vouched = include_unmanaged
                    || (has(EvidenceKind::ManagedInstaller) && has(EvidenceKind::PackageManifestMatch));
                vouched
                    && !has(EvidenceKind::ContentDigestMismatch)
                    && !has(EvidenceKind::SignatureInvalid)
                    && !has(EvidenceKind::ForbiddenBehavior)
            })
            .map(|s| s.record.id().digest)
            .collect();
        let mut baseline = Baseline {
            schema: 1,
            name: name.to_owned(),
            cell,
            network,
            capabilities: vec![],
            granted_by: granted_by.to_owned(),
            expires_at: self.now().saturating_add(ttl_secs),
            members,
        };
        baseline.normalize();
        let count = baseline.members.len();
        let bytes = baseline.sign(&self.node.node_id, &key);
        let verified = Baseline::verify(&bytes, &self.node.node_id, &self.anchors)
            .map_err(|e| EngineError::Verification(e.to_string()))?;
        write_atomic(&self.paths.baselines().join(format!("{name}.cose")), &bytes)?;
        self.baselines.retain(|(n, _)| n != name);
        self.baselines.push((name.to_owned(), verified));
        self.log(
            EventKind::Override,
            None,
            None,
            None,
            vec![Digest::of(&bytes)],
            Basis::ManualOverride,
            &format!("baseline {name} enrolled by {granted_by}: {count} members"),
        )?;

        self.ledger.set_sync(false);
        let mut fail = None;
        for s in &seen {
            match self.process(s, &[]) {
                Ok(p) => {
                    report.transitions += p.transitions;
                    report.new_artifacts += usize::from(p.is_new);
                    *report.by_state.entry(p.decision.state).or_default() += 1;
                    if p.degraded_prior || p.decision.state == AdmissionState::Degraded {
                        report.degraded.push(PathBuf::from(&s.path));
                    }
                }
                Err(e) => {
                    fail = Some(e);
                    break;
                }
            }
        }
        self.ledger.set_sync(true);
        self.flush()?;
        self.save_index()?;
        if let Some(e) = fail {
            return Err(e);
        }
        Ok((report, count))
    }

    /// Explains what the engine currently thinks of a file without changing anything.
    pub fn explain(&self, path: &Path) -> Result<Explanation, EngineError> {
        let mut dpkg = self.load_dpkg();
        let obs = observe(path, dpkg.as_mut(), &self.observe_opts())?;
        let id = obs.record.id();
        let decision = self.evaluate_now(&obs.record, &obs.evidence, &[]);
        Ok(Explanation { prior: self.states.get(&id).copied(), record: obs.record, evidence: obs.evidence, decision })
    }

    /// Runs a program in the cell its decision prescribes.
    ///
    /// The file is measured once, copied into a sealed memfd while being hashed
    /// again, and that descriptor is what executes.
    pub fn run(
        &mut self,
        path: &Path,
        args: &[String],
        env: &[String],
        requested: &[Capability],
        capture: bool,
    ) -> Result<RunResult, EngineError> {
        let mut dpkg = self.load_dpkg();
        let mut obs = observe(path, dpkg.as_mut(), &self.observe_opts())?;
        let seen = self.seen_from(&obs)?;
        let decision = self.process(&seen, requested)?.decision;
        self.save_index()?;
        let id = obs.record.id();
        if !runnable(decision.state) {
            self.log(
                EventKind::Enforcement,
                Some(&id),
                None,
                None,
                vec![],
                Basis::None,
                &format!("denied execution of {}: state {}", seen.path, decision.state),
            )?;
            self.flush()?;
            return Err(EngineError::NotRunnable(Box::new(decision)));
        }
        let mut argv = vec![obs.record.name.clone()];
        argv.extend(args.iter().cloned());
        let spec = CellSpec::from_decision(&decision, argv, env.to_vec())?;
        let sealed = SealedExe::seal(&mut obs.file, &obs.record.digest, 512 << 20)?;
        let io = if capture { Stdio3::captured() } else { Stdio3::inherit() };
        let running = match launch(&self.cfg.helper, &sealed, &spec, io) {
            Ok(r) => r,
            Err(e) => {
                let detail = format!("could not start {}: {e}", seen.path);
                self.log(EventKind::Enforcement, Some(&id), None, None, vec![], Basis::None, &detail)?;
                self.flush()?;
                return Err(e.into());
            }
        };
        let report = running.report().clone();
        let rd = put_object(&self.paths, "report", &report.to_cbor())?;
        self.log(
            EventKind::Enforcement,
            Some(&id),
            None,
            None,
            vec![rd],
            decision.basis,
            &format!(
                "started {} in {} network={} status={:?} active=[{}] unavailable=[{}]",
                seen.path,
                decision.cell,
                decision.network,
                report.status,
                report.active.join(","),
                report.unavailable.join("; ")
            ),
        )?;
        let (outcome, stdout, stderr) =
            if capture { running.wait_with_output()? } else { (running.wait()?, Vec::new(), Vec::new()) };
        self.log(
            EventKind::Enforcement,
            Some(&id),
            None,
            None,
            vec![],
            Basis::None,
            &format!("{} exited with code {}", seen.path, outcome.code),
        )?;
        self.flush()?;
        Ok(RunResult { decision, report, exit_code: outcome.code, stdout, stderr })
    }

    /// Records an operator approval for a known artifact and applies it.
    pub fn approve(
        &mut self,
        epn: &str,
        cell: CellClass,
        network: NetworkMode,
        capabilities: Vec<Capability>,
        ttl_secs: u64,
        granted_by: &str,
    ) -> Result<Decision, EngineError> {
        let id = EpnId::parse(epn).ok_or_else(|| EngineError::Invalid(format!("not an EPN identifier: {epn}")))?;
        if !self.states.contains_key(&id) {
            return Err(EngineError::Invalid(format!("{id} is not known to this machine")));
        }
        let record = self
            .load_record(&id)
            .ok_or_else(|| EngineError::Invalid("the artifact's record is missing from the object store".into()))?;
        let key = SigningKeypair::load(&self.paths.policy_key())
            .map_err(|e| EngineError::Verification(format!("policy key: {e}")))?;
        let approval = Approval {
            epn: id.to_string(),
            cell,
            network,
            capabilities,
            expires_at: self.now().saturating_add(ttl_secs),
            granted_by: granted_by.to_owned(),
        };
        let bytes = approval.sign(&self.node.node_id, &key);
        let verified = Approval::verify(&bytes, &self.node.node_id, &self.anchors)
            .map_err(|e| EngineError::Verification(e.to_string()))?;
        write_atomic(&self.paths.approvals().join(format!("{}.cose", id.digest.hex())), &bytes)?;
        self.approvals.insert(id, verified);
        self.log(
            EventKind::Override,
            Some(&id),
            None,
            None,
            vec![Digest::of(&bytes)],
            Basis::ManualOverride,
            &format!("operator {granted_by} approved {} cell={cell} network={network}", record.name),
        )?;
        // Re-evaluate with the evidence that is true now.
        let path = self.index.values().find(|r| r.epn == id.to_string()).map(|r| PathBuf::from(&r.path));
        let decision = match path {
            Some(p) if p.exists() => {
                let mut dpkg = self.load_dpkg();
                let obs = observe(&p, dpkg.as_mut(), &self.observe_opts())?;
                let seen = self.seen_from(&obs)?;
                drop(obs);
                let d = self.process(&seen, &[])?.decision;
                self.save_index()?;
                d
            }
            _ => self.evaluate_now(&record, &[], &[]),
        };
        self.flush()?;
        Ok(decision)
    }

    /// Adds a revocation, signs the new list and applies it to known artifacts.
    pub fn revoke(&mut self, kind: RevocationKind, target: &str, reason: &str) -> Result<usize, EngineError> {
        let key = SigningKeypair::load(&self.paths.policy_key())
            .map_err(|e| EngineError::Verification(format!("policy key: {e}")))?;
        let mut list = self.revocations.clone();
        list.epoch += 1;
        list.entries.push(RevocationEntry { kind, target: target.to_owned(), reason: reason.to_owned() });
        let bytes = Envelope::sign(record_type::REVOCATIONS, "*", &list.to_cbor(), &key);
        Envelope::verify(
            &bytes,
            record_type::REVOCATIONS,
            "*",
            &self.anchors,
            record_type::allowed_signers(record_type::REVOCATIONS),
        )
        .map_err(|e| EngineError::Verification(e.to_string()))?;
        write_atomic(&self.paths.revocations(), &bytes)?;
        self.revocations = list;
        self.log(
            EventKind::Revocation,
            None,
            None,
            None,
            vec![Digest::of(&bytes)],
            Basis::Policy,
            &format!("revocations epoch={} added {kind:?} {target}: {reason}", self.revocations.epoch),
        )?;

        let ids: Vec<EpnId> =
            self.states.iter().filter(|(_, s)| **s != AdmissionState::Revoked).map(|(i, _)| *i).collect();
        let mut n = 0;
        for id in ids {
            let Some(record) = self.load_record(&id) else { continue };
            if self.revocations.hit(&record).is_some() {
                let d = self.evaluate_now(&record, &[], &[]);
                let ev = self.store_evidence(&[])?;
                n += self.apply_decision(&id, &d, ev, &format!("revoked: {reason}"))?;
            }
        }
        self.flush()?;
        Ok(n)
    }

    /// Installs a new signed policy. The epoch must be strictly greater than the current one.
    pub fn set_policy(&mut self, new: Policy) -> Result<Digest, EngineError> {
        new.validate().map_err(|e| EngineError::Invalid(e.to_string()))?;
        if new.epoch <= self.policy.epoch {
            return Err(EngineError::Rollback(format!(
                "policy epoch {} must be greater than the current epoch {}",
                new.epoch, self.policy.epoch
            )));
        }
        let key = SigningKeypair::load(&self.paths.policy_key())
            .map_err(|e| EngineError::Verification(format!("policy key: {e}")))?;
        let bytes = Envelope::sign(record_type::POLICY, "*", &new.to_cbor(), &key);
        Envelope::verify(
            &bytes,
            record_type::POLICY,
            "*",
            &self.anchors,
            record_type::allowed_signers(record_type::POLICY),
        )
        .map_err(|e| EngineError::Verification(e.to_string()))?;
        write_atomic(&self.paths.policy(), &bytes)?;
        let digest = new.digest();
        let detail = format!("policy={} epoch={} digest={}", new.name, new.epoch, digest);
        self.policy = new;
        self.log(EventKind::PolicyLoad, None, None, None, vec![digest], Basis::Policy, &detail)?;
        self.flush()?;
        Ok(digest)
    }

    /// Writes a signed checkpoint and returns its envelope for off-machine storage.
    pub fn checkpoint(&mut self) -> Result<Vec<u8>, EngineError> {
        let cp = self.ledger.checkpoint()?;
        self.checkpoints += 1;
        Ok(cp)
    }

    /// Re-verifies the whole ledger, optionally against an independently held checkpoint.
    pub fn verify_ledger(&self, external: Option<&[u8]>) -> Result<jlr_ledger::VerifyReport, EngineError> {
        Ok(jlr_ledger::verify_dir(&self.paths.ledger(), &self.node.node_id, &self.anchors, external)?)
    }

    /// Summarises the current state.
    pub fn status(&self) -> Status {
        let mut by_state: BTreeMap<AdmissionState, usize> = BTreeMap::new();
        for s in self.states.values() {
            *by_state.entry(*s).or_default() += 1;
        }
        let degraded = by_state.get(&AdmissionState::Degraded).copied().unwrap_or(0);
        let posture = if degraded > 0 || self.torn_tail_bytes > 0 { Posture::Degraded } else { Posture::Proven };
        Status {
            node_id: self.node.node_id.clone(),
            assurance: Assurance::Companion,
            posture,
            scope: format!("ledger, policy, keys and {} known artifacts", self.states.len()),
            policy_name: self.policy.name.clone(),
            policy_epoch: self.policy.epoch,
            policy_digest: self.policy.digest(),
            enforce_exec: self.policy.enforce_exec,
            revocations_epoch: self.revocations.epoch,
            revocations: self.revocations.entries.len(),
            by_state,
            baselines: self.baselines.iter().map(|(n, b)| (n.clone(), b.get().members.len())).collect(),
            approvals: self.approvals.len(),
            ledger_events: self.ledger.len(),
            ledger_root: self.ledger.root(),
            checkpoints: self.checkpoints,
            torn_tail_bytes: self.torn_tail_bytes,
            anchors: self.anchors.len(),
        }
    }

    /// Node identifier in hexadecimal for display.
    pub fn short_node(&self) -> String {
        hex(&Digest::of(self.node.node_id.as_bytes()).0[..4])
    }
}

/// Lists governed files below `roots` in a deterministic order, without touching engine state.
pub fn list_artifacts(roots: &[PathBuf], opts: &ScanOptions) -> Result<Vec<PathBuf>, EngineError> {
    let mut all = Vec::new();
    for root in roots {
        let mut wo = WalkOptions { one_file_system: opts.one_file_system, ..WalkOptions::default() };
        wo.exclude.extend(opts.exclude.iter().cloned());
        all.extend(walk(root, &wo)?);
    }
    Ok(all)
}

fn read_dir_sorted(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "cose")).collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}
