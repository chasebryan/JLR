//! Append-only signed event store with checkpoints.

use crate::merkle::{Tree, leaf_hash};
use jlr_cbor::{Cbor, record};
use jlr_crypto::{Digest, Envelope, EnvelopeError, SigningKeypair, TrustAnchors};
use jlr_model::{AdmissionState, Basis, Event, EventKind, record_type};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const EVENTS: &str = "events.log";
const CHECKPOINTS: &str = "checkpoints.log";
const LOCK: &str = "lock";
/// Upper bound on one framed record; guards against corrupt length prefixes.
const MAX_FRAME: usize = 1 << 20;

/// What kind of external assurance backs a checkpoint counter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Anchor {
    /// A counter kept in the same storage as the ledger. Detects nothing on
    /// its own against an attacker who can rewrite both.
    Software = 1,
    /// A TPM NV counter (reserved; not implemented yet).
    Tpm = 2,
}

impl Cbor for Anchor {
    fn to_value(&self) -> jlr_cbor::Value {
        jlr_cbor::Value::Uint(*self as u64)
    }
    fn from_value(v: &jlr_cbor::Value) -> Result<Self, jlr_cbor::Error> {
        match v.as_u64()? {
            1 => Ok(Anchor::Software),
            2 => Ok(Anchor::Tpm),
            _ => Err(jlr_cbor::Error::Invalid("unknown anchor")),
        }
    }
}

record! {
    /// A signed commitment to the ledger head.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Checkpoint {
        /// Ledger identity, `jlr/<node>/evidence`.
        1 => origin: String,
        /// Number of events committed.
        2 => size: u64,
        /// Merkle root over those events.
        3 => root: Digest,
        /// Boot that wrote the checkpoint.
        4 => boot_id: [u8; 16],
        /// Wall clock seconds (advisory).
        5 => wall_time: u64,
        /// Counter value; strictly increasing across checkpoints.
        6 => counter: u64,
        /// What backs the counter.
        7 => anchor: Anchor,
    }
}

/// Everything that can go wrong opening, appending to or verifying a ledger.
#[derive(Debug)]
pub enum LedgerError {
    /// File-system failure.
    Io(std::io::Error),
    /// The ledger is already open in another process.
    Locked,
    /// A record failed verification. `seq` is its position when known.
    Corrupt {
        /// Position of the offending record.
        seq: u64,
        /// What was wrong.
        reason: String,
    },
    /// The ledger holds fewer events than an independently held checkpoint commits to.
    Truncated {
        /// Size the checkpoint commits to.
        committed: u64,
        /// Size found.
        found: u64,
    },
    /// The ledger disagrees with a checkpoint at the same or smaller size.
    Forked {
        /// Size of the checkpoint that no longer matches.
        size: u64,
    },
    /// The ledger directory has no events.
    Empty,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::Io(e) => write!(f, "ledger I/O error: {e}"),
            LedgerError::Locked => write!(f, "ledger is locked by another process"),
            LedgerError::Corrupt { seq, reason } => write!(f, "ledger record {seq} is invalid: {reason}"),
            LedgerError::Truncated { committed, found } => {
                write!(f, "ledger truncated: checkpoint commits to {committed} events, found {found}")
            }
            LedgerError::Forked { size } => write!(f, "ledger history no longer matches the checkpoint at size {size}"),
            LedgerError::Empty => write!(f, "ledger contains no events"),
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<std::io::Error> for LedgerError {
    fn from(e: std::io::Error) -> Self {
        LedgerError::Io(e)
    }
}

/// Fields the caller supplies; the ledger fills in the chain position.
#[derive(Clone, Debug)]
pub struct EventDraft {
    /// Component or operator identity.
    pub actor: String,
    /// EPN identifier of the subject.
    pub subject: Option<String>,
    /// Kind of event.
    pub kind: EventKind,
    /// State before.
    pub old_state: Option<AdmissionState>,
    /// State after.
    pub new_state: Option<AdmissionState>,
    /// Policy in force.
    pub policy: Digest,
    /// Evidence digests this event rests on.
    pub evidence: Vec<Digest>,
    /// Basis of the decision.
    pub basis: Basis,
    /// Human-readable detail.
    pub detail: String,
}

impl EventDraft {
    /// A draft with empty optional parts.
    pub fn new(actor: &str, kind: EventKind, detail: &str) -> Self {
        Self {
            actor: actor.into(),
            subject: None,
            kind,
            old_state: None,
            new_state: None,
            policy: Digest::ZERO,
            evidence: Vec::new(),
            basis: Basis::None,
            detail: detail.into(),
        }
    }
}

/// Facts learned while opening a ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenReport {
    /// Events replayed and verified.
    pub events: u64,
    /// Checkpoints replayed and verified.
    pub checkpoints: u64,
    /// Bytes of an incomplete final record that were moved to a quarantine file.
    ///
    /// A torn tail is expected after power loss during an append. The bytes are
    /// preserved in `events.log.torn.N`, and the caller must record the repair
    /// as an event rather than ignore it.
    pub torn_tail_bytes: u64,
}

/// Result of read-only verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Events verified.
    pub events: u64,
    /// Current Merkle root.
    pub root: Digest,
    /// Checkpoints verified against the tree.
    pub checkpoints: u64,
    /// Whether an external checkpoint was supplied and matched.
    pub external_checkpoint_matched: bool,
    /// Bytes of an incomplete final record.
    pub torn_tail_bytes: u64,
    /// Anchors that backed the latest checkpoint.
    pub anchor: Option<Anchor>,
}

struct Replayed {
    events_parsed: Vec<Event>,
    tree: Tree,
    last_env: Digest,
    events: u64,
    torn: u64,
    checkpoints: Vec<Checkpoint>,
    boot_ids: Vec<[u8; 16]>,
    valid_len: u64,
}

/// Size of a frame header: `u32 length || u32 check`.
const HEADER: usize = 8;

/// Frame header for a body of `len` bytes.
///
/// The check is the first four bytes of `SHA-256("JLR-frame" || len)`. It is
/// an integrity check on the length field, not a security control: it lets a
/// reader tell a corrupted length (an error) from a genuinely incomplete final
/// frame (a torn write), so a single flipped bit can never make valid events
/// look like a torn tail.
pub(crate) fn frame_header(len: u32) -> [u8; HEADER] {
    let d = Digest::of_parts("JLR-frame", &[&len.to_be_bytes()]);
    let mut h = [0u8; HEADER];
    h[..4].copy_from_slice(&len.to_be_bytes());
    h[4..].copy_from_slice(&d.0[..4]);
    h
}

fn frame(envelope: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + envelope.len());
    out.extend_from_slice(&frame_header(envelope.len() as u32));
    out.extend_from_slice(envelope);
    out
}

/// Splits a log into complete frames. Returns the frames, the number of bytes
/// they cover and the count of trailing bytes that form an incomplete final
/// frame. A frame whose header fails its check is corruption, never a torn tail.
fn split_frames(data: &[u8]) -> Result<(Vec<&[u8]>, usize, u64), LedgerError> {
    let mut frames = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        if data.len() - pos < HEADER {
            break;
        }
        let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        if data[pos..pos + HEADER] != frame_header(len) {
            return Err(LedgerError::Corrupt { seq: frames.len() as u64, reason: "frame header check failed".into() });
        }
        let len = len as usize;
        if len == 0 || len > MAX_FRAME {
            return Err(LedgerError::Corrupt {
                seq: frames.len() as u64,
                reason: format!("implausible frame length {len}"),
            });
        }
        if data.len() - pos - HEADER < len {
            break;
        }
        frames.push(&data[pos + HEADER..pos + HEADER + len]);
        pos += HEADER + len;
    }
    Ok((frames, pos, (data.len() - pos) as u64))
}

fn read_all(path: &Path) -> Result<Vec<u8>, LedgerError> {
    match File::open(path) {
        Ok(mut f) => {
            let mut v = Vec::new();
            f.read_to_end(&mut v)?;
            Ok(v)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

fn env_err(seq: u64, what: &str, e: EnvelopeError) -> LedgerError {
    LedgerError::Corrupt { seq, reason: format!("{what}: {e}") }
}

fn replay(dir: &Path, node: &str, anchors: &TrustAnchors) -> Result<Replayed, LedgerError> {
    let origin = format!("jlr/{node}/evidence");
    let events_data = read_all(&dir.join(EVENTS))?;
    let (frames, valid_len, torn) = split_frames(&events_data)?;

    let mut tree = Tree::new();
    let mut prev = Digest::ZERO;
    let mut boot_ids: Vec<[u8; 16]> = Vec::new();
    let mut parsed: Vec<Event> = Vec::with_capacity(frames.len());
    for (i, env) in frames.iter().enumerate() {
        let seq = i as u64;
        let v =
            Envelope::verify(env, record_type::EVENT, node, anchors, record_type::allowed_signers(record_type::EVENT))
                .map_err(|e| env_err(seq, "event signature", e))?;
        let ev = Event::from_cbor(&v.payload)
            .map_err(|e| LedgerError::Corrupt { seq, reason: format!("event payload: {e}") })?;
        if ev.seq != seq {
            return Err(LedgerError::Corrupt { seq, reason: format!("sequence number {} out of place", ev.seq) });
        }
        if ev.prev != prev {
            return Err(LedgerError::Corrupt { seq, reason: "previous-event link does not match".into() });
        }
        if i == 0 && ev.kind != EventKind::Genesis {
            return Err(LedgerError::Corrupt { seq, reason: "first event is not GENESIS".into() });
        }
        if i > 0 && ev.kind == EventKind::Genesis {
            return Err(LedgerError::Corrupt { seq, reason: "GENESIS may appear only once".into() });
        }
        if boot_ids.last() != Some(&ev.boot_id) {
            boot_ids.push(ev.boot_id);
        }
        prev = v.envelope_digest;
        tree.push(leaf_hash(env));
        parsed.push(ev);
    }

    let cp_data = read_all(&dir.join(CHECKPOINTS))?;
    let (cp_frames, _, cp_torn) = split_frames(&cp_data)?;
    let mut checkpoints: Vec<Checkpoint> = Vec::new();
    for (i, env) in cp_frames.iter().enumerate() {
        let seq = i as u64;
        let v = Envelope::verify(
            env,
            record_type::CHECKPOINT,
            node,
            anchors,
            record_type::allowed_signers(record_type::CHECKPOINT),
        )
        .map_err(|e| env_err(seq, "checkpoint signature", e))?;
        let cp = Checkpoint::from_cbor(&v.payload)
            .map_err(|e| LedgerError::Corrupt { seq, reason: format!("checkpoint payload: {e}") })?;
        if cp.origin != origin {
            return Err(LedgerError::Corrupt { seq, reason: "checkpoint belongs to another ledger".into() });
        }
        if let Some(last) = checkpoints.last()
            && (cp.counter <= last.counter || cp.size < last.size)
        {
            return Err(LedgerError::Corrupt { seq, reason: "checkpoint counter or size went backwards".into() });
        }
        let size = usize::try_from(cp.size).map_err(|_| LedgerError::Forked { size: cp.size })?;
        match tree.root_at(size) {
            None => return Err(LedgerError::Truncated { committed: cp.size, found: tree.size() as u64 }),
            Some(r) if r != cp.root => return Err(LedgerError::Forked { size: cp.size }),
            Some(_) => {}
        }
        checkpoints.push(cp);
    }
    let _ = cp_torn; // A torn checkpoint tail only loses the newest checkpoint.

    Ok(Replayed {
        events_parsed: parsed,
        tree,
        last_env: prev,
        events: frames.len() as u64,
        torn,
        checkpoints,
        boot_ids,
        valid_len: valid_len as u64,
    })
}

/// Verifies a ledger directory without opening it for writing.
///
/// `external` is an independently retained checkpoint envelope, for example
/// from JLR-V, recovery media or a witness. It is what turns a self-consistent
/// ledger into one that is also known not to have been rolled back.
pub fn verify_dir(
    dir: &Path,
    node: &str,
    anchors: &TrustAnchors,
    external: Option<&[u8]>,
) -> Result<VerifyReport, LedgerError> {
    let r = replay(dir, node, anchors)?;
    if r.events == 0 {
        return Err(LedgerError::Empty);
    }
    let mut matched = false;
    if let Some(bytes) = external {
        let v = Envelope::verify(
            bytes,
            record_type::CHECKPOINT,
            node,
            anchors,
            record_type::allowed_signers(record_type::CHECKPOINT),
        )
        .map_err(|e| env_err(0, "external checkpoint", e))?;
        let cp = Checkpoint::from_cbor(&v.payload)
            .map_err(|e| LedgerError::Corrupt { seq: 0, reason: format!("external checkpoint: {e}") })?;
        if cp.origin != format!("jlr/{node}/evidence") {
            return Err(LedgerError::Corrupt {
                seq: 0,
                reason: "external checkpoint belongs to another ledger".into(),
            });
        }
        if cp.size > r.events {
            return Err(LedgerError::Truncated { committed: cp.size, found: r.events });
        }
        let size = cp.size as usize;
        if r.tree.root_at(size) != Some(cp.root) {
            return Err(LedgerError::Forked { size: cp.size });
        }
        matched = true;
    }
    Ok(VerifyReport {
        events: r.events,
        root: r.tree.root(),
        checkpoints: r.checkpoints.len() as u64,
        external_checkpoint_matched: matched,
        torn_tail_bytes: r.torn,
        anchor: r.checkpoints.last().map(|c| c.anchor),
    })
}

/// Reads and fully verifies every event of a ledger directory.
///
/// Verification is identical to [`verify_dir`]; the events are returned only
/// when every signature, link and checkpoint is valid.
pub fn read_events(dir: &Path, node: &str, anchors: &TrustAnchors) -> Result<Vec<Event>, LedgerError> {
    let r = replay(dir, node, anchors)?;
    if r.events == 0 {
        return Err(LedgerError::Empty);
    }
    Ok(r.events_parsed)
}

/// A ledger open for appending.
pub struct Ledger {
    dir: PathBuf,
    node: String,
    key: SigningKeypair,
    events: File,
    checkpoints: File,
    _lock: File,
    tree: Tree,
    last_env: Digest,
    next_seq: u64,
    counter: u64,
    boot_id: [u8; 16],
    sync: bool,
}

impl fmt::Debug for Ledger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ledger")
            .field("dir", &self.dir)
            .field("node", &self.node)
            .field("next_seq", &self.next_seq)
            .finish()
    }
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).read(true).mode(0o600).open(path)
}

/// Copies the bytes after `valid_len` into a new `events.log.torn.N` file so
/// that repairing a torn write never destroys evidence.
fn quarantine_tail(dir: &Path, valid_len: u64) -> Result<(), LedgerError> {
    let data = read_all(&dir.join(EVENTS))?;
    let tail = &data[valid_len as usize..];
    for n in 0..u32::MAX {
        let path = dir.join(format!("{EVENTS}.torn.{n}"));
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(mut f) => {
                f.write_all(tail)?;
                f.sync_all()?;
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(LedgerError::Io(std::io::Error::other("too many torn-tail files")))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn lock(dir: &Path) -> Result<File, LedgerError> {
    let f = OpenOptions::new().create(true).write(true).truncate(false).mode(0o600).open(dir.join(LOCK))?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(std::fs::TryLockError::WouldBlock) => Err(LedgerError::Locked),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

impl Ledger {
    /// Creates a new ledger with a GENESIS event.
    pub fn create(dir: &Path, node: &str, key: SigningKeypair, boot_id: [u8; 16]) -> Result<Ledger, LedgerError> {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let lock = lock(dir)?;
        if dir.join(EVENTS).metadata().map(|m| m.len() > 0).unwrap_or(false) {
            return Err(LedgerError::Corrupt { seq: 0, reason: "ledger already exists".into() });
        }
        let mut l = Ledger {
            dir: dir.to_owned(),
            node: node.to_owned(),
            key,
            events: open_append(&dir.join(EVENTS))?,
            checkpoints: open_append(&dir.join(CHECKPOINTS))?,
            _lock: lock,
            tree: Tree::new(),
            last_env: Digest::ZERO,
            next_seq: 0,
            counter: 0,
            boot_id,
            sync: true,
        };
        l.append(EventDraft::new("jlr-ledger", EventKind::Genesis, &format!("ledger created for node {node}")))?;
        Ok(l)
    }

    /// Opens and fully re-verifies an existing ledger for appending.
    pub fn open(
        dir: &Path,
        node: &str,
        key: SigningKeypair,
        anchors: &TrustAnchors,
        boot_id: [u8; 16],
    ) -> Result<(Ledger, OpenReport), LedgerError> {
        let lock = lock(dir)?;
        let r = replay(dir, node, anchors)?;
        if r.events == 0 {
            return Err(LedgerError::Empty);
        }
        let _ = &r.boot_ids;
        let events = open_append(&dir.join(EVENTS))?;
        if r.torn > 0 {
            quarantine_tail(dir, r.valid_len)?;
            events.set_len(r.valid_len)?;
        }
        let counter = r.checkpoints.last().map_or(0, |c| c.counter);
        let report = OpenReport { events: r.events, checkpoints: r.checkpoints.len() as u64, torn_tail_bytes: r.torn };
        let l = Ledger {
            dir: dir.to_owned(),
            node: node.to_owned(),
            key,
            events,
            checkpoints: open_append(&dir.join(CHECKPOINTS))?,
            _lock: lock,
            tree: r.tree,
            last_env: r.last_env,
            next_seq: r.events,
            counter,
            boot_id,
            sync: true,
        };
        Ok((l, report))
    }

    /// Disables `fsync` after each append. For tests and bulk import only.
    pub fn set_sync(&mut self, sync: bool) {
        self.sync = sync;
    }

    /// Flushes appended events to stable storage.
    ///
    /// Use after a batch written with [`Ledger::set_sync`]`(false)`.
    pub fn sync(&mut self) -> Result<(), LedgerError> {
        self.events.sync_data()?;
        self.checkpoints.sync_data()?;
        Ok(())
    }

    /// Number of events in the ledger.
    pub fn len(&self) -> u64 {
        self.next_seq
    }

    /// Whether the ledger has no events (never true after `create`).
    pub fn is_empty(&self) -> bool {
        self.next_seq == 0
    }

    /// Current Merkle root.
    pub fn root(&self) -> Digest {
        self.tree.root()
    }

    /// Read access to the tree, for proofs.
    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    /// Envelope digest of the newest event.
    pub fn head(&self) -> Digest {
        self.last_env
    }

    /// Appends an event and returns its sequence number and envelope digest.
    pub fn append(&mut self, d: EventDraft) -> Result<(u64, Digest), LedgerError> {
        let ev = Event {
            seq: self.next_seq,
            boot_id: self.boot_id,
            wall_time: now(),
            mono_ns: mono_ns(),
            actor: d.actor,
            subject: d.subject,
            kind: d.kind,
            old_state: d.old_state,
            new_state: d.new_state,
            policy: d.policy,
            evidence: d.evidence,
            basis: d.basis,
            detail: d.detail,
            prev: self.last_env,
        };
        let env = Envelope::sign(record_type::EVENT, &self.node, &ev.to_cbor(), &self.key);
        self.events.write_all(&frame(&env))?;
        if self.sync {
            self.events.sync_data()?;
        }
        let digest = Digest::of(&env);
        self.tree.push(leaf_hash(&env));
        self.last_env = digest;
        self.next_seq += 1;
        Ok((ev.seq, digest))
    }

    /// Writes a signed checkpoint for the current head and returns its envelope.
    ///
    /// The returned bytes are what should be copied to storage outside the
    /// ledger's own failure domain.
    pub fn checkpoint(&mut self) -> Result<Vec<u8>, LedgerError> {
        self.counter += 1;
        let cp = Checkpoint {
            origin: format!("jlr/{}/evidence", self.node),
            size: self.tree.size() as u64,
            root: self.tree.root(),
            boot_id: self.boot_id,
            wall_time: now(),
            counter: self.counter,
            anchor: Anchor::Software,
        };
        let env = Envelope::sign(record_type::CHECKPOINT, &self.node, &cp.to_cbor(), &self.key);
        self.checkpoints.write_all(&frame(&env))?;
        if self.sync {
            self.checkpoints.sync_data()?;
        }
        Ok(env)
    }

    /// Directory this ledger lives in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

fn mono_ns() -> u64 {
    // Monotonic time since an arbitrary point, used only to order events
    // within a boot; wall time is advisory.
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}
