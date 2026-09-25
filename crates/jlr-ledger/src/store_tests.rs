use super::*;
use jlr_crypto::{Role, SigningKeypair, TrustAnchors};
use jlr_model::EventKind;
use std::fs;
use tempfile::TempDir;

const NODE: &str = "node-test";
const BOOT: [u8; 16] = [7; 16];

fn key() -> SigningKeypair {
    SigningKeypair::from_seed([42; 32], Role::Device)
}

fn anchors() -> TrustAnchors {
    let mut a = TrustAnchors::new();
    a.insert(key().public());
    a
}

fn fresh(n: usize) -> (TempDir, Ledger) {
    let dir = tempfile::tempdir().unwrap();
    let mut l = Ledger::create(&dir.path().join("ev"), NODE, key(), BOOT).unwrap();
    l.set_sync(false);
    for i in 0..n {
        l.append(EventDraft::new("test", EventKind::Discover, &format!("event {i}"))).unwrap();
    }
    (dir, l)
}

fn path(dir: &TempDir) -> std::path::PathBuf {
    dir.path().join("ev")
}

#[test]
fn create_append_verify() {
    let (dir, mut l) = fresh(5);
    assert_eq!(l.len(), 6); // genesis + 5
    let cp = l.checkpoint().unwrap();
    drop(l);
    let r = verify_dir(&path(&dir), NODE, &anchors(), Some(&cp)).unwrap();
    assert_eq!(r.events, 6);
    assert_eq!(r.checkpoints, 1);
    assert!(r.external_checkpoint_matched);
    assert_eq!(r.anchor, Some(Anchor::Software));
    assert_eq!(r.torn_tail_bytes, 0);
}

#[test]
fn reopen_continues_the_chain() {
    let (dir, l) = fresh(3);
    let root_before = l.root();
    drop(l);
    let (mut l, rep) = Ledger::open(&path(&dir), NODE, key(), &anchors(), [8; 16]).unwrap();
    assert_eq!(rep.events, 4);
    assert_eq!(l.root(), root_before);
    l.append(EventDraft::new("test", EventKind::Boot, "second boot")).unwrap();
    drop(l);
    let r = verify_dir(&path(&dir), NODE, &anchors(), None).unwrap();
    assert_eq!(r.events, 5);
}

#[test]
fn second_writer_is_refused() {
    let (dir, l) = fresh(0);
    let err = Ledger::open(&path(&dir), NODE, key(), &anchors(), BOOT).unwrap_err();
    assert!(matches!(err, LedgerError::Locked), "{err}");
    drop(l);
    assert!(Ledger::open(&path(&dir), NODE, key(), &anchors(), BOOT).is_ok());
}

fn frame_spans(data: &[u8]) -> Vec<(usize, usize)> {
    let mut pos = 0;
    let mut spans = Vec::new();
    while pos + 8 <= data.len() {
        let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        if pos + 8 + len > data.len() {
            break;
        }
        spans.push((pos, pos + 8 + len));
        pos += 8 + len;
    }
    spans
}

#[test]
fn flipped_byte_anywhere_is_an_error() {
    // Every single-bit change to the log, including in frame headers, must be
    // reported as corruption. A damaged length field must never masquerade as a
    // torn tail, because opening a ledger with a torn tail rewrites the file.
    let (dir, l) = fresh(4);
    drop(l);
    let file = path(&dir).join("events.log");
    let good = fs::read(&file).unwrap();
    for i in 0..good.len() {
        for bit in [0u8, 3, 7] {
            let mut bad = good.clone();
            bad[i] ^= 1 << bit;
            fs::write(&file, &bad).unwrap();
            assert!(
                verify_dir(&path(&dir), NODE, &anchors(), None).is_err(),
                "flip at byte {i} bit {bit} went unnoticed"
            );
        }
    }
}

#[test]
fn deleting_an_event_from_the_middle_is_detected() {
    let (dir, l) = fresh(4);
    drop(l);
    let file = path(&dir).join("events.log");
    let data = fs::read(&file).unwrap();
    let (s, e) = frame_spans(&data)[2];
    let mut cut = data[..s].to_vec();
    cut.extend_from_slice(&data[e..]);
    fs::write(&file, cut).unwrap();
    let err = verify_dir(&path(&dir), NODE, &anchors(), None).unwrap_err();
    assert!(matches!(err, LedgerError::Corrupt { .. }), "{err}");
}

#[test]
fn reordering_events_is_detected() {
    let (dir, l) = fresh(3);
    drop(l);
    let file = path(&dir).join("events.log");
    let data = fs::read(&file).unwrap();
    let mut frames: Vec<Vec<u8>> = frame_spans(&data).into_iter().map(|(s, e)| data[s..e].to_vec()).collect();
    frames.swap(1, 2);
    fs::write(&file, frames.concat()).unwrap();
    assert!(verify_dir(&path(&dir), NODE, &anchors(), None).is_err());
}

#[test]
fn truncation_is_caught_only_with_a_checkpoint() {
    let (dir, mut l) = fresh(6);
    let cp = l.checkpoint().unwrap(); // commits to 7 events
    l.append(EventDraft::new("test", EventKind::Discover, "after checkpoint")).unwrap(); // 8 events
    drop(l);
    let file = path(&dir).join("events.log");
    let data = fs::read(&file).unwrap();
    let spans = frame_spans(&data);
    assert_eq!(spans.len(), 8);
    let kept = 5usize; // fewer than the 7 the checkpoint commits to
    fs::write(&file, &data[..spans[kept - 1].1]).unwrap();

    // The local checkpoint log still commits to 7 events, so replay notices.
    let err = verify_dir(&path(&dir), NODE, &anchors(), None).unwrap_err();
    assert!(matches!(err, LedgerError::Truncated { committed: 7, found: 5 }), "{err}");

    // An attacker who also deletes the local checkpoints leaves a self-consistent
    // ledger; only an independently held checkpoint exposes the rollback.
    fs::write(path(&dir).join("checkpoints.log"), b"").unwrap();
    assert!(verify_dir(&path(&dir), NODE, &anchors(), None).is_ok(), "self-consistent after full local rollback");
    let err = verify_dir(&path(&dir), NODE, &anchors(), Some(&cp)).unwrap_err();
    assert!(matches!(err, LedgerError::Truncated { committed: 7, found: 5 }), "{err}");
}

#[test]
fn rewritten_history_is_caught_by_an_external_checkpoint() {
    // Build two ledgers under the same key with different early content.
    let (dir_a, mut a) = fresh(4);
    let cp_a = a.checkpoint().unwrap();
    drop(a);
    let dir_b = tempfile::tempdir().unwrap();
    let mut b = Ledger::create(&dir_b.path().join("ev"), NODE, key(), BOOT).unwrap();
    b.set_sync(false);
    for i in 0..4 {
        b.append(EventDraft::new("test", EventKind::Discover, &format!("forged {i}"))).unwrap();
    }
    drop(b);
    assert!(verify_dir(&path(&dir_a), NODE, &anchors(), Some(&cp_a)).is_ok());
    let err = verify_dir(&dir_b.path().join("ev"), NODE, &anchors(), Some(&cp_a)).unwrap_err();
    assert!(matches!(err, LedgerError::Forked { size: 5 }), "{err}");
}

#[test]
fn torn_tail_is_reported_quarantined_and_never_deleted() {
    let (dir, l) = fresh(3);
    drop(l);
    let file = path(&dir).join("events.log");
    let mut data = fs::read(&file).unwrap();
    let full = data.len();
    // A crash mid-append: a valid header announcing 256 bytes, of which only 2 arrived.
    let mut partial = crate::store::frame_header(256).to_vec();
    partial.extend_from_slice(&[0xde, 0xad]);
    data.extend_from_slice(&partial);
    fs::write(&file, &data).unwrap();

    let r = verify_dir(&path(&dir), NODE, &anchors(), None).unwrap();
    assert_eq!(r.events, 4);
    assert_eq!(r.torn_tail_bytes, partial.len() as u64);

    let (mut l, rep) = Ledger::open(&path(&dir), NODE, key(), &anchors(), BOOT).unwrap();
    assert_eq!(rep.torn_tail_bytes, partial.len() as u64);
    assert_eq!(fs::metadata(&file).unwrap().len() as usize, full);
    assert_eq!(fs::read(path(&dir).join("events.log.torn.0")).unwrap(), partial, "torn bytes must be preserved");
    l.append(EventDraft::new("test", EventKind::Degraded, "recovered torn tail")).unwrap();
    drop(l);
    assert_eq!(verify_dir(&path(&dir), NODE, &anchors(), None).unwrap().events, 5);
}

#[test]
fn fewer_than_a_header_of_trailing_bytes_is_a_torn_tail() {
    let (dir, l) = fresh(1);
    drop(l);
    let file = path(&dir).join("events.log");
    let mut data = fs::read(&file).unwrap();
    data.extend_from_slice(&[0, 0, 1]);
    fs::write(&file, &data).unwrap();
    let r = verify_dir(&path(&dir), NODE, &anchors(), None).unwrap();
    assert_eq!((r.events, r.torn_tail_bytes), (2, 3));
}

#[test]
fn a_corrupt_length_in_the_middle_never_causes_deletion_on_open() {
    let (dir, l) = fresh(4);
    drop(l);
    let file = path(&dir).join("events.log");
    let mut data = fs::read(&file).unwrap();
    let original = data.clone();
    let (start, _) = frame_spans(&data)[1];
    data[start + 1] ^= 0x01; // second byte of the length: would otherwise swallow the rest as "torn"
    fs::write(&file, &data).unwrap();
    assert!(Ledger::open(&path(&dir), NODE, key(), &anchors(), BOOT).is_err());
    assert_eq!(fs::read(&file).unwrap(), data, "file must be untouched");
    assert_ne!(data, original);
    assert!(!path(&dir).join("events.log.torn.0").exists());
}

#[test]
fn events_signed_by_the_wrong_key_or_for_another_node_are_rejected() {
    let (dir, l) = fresh(2);
    drop(l);
    let other = SigningKeypair::from_seed([9; 32], Role::Device);
    let mut only_other = TrustAnchors::new();
    only_other.insert(other.public());
    assert!(verify_dir(&path(&dir), NODE, &only_other, None).is_err());
    assert!(verify_dir(&path(&dir), "another-node", &anchors(), None).is_err());
    // A key with the wrong role is refused even when trusted.
    let policy_key = SigningKeypair::from_seed([42; 32], Role::Policy);
    let mut wrong_role = TrustAnchors::new();
    wrong_role.insert(policy_key.public());
    assert!(verify_dir(&path(&dir), NODE, &wrong_role, None).is_err());
}

#[test]
fn checkpoint_counter_is_strictly_increasing_across_reopen() {
    let (dir, mut l) = fresh(1);
    l.checkpoint().unwrap();
    l.checkpoint().unwrap();
    drop(l);
    let (mut l, rep) = Ledger::open(&path(&dir), NODE, key(), &anchors(), BOOT).unwrap();
    assert_eq!(rep.checkpoints, 2);
    l.checkpoint().unwrap();
    drop(l);
    assert_eq!(verify_dir(&path(&dir), NODE, &anchors(), None).unwrap().checkpoints, 3);
}

#[test]
fn inclusion_proofs_work_against_a_checkpoint() {
    let (_dir, mut l) = fresh(9);
    let root = l.root();
    let size = l.tree().size();
    let cp_bytes = l.checkpoint().unwrap();
    let idx = 4;
    let proof = l.tree().inclusion_proof(idx, size).unwrap();
    let leaf = *l.tree().leaf(idx).unwrap();
    assert!(crate::merkle::verify_inclusion(&leaf, idx, size, &proof, &root));
    assert!(!cp_bytes.is_empty());
}

#[test]
fn permissions_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, l) = fresh(1);
    drop(l);
    let mode = |p: std::path::PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(path(&dir)), 0o700);
    assert_eq!(mode(path(&dir).join("events.log")), 0o600);
    assert_eq!(mode(path(&dir).join("checkpoints.log")), 0o600);
}

#[test]
fn read_events_returns_verified_history_in_order() {
    let (dir, l) = fresh(3);
    drop(l);
    let evs = crate::read_events(&path(&dir), NODE, &anchors()).unwrap();
    assert_eq!(evs.len(), 4);
    assert_eq!(evs[0].kind, EventKind::Genesis);
    assert!(evs.iter().enumerate().all(|(i, e)| e.seq == i as u64));
    // A damaged ledger yields no events at all, never a partial list.
    let file = path(&dir).join("events.log");
    let mut data = fs::read(&file).unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 1;
    fs::write(&file, data).unwrap();
    assert!(crate::read_events(&path(&dir), NODE, &anchors()).is_err());
}

/// Builds a ledger directory by hand in which event `bad_index` is signed by a stranger,
/// with a device-signed checkpoint over `checkpoint_size` events.
fn forge_with_stranger_event(bad_index: usize, total: usize, checkpoint_size: usize) -> TempDir {
    use jlr_cbor::Cbor;
    use jlr_crypto::{Digest, Envelope};
    use jlr_model::{Basis, Event};
    let dir = tempfile::tempdir().unwrap();
    let evdir = path(&dir);
    fs::create_dir_all(&evdir).unwrap();
    let stranger = SigningKeypair::from_seed([9; 32], Role::Device);
    let mut tree = crate::merkle::Tree::new();
    let mut log = Vec::new();
    let mut prev = Digest::ZERO;
    for i in 0..total {
        let ev = Event {
            seq: i as u64,
            boot_id: BOOT,
            wall_time: 0,
            mono_ns: i as u64,
            actor: "forge".into(),
            subject: None,
            kind: if i == 0 { EventKind::Genesis } else { EventKind::Discover },
            old_state: None,
            new_state: None,
            policy: Digest::ZERO,
            evidence: vec![],
            basis: Basis::None,
            detail: format!("e{i}"),
            prev,
        };
        let signer = if i == bad_index { &stranger } else { &key() };
        let env = Envelope::sign(jlr_model::record_type::EVENT, NODE, &ev.to_cbor(), signer);
        prev = Digest::of(&env);
        tree.push(crate::merkle::leaf_hash(&env));
        log.extend_from_slice(&crate::store::frame_header(env.len() as u32));
        log.extend_from_slice(&env);
    }
    fs::write(evdir.join("events.log"), &log).unwrap();
    let cp = Checkpoint {
        origin: format!("jlr/{NODE}/evidence"),
        size: checkpoint_size as u64,
        root: tree.root_at(checkpoint_size).unwrap(),
        boot_id: BOOT,
        wall_time: 0,
        counter: 1,
        anchor: Anchor::Software,
    };
    let env = Envelope::sign(jlr_model::record_type::CHECKPOINT, NODE, &cp.to_cbor(), &key());
    let mut cpl = crate::store::frame_header(env.len() as u32).to_vec();
    cpl.extend_from_slice(&env);
    fs::write(evdir.join("checkpoints.log"), cpl).unwrap();
    dir
}

#[test]
fn checkpointed_prefix_is_covered_by_the_signed_root_not_by_per_event_signatures() {
    // Event 2 carries a stranger's signature, but a device-signed checkpoint vouches for events 0..5.
    let dir = forge_with_stranger_event(2, 8, 5);
    // The exhaustive check verifies every signature and refuses.
    assert!(verify_dir(&path(&dir), NODE, &anchors(), None).is_err());
    // Opening trusts the signed root over the prefix, which is the documented trade-off:
    // a checkpoint is the device key vouching for exactly those bytes.
    assert_eq!(crate::read_events(&path(&dir), NODE, &anchors()).unwrap().len(), 8);
}

#[test]
fn events_after_the_newest_checkpoint_are_always_verified_in_full() {
    // The stranger's event is at position 6, after the checkpoint over 0..5.
    let dir = forge_with_stranger_event(6, 8, 5);
    assert!(verify_dir(&path(&dir), NODE, &anchors(), None).is_err());
    assert!(crate::read_events(&path(&dir), NODE, &anchors()).is_err(), "the tail must never skip signature checks");
    assert!(Ledger::open(&path(&dir), NODE, key(), &anchors(), BOOT).is_err());
}

#[test]
fn any_single_bit_flip_is_still_detected_on_the_fast_path() {
    // Flips inside the checkpointed prefix change the Merkle root; flips in the tail fail signatures.
    let (dir, mut l) = fresh(6);
    l.checkpoint().unwrap();
    l.append(EventDraft::new("test", EventKind::Discover, "tail")).unwrap();
    drop(l);
    let file = path(&dir).join("events.log");
    let good = fs::read(&file).unwrap();
    assert!(crate::read_events(&path(&dir), NODE, &anchors()).is_ok());
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        fs::write(&file, &bad).unwrap();
        assert!(crate::read_events(&path(&dir), NODE, &anchors()).is_err(), "flip at byte {i} passed the fast path");
    }
}

#[test]
fn opening_verifies_only_the_events_since_the_last_checkpoint() {
    let (dir, mut l) = fresh(20);
    assert_eq!(l.events_since_checkpoint(), 21);
    l.checkpoint().unwrap();
    assert_eq!(l.events_since_checkpoint(), 0);
    for i in 0..3 {
        l.append(EventDraft::new("test", EventKind::Discover, &format!("t{i}"))).unwrap();
    }
    assert_eq!(l.events_since_checkpoint(), 3);
    drop(l);
    let (l, _) = Ledger::open(&path(&dir), NODE, key(), &anchors(), BOOT).unwrap();
    assert_eq!(l.events_since_checkpoint(), 3, "the checkpoint position survives a reopen");
}

#[test]
fn a_torn_checkpoint_tail_is_quarantined_and_does_not_brick_the_ledger() {
    let (dir, mut l) = fresh(3);
    l.checkpoint().unwrap();
    drop(l);
    let cps = path(&dir).join("checkpoints.log");
    let whole = fs::read(&cps).unwrap();
    // A crash mid-append: a valid header announcing 200 bytes, of which 30 arrived.
    let mut partial = crate::store::frame_header(200).to_vec();
    partial.extend_from_slice(&[0xab; 30]);
    let mut torn = whole.clone();
    torn.extend_from_slice(&partial);
    fs::write(&cps, &torn).unwrap();

    let (mut l, rep) = Ledger::open(&path(&dir), NODE, key(), &anchors(), BOOT).unwrap();
    assert_eq!(rep.checkpoint_torn_bytes, partial.len() as u64);
    assert_eq!(fs::read(&cps).unwrap(), whole, "the log is cut back to the last whole checkpoint");
    assert_eq!(fs::read(path(&dir).join("checkpoints.log.torn.0")).unwrap(), partial, "and the bytes are kept");

    // Before the fix the next checkpoint was appended after the garbage and every later open failed.
    l.checkpoint().unwrap();
    l.append(EventDraft::new("test", EventKind::Discover, "after repair")).unwrap();
    l.checkpoint().unwrap();
    drop(l);
    let r = verify_dir(&path(&dir), NODE, &anchors(), None).unwrap();
    assert_eq!(r.checkpoints, 3);
    assert!(Ledger::open(&path(&dir), NODE, key(), &anchors(), BOOT).is_ok());
}

/// A sink that accepts `limit` bytes and then fails, as a full disk or a quota does part-way through a frame.
struct Failing {
    data: Vec<u8>,
    limit: usize,
    truncate_fails: bool,
}

impl crate::store::FrameSink for Failing {
    fn len(&mut self) -> std::io::Result<u64> {
        Ok(self.data.len() as u64)
    }
    fn append(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let room = self.limit.saturating_sub(self.data.len());
        let n = room.min(bytes.len());
        self.data.extend_from_slice(&bytes[..n]);
        if n < bytes.len() { Err(std::io::Error::other("no space left on device")) } else { Ok(()) }
    }
    fn sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn truncate(&mut self, len: u64) -> std::io::Result<()> {
        if self.truncate_fails {
            return Err(std::io::Error::other("input/output error"));
        }
        self.data.truncate(len as usize);
        Ok(())
    }
}

#[test]
fn a_failed_append_leaves_no_bytes_behind() {
    use crate::store::{AppendError, append_frame};
    // Room for 6 of the 9 bytes: a genuine partial write, not a write that fails before writing anything.
    let mut sink = Failing { data: b"good".to_vec(), limit: 4 + 6, truncate_fails: false };
    let r = append_frame(&mut sink, b"123456789", false);
    assert!(matches!(r, Err(AppendError::Failed(_))), "{r:?}");
    assert_eq!(sink.data, b"good", "the six bytes that were written must be taken back");

    // A frame that fits is written whole.
    let mut sink = Failing { data: b"good".to_vec(), limit: 100, truncate_fails: false };
    append_frame(&mut sink, b"+more", true).unwrap();
    assert_eq!(sink.data, b"good+more");

    // A real file: the same guarantee through the production implementation.
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("f");
    let mut file = fs::OpenOptions::new().create(true).append(true).read(true).open(&f).unwrap();
    append_frame(&mut file, b"good", true).unwrap();
    append_frame(&mut file, b"+more", true).unwrap();
    assert_eq!(fs::read(&f).unwrap(), b"good+more");
}

#[test]
fn a_write_that_cannot_be_rolled_back_is_reported_so_the_ledger_can_stop() {
    use crate::store::{AppendError, append_frame};
    let mut sink = Failing { data: b"good".to_vec(), limit: 4 + 3, truncate_fails: true };
    let r = append_frame(&mut sink, b"123456789", false);
    assert!(matches!(r, Err(AppendError::RollbackFailed { .. })), "{r:?}");
    assert_eq!(sink.data, b"good123", "the leftover is exactly what a failed rollback leaves behind");
}

#[test]
fn a_checkpoint_written_between_the_two_reads_is_covered_by_the_events_read_afterwards() {
    // Deterministic: the writer acts at exactly the moment between `replay`'s two reads. With events read first, the
    // checkpoint it writes commits to more events than were read and verification reports a truncated ledger.
    use std::cell::RefCell;
    use std::rc::Rc;
    let dir = tempfile::tempdir().unwrap();
    let mut l = Ledger::create(&path(&dir), NODE, key(), BOOT).unwrap();
    l.append(EventDraft::new("test", EventKind::Discover, "before")).unwrap();
    l.checkpoint().unwrap();
    let writer = Rc::new(RefCell::new(l));
    let fired = Rc::new(RefCell::new(0u32));
    let (w, f) = (writer.clone(), fired.clone());
    crate::store::set_between_reads_hook(Some(Box::new(move || {
        *f.borrow_mut() += 1;
        let mut l = w.borrow_mut();
        l.append(EventDraft::new("test", EventKind::Discover, "during")).unwrap();
        l.checkpoint().unwrap();
    })));
    let r = verify_dir(&path(&dir), NODE, &anchors(), None);
    crate::store::set_between_reads_hook(None);
    assert_eq!(*fired.borrow(), 1, "the hook must run between the reads");
    let r = r.expect("a checkpoint written between the reads must not read as a truncated ledger");
    assert!(r.events >= 2, "the events read afterwards include the new event: {r:?}");
}

#[test]
fn a_reader_that_takes_no_lock_never_sees_a_checkpoint_the_events_do_not_cover() {
    // A stress companion of the deterministic test above: it only fails occasionally with the old read order.
    // `jlr ledger verify` runs beside the daemon. A checkpoint written between reading the events and reading the
    // checkpoints used to be reported as a truncated ledger.
    let dir = tempfile::tempdir().unwrap();
    let mut l = Ledger::create(&path(&dir), NODE, key(), BOOT).unwrap();
    l.set_sync(false); // fast enough that a checkpoint lands in the reader's window often
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let d = path(&dir);
    let reader_stop = stop.clone();
    let reader = std::thread::spawn(move || {
        let (mut ok, mut bad) = (0u32, Vec::new());
        while !reader_stop.load(std::sync::atomic::Ordering::SeqCst) {
            match verify_dir(&d, NODE, &anchors(), None) {
                Ok(_) => ok += 1,
                Err(e) => bad.push(e.to_string()),
            }
        }
        (ok, bad)
    });
    for i in 0..3000 {
        l.append(EventDraft::new("test", EventKind::Discover, &format!("event {i}"))).unwrap();
        if i % 2 == 0 {
            l.checkpoint().unwrap();
        }
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let (ok, bad) = reader.join().unwrap();
    assert!(ok > 0, "the reader never completed a verification");
    assert!(
        bad.is_empty(),
        "verification beside a live writer failed {} times: {:?}",
        bad.len(),
        &bad[..bad.len().min(3)]
    );
}
