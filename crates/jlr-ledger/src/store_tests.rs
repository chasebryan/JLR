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
