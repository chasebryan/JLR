use super::*;
use jlr_crypto::{Digest, Role, SigningKeypair, TrustAnchors};
use proptest::prelude::*;
use std::io::Cursor;

fn release_key() -> SigningKeypair {
    SigningKeypair::from_seed([11; 32], Role::Release)
}

fn anchors() -> TrustAnchors {
    let mut a = TrustAnchors::new();
    a.insert(release_key().public());
    a
}

fn manifest_for(image: &[u8], epoch: u64, min_epoch: u64) -> ReleaseManifest {
    ReleaseManifest {
        schema: 1,
        name: "jlr-base".into(),
        version: format!("0.{epoch}.0"),
        epoch,
        image_digest: Digest::of(image),
        image_size: image.len() as u64,
        min_epoch,
        policy_digest: None,
        components: vec![Component { name: "jlr".into(), digest: Digest::of(b"jlr") }],
    }
}

#[test]
fn signed_manifest_verifies_and_round_trips() {
    let image = b"image-bytes".to_vec();
    let m = manifest_for(&image, 3, 2);
    let bytes = m.sign(&release_key());
    assert_eq!(verify_manifest(&bytes, &anchors(), 0).unwrap(), m);
}

#[test]
fn manifest_signature_failures_are_refused() {
    let m = manifest_for(b"x", 1, 1);
    let good = m.sign(&release_key());

    // Any bit flip anywhere.
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 1;
        assert!(verify_manifest(&bad, &anchors(), 0).is_err(), "flip at {i} accepted");
    }
    // A stranger's key.
    let stranger = SigningKeypair::from_seed([12; 32], Role::Release);
    assert!(matches!(verify_manifest(&m.sign(&stranger), &anchors(), 0), Err(BootError::Signature(_))));
    // A trusted key with the wrong role (a device key must not sign releases).
    let device = SigningKeypair::from_seed([13; 32], Role::Device);
    let mut a = anchors();
    a.insert(device.public());
    assert!(matches!(verify_manifest(&m.sign(&device), &a, 0), Err(BootError::Signature(_))));
    // No anchors at all: nothing is trusted.
    assert!(verify_manifest(&good, &TrustAnchors::new(), 0).is_err());
}

#[test]
fn a_manifest_signed_for_another_record_type_is_refused() {
    // A validly signed *policy* envelope must not be accepted as a release manifest.
    let policy_key = SigningKeypair::from_seed([14; 32], Role::Policy);
    let mut a = anchors();
    a.insert(policy_key.public());
    let m = manifest_for(b"x", 1, 1);
    let confused =
        jlr_crypto::Envelope::sign(jlr_model::record_type::POLICY, "*", &jlr_cbor::Cbor::to_cbor(&m), &policy_key);
    assert!(verify_manifest(&confused, &a, 0).is_err());
    let confused = jlr_crypto::Envelope::sign("something-else", "*", &jlr_cbor::Cbor::to_cbor(&m), &release_key());
    assert!(verify_manifest(&confused, &anchors(), 0).is_err());
}

#[test]
fn rollback_floor_is_enforced() {
    let m = manifest_for(b"x", 4, 4);
    let bytes = m.sign(&release_key());
    assert!(verify_manifest(&bytes, &anchors(), 4).is_ok());
    assert!(matches!(verify_manifest(&bytes, &anchors(), 5), Err(BootError::Rollback { epoch: 4, floor: 5 })));
}

#[test]
fn inconsistent_manifests_are_refused() {
    let mut m = manifest_for(b"x", 2, 2);
    m.min_epoch = 3; // a release may not forbid itself
    assert!(matches!(verify_manifest(&m.sign(&release_key()), &anchors(), 0), Err(BootError::Manifest(_))));
    let mut m = manifest_for(b"x", 2, 2);
    m.schema = 9;
    assert!(matches!(verify_manifest(&m.sign(&release_key()), &anchors(), 0), Err(BootError::Manifest(_))));
}

#[test]
fn image_is_hashed_while_copied_and_mismatches_are_refused() {
    let image: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let m = manifest_for(&image, 1, 1);
    let mut sink = Vec::new();
    assert_eq!(verify_image(&m, &mut Cursor::new(&image), &mut sink).unwrap(), image.len() as u64);
    assert_eq!(sink, image, "the sink must hold exactly the verified bytes");

    // One flipped bit anywhere in the image.
    for pos in [0usize, 1, 4096, image.len() / 2, image.len() - 1] {
        let mut bad = image.clone();
        bad[pos] ^= 0x10;
        let mut sink = Vec::new();
        assert!(
            matches!(verify_image(&m, &mut Cursor::new(&bad), &mut sink), Err(BootError::ImageDigest { .. })),
            "pos {pos}"
        );
    }
    // Truncated and extended images.
    let mut sink = Vec::new();
    assert!(matches!(
        verify_image(&m, &mut Cursor::new(&image[..image.len() - 1]), &mut sink),
        Err(BootError::ImageSize { .. })
    ));
    let mut longer = image.clone();
    longer.push(0);
    let mut sink = Vec::new();
    let err = verify_image(&m, &mut Cursor::new(&longer), &mut sink).unwrap_err();
    assert!(matches!(err, BootError::ImageSize { .. }));
    assert!(sink.len() as u64 <= m.image_size, "never buffer more than the manifest promised");
}

fn verified(list: &[(&str, u64)]) -> Vec<(String, ReleaseManifest)> {
    list.iter().map(|(n, e)| ((*n).to_owned(), manifest_for(n.as_bytes(), *e, *e))).collect()
}

#[test]
fn fresh_state_boots_slot_a() {
    let c = choose(&BootState::fresh(), &verified(&[("a", 1)])).unwrap();
    assert_eq!(c.slot, "a");
    assert_eq!(c.next, BootState::fresh(), "a proven slot consumes no tries");
}

#[test]
fn a_new_unproven_slot_is_preferred_and_consumes_a_try_before_booting() {
    let mut s = BootState::fresh();
    s.install("b");
    let c = choose(&s, &verified(&[("a", 1), ("b", 2)])).unwrap();
    assert_eq!(c.slot, "b");
    let b = c.next.slots.iter().find(|x| x.name == "b").unwrap();
    assert_eq!((b.tries, b.successful), (2, false), "the try is spent in the state that will be written before boot");
}

#[test]
fn a_crashing_update_falls_back_to_the_old_slot_after_its_tries() {
    // Simulate three boots of slot B that never reach the health check (power cut, panic, hang).
    let mut s = BootState::fresh();
    s.install("b");
    let v = verified(&[("a", 1), ("b", 2)]);
    for attempt in 1..=3 {
        let c = choose(&s, &v).unwrap();
        assert_eq!(c.slot, "b", "attempt {attempt}");
        s = c.next; // durable before boot; the boot then dies without marking success
    }
    let c = choose(&s, &v).unwrap();
    assert_eq!(c.slot, "a", "with B out of tries the proven slot A must boot");
    assert_eq!(c.next, s, "falling back changes nothing");
}

#[test]
fn success_raises_the_floor_and_strands_older_releases() {
    let mut s = BootState::fresh();
    s.install("b");
    let vb = manifest_for(b"b", 5, 5);
    let c = choose(&s, &[("a".into(), manifest_for(b"a", 1, 1)), ("b".into(), vb.clone())]).unwrap();
    s = c.next;
    s.mark_successful("b", &vb);
    assert_eq!(s.floor, 5);
    // Slot A (epoch 1) is now below the floor and must not boot, even though it is "successful".
    let only_a = [("a".to_owned(), manifest_for(b"a", 1, 1))];
    assert!(matches!(choose(&s, &only_a), Err(BootError::NoBootableSlot)));
    // ...and a verify_manifest with the floor refuses it earlier.
    assert!(verify_manifest(&only_a[0].1.sign(&release_key()), &anchors(), s.floor).is_err());
}

#[test]
fn floor_never_decreases() {
    let mut s = BootState::fresh();
    s.mark_successful("a", &manifest_for(b"a", 9, 9));
    s.mark_successful("a", &manifest_for(b"a", 2, 2));
    assert_eq!(s.floor, 9);
}

#[test]
fn a_slot_whose_image_failed_is_never_chosen_again() {
    let mut s = BootState::fresh();
    s.install("b");
    s.mark_bad("b");
    let c = choose(&s, &verified(&[("a", 1), ("b", 2)])).unwrap();
    assert_eq!(c.slot, "a");
    s.mark_bad("a");
    assert!(matches!(choose(&s, &verified(&[("a", 1), ("b", 2)])), Err(BootError::NoBootableSlot)));
}

#[test]
fn unverified_slots_are_never_chosen_whatever_the_state_says() {
    let mut s = BootState::fresh();
    s.install("b");
    // Only A verified; B is preferred by the state but absent from the verified list.
    assert_eq!(choose(&s, &verified(&[("a", 1)])).unwrap().slot, "a");
    assert!(matches!(choose(&s, &[]), Err(BootError::NoBootableSlot)));
}

#[test]
fn boot_state_round_trips_and_rejects_garbage() {
    use jlr_cbor::Cbor;
    let mut s = BootState::fresh();
    s.install("b");
    assert_eq!(BootState::from_cbor(&s.to_cbor()).unwrap(), s);
    for cut in 0..s.to_cbor().len() {
        assert!(BootState::from_cbor(&s.to_cbor()[..cut]).is_err());
    }
}

fn arb_state() -> impl Strategy<Value = BootState> {
    (0u64..6, prop::collection::vec((0u16..4, 0u16..4, any::<bool>()), 1..4)).prop_map(|(floor, slots)| BootState {
        floor,
        slots: slots
            .into_iter()
            .enumerate()
            .map(|(i, (priority, tries, successful))| SlotState { name: format!("s{i}"), priority, tries, successful })
            .collect(),
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn choose_never_violates_its_invariants(state in arb_state(), epochs in prop::collection::vec(0u64..8, 4), present in prop::collection::vec(any::<bool>(), 4)) {
        let v: Vec<(String, ReleaseManifest)> = state
            .slots
            .iter()
            .enumerate()
            .filter(|(i, _)| present[*i % 4])
            .map(|(i, s)| (s.name.clone(), manifest_for(s.name.as_bytes(), epochs[i % 4], 0)))
            .collect();
        if let Ok(c) = choose(&state, &v) {
            let chosen = state.slots.iter().find(|s| s.name == c.slot).unwrap();
            let m = &v.iter().find(|(n, _)| *n == c.slot).unwrap().1;
            // Only verified slots, above the floor, with priority, and either proven or with tries left.
            prop_assert!(chosen.priority > 0);
            prop_assert!(m.epoch >= state.floor);
            prop_assert!(chosen.successful || chosen.tries > 0);
            // A try is spent exactly when the slot is unproven; nothing else changes.
            let after = c.next.slots.iter().find(|s| s.name == c.slot).unwrap();
            prop_assert_eq!(after.tries, if chosen.successful { chosen.tries } else { chosen.tries - 1 });
            prop_assert_eq!(c.next.floor, state.floor);
            // No other slot has higher priority AND is bootable.
            for other in &state.slots {
                if other.name == chosen.name { continue; }
                if let Some((_, om)) = v.iter().find(|(n, _)| *n == other.name) {
                    let bootable = other.priority > 0 && om.epoch >= state.floor && (other.successful || other.tries > 0);
                    prop_assert!(!(bootable && other.priority > chosen.priority), "a higher-priority bootable slot was skipped");
                }
            }
        }
    }
}

// ---- boot media and state files ---------------------------------------------------------------------------

mod media_tests {
    use crate::media::{StateRead, filesystem_id, parse_pin, read_state, write_state};
    use crate::{BootError, BootState, SlotState};
    use jlr_cbor::Cbor;
    use jlr_crypto::Digest;
    use std::fs;

    fn media_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("jlr")).unwrap();
        d
    }

    fn proven_at(floor: u64) -> BootState {
        BootState { floor, slots: vec![SlotState { name: "a".into(), priority: 15, tries: 0, successful: true }] }
    }

    #[test]
    fn a_missing_state_file_is_a_fresh_medium_and_nothing_else_is() {
        let d = media_dir();
        assert_eq!(read_state(d.path()).unwrap(), StateRead::Fresh(BootState::fresh()));

        // A damaged file is an error, never "fresh": that would reset the rollback floor to zero.
        fs::write(d.path().join("jlr/bootstate.cbor"), b"\xff\xff garbage").unwrap();
        assert!(matches!(read_state(d.path()), Err(BootError::Io(_))));
        let mut truncated = proven_at(9).to_cbor();
        truncated.truncate(truncated.len() - 1);
        fs::write(d.path().join("jlr/bootstate.cbor"), truncated).unwrap();
        assert!(read_state(d.path()).is_err());

        // So is any other read failure. A directory where the file should be reads as EISDIR.
        fs::remove_file(d.path().join("jlr/bootstate.cbor")).unwrap();
        fs::create_dir(d.path().join("jlr/bootstate.cbor")).unwrap();
        assert!(matches!(read_state(d.path()), Err(BootError::Io(_))), "an unreadable state must not read as fresh");
    }

    #[test]
    fn state_round_trips_and_leaves_no_temporary_file() {
        let d = media_dir();
        let st = proven_at(7);
        write_state(d.path(), &st).unwrap();
        assert_eq!(read_state(d.path()).unwrap(), StateRead::Loaded(st));
        assert!(!d.path().join("jlr/bootstate.cbor.new").exists());
    }

    #[test]
    fn an_interrupted_rename_does_not_reset_the_floor() {
        // A power cut in the middle of replacing the file on FAT leaves the complete new file beside a missing
        // old one. The floor recorded there must survive.
        let d = media_dir();
        fs::write(d.path().join("jlr/bootstate.cbor.new"), proven_at(12).to_cbor()).unwrap();
        match read_state(d.path()).unwrap() {
            StateRead::Recovered(s) => assert_eq!(s.floor, 12),
            other => panic!("{other:?}"),
        }
        // When both exist the rename did not happen; the file that was renamed earlier is authoritative.
        fs::write(d.path().join("jlr/bootstate.cbor"), proven_at(3).to_cbor()).unwrap();
        assert_eq!(read_state(d.path()).unwrap(), StateRead::Loaded(proven_at(3)));
    }

    #[test]
    fn a_torn_replacement_beside_no_state_is_a_fresh_medium_not_a_brick() {
        // The replacement is synced before it replaces anything, so a torn `.new` with no state file means the very
        // first write was cut short. Refusing to boot on it, on every boot, would strand a machine over nothing.
        let d = media_dir();
        fs::write(d.path().join("jlr/bootstate.cbor.new"), b"\x01").unwrap();
        assert_eq!(read_state(d.path()).unwrap(), StateRead::Fresh(BootState::fresh()));
        // A torn `.new` beside a state file is simply ignored: the state file is what counts.
        fs::write(d.path().join("jlr/bootstate.cbor"), proven_at(3).to_cbor()).unwrap();
        assert_eq!(read_state(d.path()).unwrap(), StateRead::Loaded(proven_at(3)));
    }

    #[test]
    fn a_failed_write_leaves_no_partial_file_and_a_later_write_supersedes_a_recovered_copy() {
        // A rename that cannot happen (a directory is in the way) fails after the new file was written.
        let d = media_dir();
        fs::create_dir(d.path().join("jlr/bootstate.cbor")).unwrap();
        assert!(write_state(d.path(), &proven_at(9)).is_err());
        assert!(!d.path().join("jlr/bootstate.cbor.new").exists(), "a failed write must not leave its partial file");
        fs::remove_dir(d.path().join("jlr/bootstate.cbor")).unwrap();

        // A complete `.new` with no state file is the only copy of the floor. A later write ends with the newer state
        // in place and no `.new` left over (that the older copy is promoted first, rather than truncated by the new
        // write, is what `promote_recovered` is tested for below).
        fs::write(d.path().join("jlr/bootstate.cbor.new"), proven_at(12).to_cbor()).unwrap();
        write_state(d.path(), &proven_at(20)).unwrap();
        assert_eq!(read_state(d.path()).unwrap(), StateRead::Loaded(proven_at(20)));
        assert!(!d.path().join("jlr/bootstate.cbor.new").exists());
    }

    #[test]
    fn only_content_that_is_provably_bad_retires_a_slot() {
        let mut st = BootState::fresh();
        st.install("b");
        let before = st.clone();
        assert!(!st.record_image_failure("b", &BootError::Io("read error".into())));
        assert_eq!(st, before, "an I/O error must not change the state");
        let bad = BootError::ImageDigest { expected: Digest::of(b"x"), actual: Digest::of(b"y") };
        assert!(st.record_image_failure("b", &bad));
        assert_eq!(st.slots.iter().find(|s| s.name == "b").unwrap().priority, 0);
        let mut st2 = before;
        assert!(st2.record_image_failure("b", &BootError::ImageSize { expected: 2, actual: 1 }));
        assert!(
            !BootError::NoBootableSlot.proves_bad_content() && !BootError::Manifest("x".into()).proves_bad_content()
        );
    }

    #[test]
    fn media_pins_parse_strictly() {
        assert_eq!(
            parse_pin("uuid=6F1B2C3D-0000-4444-8888-123456789ABC\n").as_deref(),
            Some("6f1b2c3d-0000-4444-8888-123456789abc")
        );
        assert_eq!(parse_pin(" ABCD-1234 ").as_deref(), Some("abcd-1234"));
        assert_eq!(parse_pin("id=abcd-1234").as_deref(), Some("abcd-1234"));
        for bad in ["", "uuid=", "not a uuid", "uuid=xyz", "a b", "../../dev/sda", &"a".repeat(65)] {
            assert_eq!(parse_pin(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn filesystem_ids_are_read_from_superblocks() {
        // ext: magic 0xEF53 at superblock+56, UUID at +104.
        let mut head = vec![0u8; 2048];
        head[1024 + 56..1024 + 58].copy_from_slice(&[0x53, 0xEF]);
        let uuid: Vec<u8> = (0..16).collect();
        head[1024 + 104..1024 + 120].copy_from_slice(&uuid);
        assert_eq!(filesystem_id(&head).as_deref(), Some("00010203-0405-0607-0809-0a0b0c0d0e0f"));
        // FAT32: boot signature, "FAT32   " at 82, serial at 67 (little endian, printed high half first).
        let mut fat = vec![0u8; 2048];
        fat[510] = 0x55;
        fat[511] = 0xAA;
        fat[82..90].copy_from_slice(b"FAT32   ");
        fat[67..71].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(filesystem_id(&fat).as_deref(), Some("1234-5678"));
        // FAT16 keeps the serial at 39.
        let mut fat16 = vec![0u8; 2048];
        fat16[510] = 0x55;
        fat16[511] = 0xAA;
        fat16[54..62].copy_from_slice(b"FAT16   ");
        fat16[39..43].copy_from_slice(&[0xEF, 0xBE, 0xAD, 0xDE]);
        assert_eq!(filesystem_id(&fat16).as_deref(), Some("dead-beef"));
        // Nothing recognisable, or too short to hold a superblock: no identifier, so a pinned boot never trusts it.
        assert_eq!(filesystem_id(&[0u8; 2048]), None);
        assert_eq!(filesystem_id(&[0u8; 100]), None);
        assert_eq!(filesystem_id(&[]), None);
    }
}

mod confirm_tests {
    use crate::BootError;
    use crate::confirm::{LoadFailure, Reading, confirm, same_mismatch};
    use jlr_crypto::Digest;

    fn wrong(byte: &[u8]) -> LoadFailure {
        LoadFailure::ProvenBad(BootError::ImageDigest { expected: Digest::of(b"good"), actual: Digest::of(byte) })
    }

    fn run(reads: Vec<Result<&'static str, LoadFailure>>) -> (Result<&'static str, LoadFailure>, Vec<Reading>) {
        let mut reads = reads.into_iter();
        let mut seen = Vec::new();
        let r = confirm(
            |reading| {
                seen.push(reading);
                reads.next().expect("more reads than expected")
            },
            &mut |_| {},
        );
        (r, seen)
    }

    #[test]
    fn a_read_that_verifies_is_used_without_a_second_read() {
        let (r, seen) = run(vec![Ok("image")]);
        assert_eq!(r.unwrap(), "image");
        assert_eq!(seen, vec![Reading::First]);
    }

    #[test]
    fn a_transient_failure_ends_the_attempt_and_is_not_confirmed() {
        let (r, seen) = run(vec![Err(LoadFailure::Transient("read error".into()))]);
        assert!(matches!(r, Err(LoadFailure::Transient(_))));
        assert_eq!(seen, vec![Reading::First], "a medium that errors is not read again to confirm anything");
    }

    #[test]
    fn a_fluke_is_cleared_when_the_confirming_read_verifies() {
        let (r, seen) = run(vec![Err(wrong(b"flaky")), Ok("image")]);
        assert_eq!(r.unwrap(), "image", "the slot must boot, not be retired");
        assert_eq!(seen, vec![Reading::First, Reading::Confirming]);
    }

    #[test]
    fn the_same_wrong_answer_twice_is_proof() {
        let (r, _) = run(vec![Err(wrong(b"bad image")), Err(wrong(b"bad image"))]);
        assert!(matches!(r, Err(LoadFailure::ProvenBad(BootError::ImageDigest { .. }))), "{r:?}");
    }

    #[test]
    fn reads_that_disagree_prove_nothing() {
        let (r, _) = run(vec![Err(wrong(b"one")), Err(wrong(b"two"))]);
        assert!(matches!(r, Err(LoadFailure::Transient(_))), "unreliable media is not a bad image: {r:?}");
        // A confirming read that errors is no better.
        let (r, _) = run(vec![Err(wrong(b"one")), Err(LoadFailure::Transient("io".into()))]);
        assert!(matches!(r, Err(LoadFailure::Transient(_))));
    }

    #[test]
    fn size_and_digest_mismatches_are_never_the_same_answer() {
        let d = BootError::ImageDigest { expected: Digest::of(b"a"), actual: Digest::of(b"b") };
        let s = BootError::ImageSize { expected: 4, actual: 2 };
        assert!(!same_mismatch(&d, &s));
        assert!(same_mismatch(&s, &BootError::ImageSize { expected: 4, actual: 2 }));
        assert!(!same_mismatch(&s, &BootError::ImageSize { expected: 4, actual: 3 }));
        assert!(!same_mismatch(&BootError::NoBootableSlot, &BootError::NoBootableSlot));
    }
}

mod recovery_tests {
    use crate::media::{StateRead, promote_recovered, read_state};
    use crate::{BootState, SlotState};
    use jlr_cbor::Cbor;
    use std::fs;

    fn state_at(floor: u64) -> BootState {
        BootState { floor, slots: vec![SlotState { name: "a".into(), priority: 15, tries: 0, successful: true }] }
    }

    #[test]
    fn a_complete_replacement_beside_no_state_file_becomes_the_state_file() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("jlr")).unwrap();
        fs::write(d.path().join("jlr/bootstate.cbor.new"), state_at(12).to_cbor()).unwrap();
        assert!(promote_recovered(d.path()).unwrap());
        assert!(!d.path().join("jlr/bootstate.cbor.new").exists(), "the copy is moved, not left beside the real one");
        assert_eq!(read_state(d.path()).unwrap(), StateRead::Loaded(state_at(12)));
        // With a state file present nothing is touched, whatever the replacement holds.
        fs::write(d.path().join("jlr/bootstate.cbor.new"), state_at(99).to_cbor()).unwrap();
        assert!(!promote_recovered(d.path()).unwrap());
        assert_eq!(read_state(d.path()).unwrap(), StateRead::Loaded(state_at(12)));
        assert!(d.path().join("jlr/bootstate.cbor.new").exists());
    }

    #[test]
    fn a_torn_replacement_is_removed_and_promotes_nothing() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("jlr")).unwrap();
        fs::write(d.path().join("jlr/bootstate.cbor.new"), b"\x01").unwrap();
        assert!(!promote_recovered(d.path()).unwrap());
        assert!(!d.path().join("jlr/bootstate.cbor.new").exists());
        assert!(!d.path().join("jlr/bootstate.cbor").exists());
    }
}
