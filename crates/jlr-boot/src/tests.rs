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
