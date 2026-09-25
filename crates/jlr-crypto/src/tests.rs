use super::*;
use jlr_cbor::{Cbor, Map, Value};

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

fn anchors_for(keys: &[&SigningKeypair]) -> TrustAnchors {
    let mut a = TrustAnchors::new();
    for k in keys {
        a.insert(k.public());
    }
    a
}

// RFC 8032 section 7.1 TEST 1, verifying our key derivation and strict verify.
#[test]
fn ed25519_rfc8032_test1() {
    let seed_bytes: [u8; 32] =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap().try_into().unwrap();
    let expected_pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let expected_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    let kp = SigningKeypair::from_seed(seed_bytes, Role::Root);
    assert_eq!(hex::encode(kp.public().as_bytes()), expected_pub);
    assert_eq!(hex::encode(kp.sign(b"")), expected_sig);
}

#[test]
fn sha256_known_answers() {
    assert_eq!(Digest::of(b"").hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(Digest::of(b"abc").hex(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn digest_hex_roundtrip_and_cbor_is_labelled() {
    let d = Digest::of(b"jlr");
    assert_eq!(Digest::from_hex(&d.hex()), Some(d));
    assert_eq!(Digest::from_hex("zz"), None);
    let v = d.to_value();
    // [ -16, h'..' ]
    assert_eq!(v.as_array().unwrap()[0].as_i64().unwrap(), -16);
    assert_eq!(Digest::from_cbor(&d.to_cbor()).unwrap(), d);
    // A different algorithm label must be refused.
    let bad = Value::Array(vec![Value::from(-44i64), Value::Bytes(vec![0; 32])]);
    assert!(Digest::from_value(&bad).is_err());
}

#[test]
fn of_parts_is_length_framed() {
    let a = Digest::of_parts("ctx", &[b"ab", b"c"]);
    let b = Digest::of_parts("ctx", &[b"a", b"bc"]);
    let c = Digest::of_parts("other", &[b"ab", b"c"]);
    assert_ne!(a, b);
    assert_ne!(a, c);
}

#[test]
fn sign_and_verify_roundtrip() {
    let key = SigningKeypair::from_seed(seed(1), Role::Release);
    let anchors = anchors_for(&[&key]);
    let payload = jlr_cbor::encode(&Value::Map(Map::new().with(0u8, 1u8)));
    let env = Envelope::sign("release-manifest", "*", &payload, &key);
    let v = Envelope::verify(&env, "release-manifest", "*", &anchors, &[Role::Release]).unwrap();
    assert_eq!(v.payload, payload);
    assert_eq!(v.role, Role::Release);
    assert_eq!(v.kid, key.public().id());
    assert_eq!(v.record_digest, Digest::of(&payload));
    assert_eq!(v.envelope_digest, Digest::of(&env));
    assert_eq!(Envelope::peek_kid(&env), Some(key.public().id()));
}

#[test]
fn signature_is_bound_to_record_type_and_scope() {
    let key = SigningKeypair::from_seed(seed(1), Role::Device);
    let anchors = anchors_for(&[&key]);
    let env = Envelope::sign("epn", "node-a", b"\xa0", &key);
    assert!(Envelope::verify(&env, "epn", "node-a", &anchors, &[Role::Device]).is_ok());
    assert_eq!(Envelope::verify(&env, "epn", "node-b", &anchors, &[Role::Device]), Err(EnvelopeError::BadSignature));
    assert_eq!(Envelope::verify(&env, "policy", "node-a", &anchors, &[Role::Device]), Err(EnvelopeError::RecordType));
}

#[test]
fn record_type_confusion_is_rejected_even_with_forged_header() {
    // An attacker re-labels the typ header to "policy" without re-signing.
    let key = SigningKeypair::from_seed(seed(1), Role::Policy);
    let anchors = anchors_for(&[&key]);
    let env = Envelope::sign("epn", "*", b"\xa0", &key);
    let top = jlr_cbor::decode(&env).unwrap();
    let parts = top.as_tag(18).unwrap().as_array().unwrap().to_vec();
    let header = jlr_cbor::decode(parts[0].as_bytes().unwrap()).unwrap();
    let mut m = Map::new();
    for (k, v) in header.as_map().unwrap().iter() {
        if k == &Value::Uint(16) {
            m.insert(Value::Uint(16), "application/vnd.jlr.policy+cbor;v=1").unwrap();
        } else {
            m.insert(k.clone(), v.clone()).unwrap();
        }
    }
    let forged = jlr_cbor::encode(&Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(jlr_cbor::encode(&Value::Map(m))),
            parts[1].clone(),
            parts[2].clone(),
            parts[3].clone(),
        ])),
    ));
    assert_eq!(Envelope::verify(&forged, "policy", "*", &anchors, &[Role::Policy]), Err(EnvelopeError::BadSignature));
}

#[test]
fn wrong_role_and_unknown_key_are_rejected() {
    let device = SigningKeypair::from_seed(seed(2), Role::Device);
    let stranger = SigningKeypair::from_seed(seed(3), Role::Release);
    let anchors = anchors_for(&[&device]);

    let env = Envelope::sign("release-manifest", "*", b"\xa0", &device);
    assert_eq!(
        Envelope::verify(&env, "release-manifest", "*", &anchors, &[Role::Release]),
        Err(EnvelopeError::RoleNotAllowed(Role::Device))
    );

    let env = Envelope::sign("release-manifest", "*", b"\xa0", &stranger);
    assert_eq!(
        Envelope::verify(&env, "release-manifest", "*", &anchors, &[Role::Release]),
        Err(EnvelopeError::UnknownKey(stranger.public().id()))
    );
}

#[test]
fn any_single_bit_flip_is_rejected() {
    let key = SigningKeypair::from_seed(seed(4), Role::Release);
    let anchors = anchors_for(&[&key]);
    let env = Envelope::sign("release-manifest", "*", b"\xa1\x01\x02", &key);
    assert!(Envelope::verify(&env, "release-manifest", "*", &anchors, &[Role::Release]).is_ok());
    for i in 0..env.len() {
        for bit in 0..8 {
            let mut m = env.clone();
            m[i] ^= 1 << bit;
            assert!(
                Envelope::verify(&m, "release-manifest", "*", &anchors, &[Role::Release]).is_err(),
                "flip byte {i} bit {bit} was accepted"
            );
        }
    }
}

#[test]
fn trailing_bytes_and_truncation_are_rejected() {
    let key = SigningKeypair::from_seed(seed(5), Role::Release);
    let anchors = anchors_for(&[&key]);
    let env = Envelope::sign("release-manifest", "*", b"\xa0", &key);
    let mut longer = env.clone();
    longer.push(0);
    assert!(Envelope::verify(&longer, "release-manifest", "*", &anchors, &[Role::Release]).is_err());
    assert!(Envelope::verify(&env[..env.len() - 1], "release-manifest", "*", &anchors, &[Role::Release]).is_err());
}

#[test]
fn signature_malleability_is_rejected() {
    // Ed25519 signatures with s >= L must not verify (strict verification).
    let key = SigningKeypair::from_seed(seed(6), Role::Release);
    let anchors = anchors_for(&[&key]);
    let env = Envelope::sign("release-manifest", "*", b"\xa0", &key);
    let top = jlr_cbor::decode(&env).unwrap();
    let parts = top.as_tag(18).unwrap().as_array().unwrap().to_vec();
    let mut sig = parts[3].as_bytes().unwrap().to_vec();
    // s' = s + L, with L = 2^252 + 27742317777372353535851937790883648493 (little-endian).
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(sig[32 + i]) + u16::from(l[i]) + carry;
        sig[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    let forged = jlr_cbor::encode(&Value::Tag(
        18,
        Box::new(Value::Array(vec![parts[0].clone(), parts[1].clone(), parts[2].clone(), Value::Bytes(sig)])),
    ));
    assert!(Envelope::verify(&forged, "release-manifest", "*", &anchors, &[Role::Release]).is_err());
}

#[test]
fn weak_public_keys_are_rejected_at_enrollment() {
    // The identity point (0, 1) encodes as 01 00 .. 00 and has order 1.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(PublicKey::from_bytes(identity, Role::Release).is_err());
}

#[test]
fn key_files_are_private_and_never_overwritten() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("release.jlrkey");
    let key = SigningKeypair::generate(Role::Release).unwrap();
    key.save(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(key.save(&path).is_err(), "must not overwrite an existing key");
    let loaded = SigningKeypair::load(&path).unwrap();
    assert_eq!(loaded.public(), key.public());
    assert_eq!(loaded.role(), Role::Release);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(SigningKeypair::load(&path).is_err(), "group/world-readable key must be refused");
}

#[test]
fn trust_anchors_roundtrip_and_reject_duplicates() {
    let a = SigningKeypair::from_seed(seed(7), Role::Root);
    let b = SigningKeypair::from_seed(seed(8), Role::Policy);
    let anchors = anchors_for(&[&a, &b]);
    let back = TrustAnchors::from_cbor(&anchors.to_cbor()).unwrap();
    assert_eq!(back.len(), 2);
    let dup = Value::Array(vec![a.public().to_value(), a.public().to_value()]);
    assert!(TrustAnchors::from_value(&dup).is_err());
}
