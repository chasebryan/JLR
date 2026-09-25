//! Protocol test vectors.
//!
//! Every signed or hashed JLR record has a fixed encoding. This test computes
//! canonical bytes, digests, identifiers and signatures from fixed inputs and
//! compares them with `docs/vectors/protocol-v1.json`. A change to any wire
//! format changes a vector and fails the test, which is the point: protocol
//! changes need an explicit version decision, and the file is regenerated only
//! on purpose:
//!
//! ```text
//! JLR_UPDATE_VECTORS=1 cargo test -p jlr --test vectors
//! ```
//!
//! Other implementations can check themselves against the same file.

#![allow(clippy::unwrap_used)]

use jlr_boot::{BootState, Component, ReleaseManifest};
use jlr_cbor::{Cbor, Map, Value, encode};
use jlr_crypto::{Digest, Envelope, Role, SigningKeypair, TrustAnchors};
use jlr_ledger::merkle::{Tree, leaf_hash, verify_consistency, verify_inclusion};
use jlr_model::{
    AdmissionState, ArtifactClass, Basis, Capability, CellClass, Decision, EpnRecord, Event, EventKind, NetworkMode,
    ProvenanceRank, ReasonCode, Source, record_type,
};
use jlr_policy::Policy;
use serde_json::{Value as J, json};
use std::path::PathBuf;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn vectors() -> J {
    let seed = [1u8; 32];
    let device = SigningKeypair::from_seed(seed, Role::Device);
    let release = SigningKeypair::from_seed([2u8; 32], Role::Release);
    let mut anchors = TrustAnchors::new();
    anchors.insert(device.public());
    anchors.insert(release.public());

    // --- deterministic CBOR (JLR-DCBOR/1) ---
    let cbor_cases: Vec<(&str, Value)> = vec![
        ("uint 0", Value::Uint(0)),
        ("uint 1000", Value::Uint(1000)),
        ("uint max", Value::Uint(u64::MAX)),
        ("negative -1", Value::from(-1i64)),
        ("text IETF", Value::Text("IETF".into())),
        ("bytes", Value::Bytes(vec![1, 2, 3, 4])),
        ("array", Value::Array(vec![1u8.into(), 2u8.into(), 3u8.into()])),
        (
            "map keys sorted by encoding, inserted out of order",
            Value::Map(Map::new().with("aa", 5u8).with(-1i64, 3u8).with(100u8, 2u8).with("z", 4u8).with(10u8, 1u8)),
        ),
        ("tag 18 wrapped uint", Value::Tag(18, Box::new(Value::Uint(1)))),
        ("bool and null", Value::Array(vec![Value::Bool(true), Value::Bool(false), Value::Null])),
    ];
    let cbor: Vec<J> =
        cbor_cases.iter().map(|(n, v)| json!({"name": n, "diagnostic": v.diag(), "hex": hex(&encode(v))})).collect();

    // --- an EPN record and its identifier ---
    let epn = EpnRecord {
        schema: 1,
        class: ArtifactClass::Exe,
        name: "ls".into(),
        version: Some("9.4-3".into()),
        size: 138_208,
        digest: Digest::of(b"vector artifact bytes"),
        provenance: ProvenanceRank::SourceKnown,
        signer: None,
        source: Source { channel: "dpkg".into(), origin: Some("coreutils".into()), path: Some("/usr/bin/ls".into()) },
        dependencies: vec![Digest::of(b"libc")],
    };
    let epn_cbor = epn.to_cbor();

    // --- envelope ---
    let env = Envelope::sign(record_type::EPN, "node-vector", &epn_cbor, &device);
    let verified = Envelope::verify(
        &env,
        record_type::EPN,
        "node-vector",
        &anchors,
        record_type::allowed_signers(record_type::EPN),
    )
    .unwrap();

    // --- event ---
    let event = Event {
        seq: 1,
        boot_id: [7; 16],
        wall_time: 1_800_000_000,
        mono_ns: 42,
        actor: "jlr-engine".into(),
        subject: Some(epn.id().to_string()),
        kind: EventKind::Transition,
        old_state: Some(AdmissionState::Observed),
        new_state: Some(AdmissionState::Verified),
        policy: Digest::of(b"policy"),
        evidence: vec![Digest::of(b"evidence")],
        basis: Basis::ManualOverride,
        detail: "vector".into(),
        prev: Digest::ZERO,
    };

    // --- decision ---
    let decision = Decision {
        state: AdmissionState::Admitted,
        cell: CellClass::Cell2,
        network: NetworkMode::FullUserNetwork,
        capabilities: vec![Capability::parse("FS_READ:/home/user/Documents").unwrap(), Capability::DevAudio],
        reasons: vec![ReasonCode::ManagedInstall],
        basis: Basis::Cryptographic,
        needs_user: None,
        policy: Digest::of(b"policy"),
    };

    // --- policy ---
    let workstation = Policy::workstation(1);

    // --- Merkle tree (RFC 9162) ---
    let leaves: Vec<Digest> = (0..5).map(|i| leaf_hash(format!("leaf-{i}").as_bytes())).collect();
    let mut tree = Tree::new();
    for l in &leaves {
        tree.push(*l);
    }
    let inclusion = tree.inclusion_proof(2, 5).unwrap();
    assert!(verify_inclusion(&leaves[2], 2, 5, &inclusion, &tree.root()));
    let consistency = tree.consistency_proof(3, 5).unwrap();
    assert!(verify_consistency(3, 5, &tree.root_at(3).unwrap(), &tree.root(), &consistency));

    // --- release manifest and boot state ---
    let image = b"vector base image";
    let manifest = ReleaseManifest {
        schema: 1,
        name: "jlr-base".into(),
        version: "0.1.0".into(),
        epoch: 3,
        image_digest: Digest::of(image),
        image_size: image.len() as u64,
        min_epoch: 2,
        policy_digest: Some(workstation.digest()),
        components: vec![Component { name: "jlr".into(), digest: Digest::of(b"jlr binary") }],
    };
    let manifest_env = manifest.sign(&release);
    let mut state = BootState::fresh();
    state.install("b");

    json!({
        "format": "jlr-protocol-vectors",
        "version": 1,
        "note": "Regenerate only deliberately: JLR_UPDATE_VECTORS=1 cargo test -p jlr --test vectors. A changed vector is a protocol change.",
        "cbor": cbor,
        "keys": {
            "device_seed": hex(&seed),
            "device_public": hex(device.public().as_bytes()),
            "device_kid": hex(&device.public().id().0),
            "release_seed": hex(&[2u8; 32]),
            "release_public": hex(release.public().as_bytes()),
        },
        "epn": {
            "fields": {"class": "EXE", "name": "ls", "version": "9.4-3", "size": 138208,
                       "digest": Digest::of(b"vector artifact bytes").to_string(),
                       "provenance": "SOURCE_KNOWN",
                       "source": {"channel": "dpkg", "origin": "coreutils", "path": "/usr/bin/ls"}},
            "record_cbor": hex(&epn_cbor),
            "record_digest": Digest::of(&epn_cbor).to_string(),
            "id": epn.id().to_string(),
        },
        "envelope": {
            "record_type": record_type::EPN,
            "scope": "node-vector",
            "signer": "device_seed",
            "cose_sign1": hex(&env),
            "envelope_digest": verified.envelope_digest.to_string(),
            "record_digest": verified.record_digest.to_string(),
            "external_aad": "JLR/1/epn/node-vector",
        },
        "event": {"record_cbor": hex(&event.to_cbor()), "digest": Digest::of(&event.to_cbor()).to_string()},
        "decision": {"record_cbor": hex(&decision.to_cbor())},
        "policy": {
            "workstation_epoch_1_digest": workstation.digest().to_string(),
            "workstation_epoch_1_cbor_len": workstation.to_cbor().len(),
        },
        "merkle": {
            "leaves": ["leaf-0", "leaf-1", "leaf-2", "leaf-3", "leaf-4"],
            "leaf_hashes": leaves.iter().map(Digest::to_string).collect::<Vec<_>>(),
            "root_5": tree.root().to_string(),
            "root_3": tree.root_at(3).unwrap().to_string(),
            "inclusion_index_2_size_5": inclusion.iter().map(Digest::to_string).collect::<Vec<_>>(),
            "consistency_3_to_5": consistency.iter().map(Digest::to_string).collect::<Vec<_>>(),
        },
        "release": {"manifest_cbor": hex(&manifest.to_cbor()), "signed_manifest": hex(&manifest_env), "signer": "release_seed"},
        "boot_state": {"after_install_b": hex(&state.to_cbor())},
    })
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/vectors/protocol-v1.json")
}

#[test]
fn protocol_vectors_match_the_checked_in_file() {
    let now = vectors();
    let text = serde_json::to_string_pretty(&now).unwrap() + "\n";
    if std::env::var_os("JLR_UPDATE_VECTORS").is_some() || !path().exists() {
        std::fs::write(path(), &text).unwrap();
        eprintln!("wrote {}", path().display());
        return;
    }
    let expected = std::fs::read_to_string(path()).unwrap();
    assert_eq!(
        text, expected,
        "a protocol vector changed. If this is intentional, it is a protocol change: bump the affected format version, \
         update docs/INTEGRITY_PROTOCOL.md, and regenerate with JLR_UPDATE_VECTORS=1"
    );
}

#[test]
fn vectors_are_deterministic() {
    assert_eq!(vectors(), vectors());
}
