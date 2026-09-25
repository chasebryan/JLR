use super::*;
use jlr_cbor::Cbor;
use jlr_crypto::Digest;

fn sample_epn() -> EpnRecord {
    EpnRecord {
        schema: EpnRecord::SCHEMA,
        class: ArtifactClass::Exe,
        name: "ls".into(),
        version: Some("9.4".into()),
        size: 138_208,
        digest: Digest::of(b"ls-bytes"),
        provenance: ProvenanceRank::DistroSigned,
        signer: Some("debian-archive".into()),
        source: Source { channel: "dpkg".into(), origin: Some("coreutils".into()), path: Some("/usr/bin/ls".into()) },
        dependencies: vec![Digest::of(b"libc")],
    }
}

#[test]
fn epn_id_is_content_addressed_and_stable() {
    let r = sample_epn();
    let id = r.id();
    assert_eq!(id.digest, Digest::of(&r.to_cbor()));
    assert!(id.to_string().starts_with("EPN-1-EXE-"));
    assert_eq!(id.to_string().len(), "EPN-1-EXE-".len() + 64);
    assert_eq!(EpnId::parse(&id.to_string()), Some(id));

    // Any change of identity-bearing content changes the identifier.
    let mut other = r.clone();
    other.size += 1;
    assert_ne!(other.id(), id);
    let mut other = r.clone();
    other.source.path = Some("/tmp/ls".into());
    assert_ne!(other.id(), id);
}

#[test]
fn epn_id_rejects_malformed_text() {
    for s in ["", "EPN-2-EXE-00", "EPN-1-NOPE-00", "EPN-1-EXE-zz", "EPN-1-EXE", "epn-1-exe-"] {
        assert_eq!(EpnId::parse(s), None, "{s}");
    }
}

#[test]
fn epn_record_roundtrips_and_pins_bytes() {
    let r = sample_epn();
    let bytes = r.to_cbor();
    assert_eq!(EpnRecord::from_cbor(&bytes).unwrap(), r);
    // A byte flip must not produce a different accepted record with the same id.
    for i in 0..bytes.len() {
        let mut m = bytes.clone();
        m[i] ^= 0x01;
        if let Ok(other) = EpnRecord::from_cbor(&m) {
            assert_ne!(other.id(), r.id(), "byte {i}");
        }
    }
}

#[test]
fn provenance_ordering() {
    assert!(ProvenanceRank::Reproduced.satisfies(ProvenanceRank::DistroSigned));
    assert!(ProvenanceRank::DistroSigned.satisfies(ProvenanceRank::DistroSigned));
    assert!(!ProvenanceRank::SourceKnown.satisfies(ProvenanceRank::DistroSigned));
    assert!(!ProvenanceRank::Unknown.satisfies(ProvenanceRank::VerifiedChecksum));
}

#[test]
fn state_machine_matches_specification() {
    use AdmissionState::*;
    // Permitted edges from the specification's state diagram.
    let allowed = [
        (Unknown, Quarantined),
        (Quarantined, Observed),
        (Observed, Verified),
        (Verified, Admitted),
        (Admitted, Degraded),
        (Degraded, Quarantined),
        (Degraded, Revoked),
        (Observed, PolicyBlocked),
        (Admitted, Revoked),
    ];
    for (a, b) in allowed {
        assert!(a.can_become(b), "{a} -> {b}");
    }
    // Revocation is reachable from every state.
    for s in AdmissionState::ALL {
        assert!(s.can_become(Revoked));
    }
    // Revoked is terminal: nothing leaves it except itself.
    for s in AdmissionState::ALL {
        if *s != Revoked {
            assert!(!Revoked.can_become(*s), "Revoked -> {s} must be refused");
        }
    }
    // No shortcut to admission.
    for s in [Unknown, Quarantined, Observed, Degraded, PolicyBlocked] {
        assert!(!s.can_become(Admitted), "{s} -> ADMITTED must be refused");
    }
    assert!(Unknown.transition(Admitted).is_err());
    assert!(!Verified.is_promotion_to(Admitted));
    assert!(Observed.is_promotion_to(Verified));
    assert!(!Admitted.is_promotion_to(Degraded));
}

#[test]
fn only_verified_and_admitted_run_normally() {
    for s in AdmissionState::ALL {
        let expect = matches!(s, AdmissionState::Verified | AdmissionState::Admitted);
        assert_eq!(s.permits_normal_execution(), expect, "{s}");
    }
}

#[test]
fn capability_parse_display_roundtrip() {
    for s in [
        "FS_READ:/home/user/Documents",
        "FS_WRITE:/var/lib/app",
        "NET_CONNECT:example.org:443",
        "NET_LISTEN:127.0.0.1:8080",
        "DEV_AUDIO",
        "DEV_GPU",
        "DEV_USB:hid",
        "PROC_SPAWN:EPN-1-EXE-abcd",
        "IPC_DBUS:org.freedesktop.Notifications",
        "HOST_SERVICE_CONTROL:cups",
        "KERNEL_MODULE_LOAD",
        "RAW_NETWORK",
        "RAW_BLOCK_WRITE",
    ] {
        let c = Capability::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"));
        assert_eq!(c.to_string(), s);
        assert_eq!(Capability::from_cbor(&c.to_cbor()).unwrap(), c);
    }
}

#[test]
fn capability_rejects_malformed_and_traversal() {
    for s in [
        "",
        "FS_READ",
        "FS_READ:relative/path",
        "FS_READ:/a/../etc",
        "FS_READ:/a//b",
        "FS_READ:/a/",
        "FS_READ:/a/./b",
        "NET_CONNECT:example.org",
        "NET_CONNECT:example.org:99999",
        "NET_CONNECT:bad host:80",
        "DEV_AUDIO:extra",
        "RAW_NETWORK:x",
        "NOPE",
    ] {
        assert!(Capability::parse(s).is_err(), "{s:?} should be rejected");
    }
}

#[test]
fn capability_cbor_rejects_non_canonical_text() {
    // "0443" parses to port 443 but re-displays as "443", so the record is not canonical.
    let c = Capability::parse("NET_CONNECT:example.org:0443").unwrap();
    assert_eq!(c.to_string(), "NET_CONNECT:example.org:443");
    let v = jlr_cbor::Value::Text("NET_CONNECT:example.org:0443".into());
    let decoded = Capability::from_value(&v).unwrap();
    let list = vec![decoded];
    let noncanonical = jlr_cbor::encode(&jlr_cbor::Value::Array(vec![v]));
    assert!(<Vec<Capability>>::from_cbor(&noncanonical).is_err());
    assert!(<Vec<Capability>>::from_cbor(&list.to_cbor()).is_ok());
}

#[test]
fn high_risk_capabilities() {
    for s in ["KERNEL_MODULE_LOAD", "RAW_NETWORK", "RAW_BLOCK_WRITE", "HOST_SERVICE_CONTROL:cups", "DEV_USB:mass"] {
        assert!(Capability::parse(s).unwrap().is_high_risk(), "{s}");
    }
    for s in ["FS_READ:/tmp", "NET_CONNECT:a.b:1", "DEV_AUDIO", "DEV_GPU"] {
        assert!(!Capability::parse(s).unwrap().is_high_risk(), "{s}");
    }
}

#[test]
fn coded_enums_roundtrip_and_reject_unknown_codes() {
    for c in ArtifactClass::ALL {
        assert_eq!(ArtifactClass::from_code(c.code()), Some(*c));
        assert_eq!(ArtifactClass::parse(c.as_str()), Some(*c));
        assert_eq!(ArtifactClass::from_cbor(&c.to_cbor()).unwrap(), *c);
    }
    assert!(ArtifactClass::from_cbor(&jlr_cbor::encode(&jlr_cbor::Value::Uint(99))).is_err());
    assert!(AdmissionState::from_cbor(&jlr_cbor::encode(&jlr_cbor::Value::Uint(0))).is_err());
}

#[test]
fn event_and_decision_roundtrip() {
    let ev = Event {
        seq: 7,
        boot_id: [9; 16],
        wall_time: 1_790_000_100,
        mono_ns: 42,
        actor: "jlrd".into(),
        subject: Some(sample_epn().id().to_string()),
        kind: EventKind::Transition,
        old_state: Some(AdmissionState::Observed),
        new_state: Some(AdmissionState::Verified),
        policy: Digest::of(b"policy"),
        evidence: vec![Digest::of(b"e1"), Digest::of(b"e2")],
        basis: Basis::Cryptographic,
        detail: "ok".into(),
        prev: Digest::ZERO,
    };
    assert_eq!(Event::from_cbor(&ev.to_cbor()).unwrap(), ev);

    let d = Decision {
        state: AdmissionState::Admitted,
        cell: CellClass::Cell2,
        network: NetworkMode::FullUserNetwork,
        capabilities: vec![Capability::DevAudio, Capability::parse("FS_READ:/home/u").unwrap()],
        reasons: vec![ReasonCode::ManagedInstall],
        basis: Basis::Cryptographic,
        needs_user: None,
        policy: Digest::of(b"policy"),
    };
    assert_eq!(Decision::from_cbor(&d.to_cbor()).unwrap(), d);
}

#[test]
fn record_types_have_disjoint_signer_roles_where_required() {
    use jlr_crypto::Role;
    assert_eq!(record_type::allowed_signers(record_type::POLICY), &[Role::Policy]);
    assert_eq!(record_type::allowed_signers(record_type::RELEASE), &[Role::Release]);
    assert!(!record_type::allowed_signers(record_type::EVENT).contains(&Role::Policy));
    assert!(record_type::allowed_signers("no-such-type").is_empty());
}

#[test]
fn identity_is_stable_across_observations() {
    // Observing the same file twice must produce the same EPN. Any field that varies between
    // observations of unchanged bytes (a timestamp, a counter) would break this.
    let a = sample_epn();
    let b = EpnRecord::from_cbor(&a.to_cbor()).unwrap();
    assert_eq!(a.id(), b.id());
    assert_eq!(a.to_cbor(), b.to_cbor());
}

#[test]
fn sanitize_makes_untrusted_text_one_line_of_visible_characters() {
    assert_eq!(sanitize("/usr/bin/ls"), "/usr/bin/ls");
    assert_eq!(sanitize("a\nb"), "a\\u{a}b", "a newline must not be able to start a forged ledger row");
    assert_eq!(sanitize("x\x1b[2Jy"), "x\\u{1b}[2Jy", "terminal escapes are neutralised");
    assert_eq!(sanitize("exe\u{202e}gpj.txt"), "exe\\u{202e}gpj.txt");
    assert_eq!(sanitize("a\u{200b}b"), "a\\u{200b}b");
    assert_eq!(sanitize("caf\u{e9}"), "caf\u{e9}", "ordinary non-ASCII text is kept");
    assert_eq!(sanitize("\u{65e5}\u{672c}\u{8a9e}"), "\u{65e5}\u{672c}\u{8a9e}");
    let long = "a".repeat(5000);
    assert!(sanitize(&long).len() < 1100 && sanitize(&long).ends_with("[truncated]"));
    assert!(!sanitize("\r\n\t\0").chars().any(char::is_control));
}

#[test]
fn sanitize_also_escapes_separators_and_invisible_characters() {
    // Line and paragraph separators are not control characters, yet Unicode-aware viewers, Python's splitlines and
    // JSON consumers treat them as line breaks. The others let text hide or read as something else.
    for c in [
        '\u{2028}',
        '\u{2029}',
        '\u{85}',
        '\u{9f}',
        '\u{34f}',
        '\u{115f}',
        '\u{17b4}',
        '\u{180b}',
        '\u{2060}',
        '\u{2800}',
        '\u{3164}',
        '\u{fe0f}',
        '\u{feff}',
        '\u{ffa0}',
        '\u{fffc}',
        '\u{e0041}',
        '\u{e0100}',
        '\u{202a}',
        '\u{2066}',
    ] {
        let out = sanitize(&format!("a{c}b"));
        assert!(!out.contains(c), "U+{:04X} passed through", c as u32);
        assert!(out.starts_with('a') && out.ends_with('b') && out.contains("\\u{"), "{out:?}");
    }
    // Printable text in other scripts, and ordinary punctuation, is untouched.
    for ok in ["\u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}", "\u{5b89}\u{5168}", "a-b_c.d (e) [f] {g}", "\u{1f600}"] {
        assert_eq!(sanitize(ok), ok);
    }
}

#[test]
fn sanitize_is_idempotent_so_layers_do_not_double_escape() {
    for s in [
        "plain",
        "a\\b",
        "CN=Doe\\, John",
        "x\ny",
        "\u{202e}rtl",
        "already \\u{a} escaped",
        "tab\there",
        &"z".repeat(3000),
    ] {
        let once = sanitize(s);
        assert_eq!(sanitize(&once), once, "{s:?}");
        assert_eq!(sanitize(&sanitize(&once)), once);
    }
    assert_eq!(sanitize("C:\\dir"), "C:\\dir", "a backslash is data, not an escape");
}

#[test]
fn sanitize_is_idempotent_when_the_limit_falls_inside_an_escape() {
    // A hostile character right at the limit: the escape must be written whole or not at all, and the result must be
    // a fixed point (an earlier version cut the escape in the middle on the second application).
    for pad in 1000..1030 {
        for tail in ["xyz", "", "\u{e0041}q", "\n", "\u{202e}\u{202e}\u{202e}"] {
            let raw = format!("{}\u{e0041}{tail}", "a".repeat(pad));
            let once = sanitize(&raw);
            assert_eq!(sanitize(&once), once, "pad {pad}, tail {tail:?}");
            assert!(!once.contains('\u{e0041}'));
            assert!(once.len() <= 1024 + "\u{2026}[truncated]".len(), "{}", once.len());
            // No escape is ever cut in half: every backslash-u is followed by a closing brace before the end.
            for (k, _) in once.match_indices("\\u{") {
                assert!(once[k..].contains('}'), "cut escape in {once:?}");
            }
        }
    }
}

#[test]
fn sanitize_to_bounds_each_field_so_the_fields_after_it_survive() {
    let hostile_path = "/x/".to_owned() + &"d".repeat(3000);
    let line = format!("exec gate: denied {}: state QUARANTINED [EVIDENCE_MISSING]", sanitize_to(&hostile_path, 200));
    assert!(line.ends_with("state QUARANTINED [EVIDENCE_MISSING]"), "{line}");
    assert!(line.len() < 400);
}
