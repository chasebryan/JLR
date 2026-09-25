use super::*;
use jlr_cbor::Cbor;
use jlr_model::{AdmissionState as S, Assurance, Basis, CellClass, EpnId, EventKind, NetworkMode, Posture};
use jlr_policy::RevocationKind;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

struct Lab {
    _dir: tempfile::TempDir,
    state: PathBuf,
    sys: PathBuf,
    dpkg: PathBuf,
    clock: Arc<AtomicU64>,
}

fn elf() -> Vec<u8> {
    let mut h = vec![0u8; 128];
    h[..4].copy_from_slice(b"\x7fELF");
    h[4] = 2;
    h[5] = 1;
    h[16] = 2; // ET_EXEC
    h
}

impl Lab {
    fn new() -> Lab {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_owned();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let sys = root.join("sys");
        let dpkg = root.join("dpkg");
        fs::create_dir_all(sys.join("usr/bin")).unwrap();
        fs::create_dir_all(dpkg.join("var/lib/dpkg/info")).unwrap();
        for d in [&sys, &sys.join("usr"), &sys.join("usr/bin")] {
            fs::set_permissions(d, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Lab { state: root.join("state"), sys, dpkg, clock: Arc::new(AtomicU64::new(1_800_000_000)), _dir: dir }
    }

    fn file(&self, rel: &str, content: &[u8]) -> PathBuf {
        let p = self.sys.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, content).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// Registers files as owned by a fake dpkg package with matching md5 manifests.
    fn package(&self, name: &str, files: &[(&Path, &[u8])]) {
        let info = self.dpkg.join("var/lib/dpkg/info");
        let status = self.dpkg.join("var/lib/dpkg/status");
        let mut st = fs::read_to_string(&status).unwrap_or_default();
        st.push_str(&format!("Package: {name}\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n\n"));
        fs::write(&status, st).unwrap();
        let mut list = String::new();
        let mut sums = String::new();
        for (p, c) in files {
            list.push_str(&format!("{}\n", p.display()));
            sums.push_str(&format!("{}  {}\n", md5_hex(c), p.display().to_string().trim_start_matches('/')));
        }
        fs::write(info.join(format!("{name}.list")), list).unwrap();
        fs::write(info.join(format!("{name}.md5sums")), sums).unwrap();
    }

    fn cfg(&self) -> Config {
        let clock = self.clock.clone();
        let helper = std::env::var_os("JLR_CELL_INIT")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/jlr-cell-init"));
        Config {
            helper,
            trust: jlr_measure::Trust::current_process(),
            clock: Arc::new(move || clock.load(Ordering::SeqCst)),
            dpkg_root: Some(self.dpkg.clone()),
        }
    }

    fn paths(&self) -> Paths {
        Paths::new(&self.state)
    }

    fn init(&self, kind: PolicyKind) {
        init(&self.paths(), kind, self.clock.load(Ordering::SeqCst)).unwrap();
    }

    fn open(&self) -> Engine {
        Engine::open(self.paths(), self.cfg()).unwrap()
    }

    fn scan_opts() -> ScanOptions {
        ScanOptions { full: true, one_file_system: false, exclude: vec![], max_size: 1 << 20 }
    }
}

fn enroll(name: &str, by: &str, include_unmanaged: bool) -> EnrollOptions {
    EnrollOptions {
        name: name.into(),
        cell: CellClass::Cell2,
        network: NetworkMode::FullUserNetwork,
        ttl_secs: 3600,
        granted_by: by.into(),
        include_unmanaged,
    }
}

fn md5_hex(data: &[u8]) -> String {
    // Independent tiny MD5 via the system tool would need a process; use the crate through jlr-measure's own behaviour instead.
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("md5sum").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(data).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap().split_whitespace().next().unwrap().to_owned()
}

fn id_of(e: &Engine, path: &Path) -> EpnId {
    e.explain(path).unwrap().record.id()
}

fn events(lab: &Lab) -> Vec<jlr_model::Event> {
    let anchors = jlr_crypto::TrustAnchors::from_cbor(&fs::read(lab.paths().anchors()).unwrap()).unwrap();
    let info: NodeInfo = jlr_cbor::Cbor::from_cbor(&fs::read(lab.paths().node()).unwrap()).unwrap();
    jlr_ledger::read_events(&lab.paths().ledger(), &info.node_id, &anchors).unwrap()
}

fn helper_available(lab: &Lab) -> bool {
    let ok = lab.cfg().helper.exists();
    if !ok {
        eprintln!("SKIPPED: build the workspace first so target/debug/jlr-cell-init exists");
    }
    ok
}

#[test]
fn init_creates_a_verifiable_installation_and_refuses_to_run_twice() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    assert!(matches!(init(&lab.paths(), PolicyKind::Workstation, 1), Err(EngineError::AlreadyInitialised)));
    let e = lab.open();
    let st = e.status();
    assert_eq!(st.assurance, Assurance::Companion);
    assert_eq!(st.posture, Posture::Proven);
    assert_eq!((st.policy_name.as_str(), st.policy_epoch), ("workstation", 1));
    assert_eq!(st.anchors, 2);
    assert!(st.ledger_events >= 4, "genesis, two key enrolments and a policy load");
    e.verify_ledger(None).unwrap();
    use std::os::unix::fs::PermissionsExt;
    for k in [lab.paths().device_key(), lab.paths().policy_key()] {
        assert_eq!(fs::metadata(k).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn unmanaged_software_is_observed_not_admitted() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    let exe = lab.file("opt/dropper", &elf());
    let r = e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    assert_eq!(r.new_artifacts, 1);
    let id = id_of(&e, &exe);
    assert_eq!(e.state_of(&id), Some(S::Observed));
    let d = e.explain(&exe).unwrap().decision;
    assert_eq!((d.cell, d.network), (CellClass::Cell0, NetworkMode::None));
    // A second scan changes nothing and adds no events.
    let before = e.status().ledger_events;
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    assert_eq!(e.status().ledger_events, before, "an idempotent scan must not grow the ledger");
}

#[test]
fn strict_policy_quarantines_unmanaged_software() {
    let lab = Lab::new();
    lab.init(PolicyKind::Strict);
    let mut e = lab.open();
    let exe = lab.file("opt/dropper", &elf());
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    assert_eq!(e.state_of(&id_of(&e, &exe)), Some(S::Quarantined));
}

#[test]
fn baseline_admits_managed_software_and_tampering_degrades_it() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let bytes = elf();
    let tool = lab.file("usr/bin/tool", &bytes);
    let stranger = lab.file("opt/stranger", &elf());
    lab.package("tool", &[(&tool, &bytes)]);
    let mut e = lab.open();
    let (report, members) = e
        .enroll_baseline(std::slice::from_ref(&lab.sys), &enroll("initial-host", "operator", false), &Lab::scan_opts())
        .unwrap();
    assert_eq!(members, 1, "only package-managed, manifest-matching files become members");
    assert_eq!(report.new_artifacts, 2);
    let tool_id = id_of(&e, &tool);
    assert_eq!(e.state_of(&tool_id), Some(S::Admitted));
    assert_eq!(e.state_of(&id_of(&e, &stranger)), Some(S::Observed), "non-members stay under ordinary policy");

    // The promotion is recorded step by step with a manual basis, never as automatic verification.
    let evs = events(&lab);
    let steps: Vec<_> = evs
        .iter()
        .filter(|x| x.kind == EventKind::Transition && x.subject.as_deref() == Some(&tool_id.to_string()))
        .collect();
    assert!(steps.len() >= 2, "{steps:?}");
    assert!(steps.iter().all(|s| s.basis == Basis::ManualOverride));
    assert_eq!(steps.last().unwrap().new_state, Some(S::Admitted));
    assert!(evs.iter().any(|x| x.kind == EventKind::Override && x.detail.contains("initial-host")));

    // Tamper with the admitted binary.
    fs::write(&tool, b"#!/bin/sh\necho pwned\n").unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
    let r = e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    assert_eq!(r.degraded.len(), 1, "{r:?}");
    assert_eq!(e.state_of(&tool_id), Some(S::Degraded), "the previously admitted identity must be degraded");
    let new_id = id_of(&e, &tool);
    assert_ne!(new_id, tool_id);
    assert_eq!(e.state_of(&new_id), Some(S::Quarantined), "the new bytes disagree with the package manifest");
    assert_eq!(e.status().posture, Posture::Degraded);
    assert!(events(&lab).iter().any(|x| x.kind == EventKind::Mismatch));
}

#[test]
fn incremental_scan_skips_unchanged_files_but_notices_edits_even_with_preserved_mtime() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    let exe = lab.file("opt/prog", &elf());
    let mut opts = Lab::scan_opts();
    opts.full = false;
    e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    let r = e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    assert_eq!((r.examined, r.unchanged), (0, 1));

    // Edit in place and restore the old mtime; ctime cannot be restored by the writer.
    let old = fs::metadata(&exe).unwrap().modified().unwrap();
    let mut changed = elf();
    changed[100] = 7;
    fs::write(&exe, &changed).unwrap();
    fs::File::options().write(true).open(&exe).unwrap().set_modified(old).unwrap();
    let r = e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    assert_eq!(r.examined, 1, "ctime must expose an edit that preserved mtime");
}

#[test]
fn revocation_wins_and_cannot_be_approved_away() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    let exe = lab.file("opt/bad", &elf());
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    let ex = e.explain(&exe).unwrap();
    let id = ex.record.id();
    assert_eq!(e.state_of(&id), Some(S::Observed));

    let n = e.revoke(RevocationKind::Digest, &ex.record.digest.to_string(), "known malware").unwrap();
    assert_eq!(n, 1);
    assert_eq!(e.state_of(&id), Some(S::Revoked));
    assert_eq!(e.status().revocations, 1);
    assert_eq!(e.status().revocations_epoch, 2);

    // A later approval and a later scan both leave it revoked.
    let d = e.approve(&id.to_string(), CellClass::Cell1, NetworkMode::None, vec![], 3600, "operator").unwrap();
    assert_eq!(d.state, S::Revoked);
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    assert_eq!(e.state_of(&id), Some(S::Revoked));

    // Execution is denied outright.
    match e.run(&exe, &[], &[], &[], true) {
        Err(EngineError::NotRunnable(d)) => assert_eq!(d.state, S::Revoked),
        other => panic!("{other:?}"),
    }
}

#[test]
fn approval_promotes_step_by_step_with_a_manual_basis() {
    let lab = Lab::new();
    lab.init(PolicyKind::Strict);
    let mut e = lab.open();
    let exe = lab.file("opt/tool", &elf());
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    let id = id_of(&e, &exe);
    assert_eq!(e.state_of(&id), Some(S::Quarantined));

    assert!(e.approve("EPN-1-EXE-nope", CellClass::Cell1, NetworkMode::None, vec![], 60, "op").is_err());
    let unknown = EpnId::parse(&format!("EPN-1-EXE-{}", jlr_crypto::Digest::of(b"never seen").hex())).unwrap();
    assert!(
        e.approve(&unknown.to_string(), CellClass::Cell1, NetworkMode::None, vec![], 60, "op").is_err(),
        "cannot approve what was never observed"
    );

    let d = e.approve(&id.to_string(), CellClass::Cell1, NetworkMode::None, vec![], 3600, "alice").unwrap();
    assert_eq!((d.state, d.basis, d.cell), (S::Admitted, Basis::ManualOverride, CellClass::Cell1));
    assert_eq!(e.state_of(&id), Some(S::Admitted));
    let evs = events(&lab);
    let sub = id.to_string();
    let path: Vec<_> = evs
        .iter()
        .filter(|x| x.kind == EventKind::Transition && x.subject.as_deref() == Some(sub.as_str()))
        .map(|x| x.new_state.unwrap())
        .collect();
    // Discovery quarantined it; the approval then walked the state machine one legal step at a time.
    assert_eq!(path, vec![S::Quarantined, S::Verified, S::Admitted]);
    assert!(
        evs.iter()
            .filter(|x| x.kind == EventKind::Transition && x.subject.as_deref() == Some(sub.as_str()))
            .skip(1)
            .all(|x| x.basis == Basis::ManualOverride)
    );

    // The approval expires. Close the first engine first: the ledger allows one writer.
    drop(e);
    lab.clock.fetch_add(7200, Ordering::SeqCst);
    let mut e2 = lab.open();
    e2.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    assert_ne!(e2.state_of(&id), Some(S::Admitted), "an expired approval grants nothing");
}

#[test]
fn state_is_rebuilt_from_the_ledger_not_from_caches() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let exe = lab.file("opt/prog", &elf());
    let id;
    {
        let mut e = lab.open();
        e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
        id = id_of(&e, &exe);
        assert_eq!(e.state_of(&id), Some(S::Observed));
    }
    // Destroy every cache; the ledger alone must restore the truth.
    let _ = fs::remove_file(lab.paths().index());
    let e = lab.open();
    assert_eq!(e.state_of(&id), Some(S::Observed));
    assert_eq!(e.status().by_state.get(&S::Observed), Some(&1));
}

#[test]
fn a_tampered_policy_is_refused_and_no_default_is_substituted() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let p = lab.paths().policy();
    let mut bytes = fs::read(&p).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    fs::write(&p, &bytes).unwrap();
    match Engine::open(lab.paths(), lab.cfg()) {
        Err(EngineError::Verification(m)) => assert!(m.contains("policy"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_policy_signed_by_the_wrong_role_is_refused() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    // Re-sign the policy with the device key, which must not be able to define policy.
    let device = jlr_crypto::SigningKeypair::load(&lab.paths().device_key()).unwrap();
    let forged = jlr_crypto::Envelope::sign(
        jlr_model::record_type::POLICY,
        "*",
        &jlr_cbor::Cbor::to_cbor(&jlr_policy::Policy::workstation(5)),
        &device,
    );
    fs::write(lab.paths().policy(), forged).unwrap();
    assert!(matches!(Engine::open(lab.paths(), lab.cfg()), Err(EngineError::Verification(_))));
}

#[test]
fn policy_epoch_cannot_go_backwards() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let key = jlr_crypto::SigningKeypair::load(&lab.paths().policy_key()).unwrap();
    // Install epoch 2 and let the engine record it.
    let p2 = jlr_policy::Policy::strict(2);
    let old = fs::read(lab.paths().policy()).unwrap();
    fs::write(
        lab.paths().policy(),
        jlr_crypto::Envelope::sign(jlr_model::record_type::POLICY, "*", &jlr_cbor::Cbor::to_cbor(&p2), &key),
    )
    .unwrap();
    // The engine notes the loaded epoch in the ledger; simulate the loader doing so.
    {
        let anchors = jlr_crypto::TrustAnchors::from_cbor(&fs::read(lab.paths().anchors()).unwrap()).unwrap();
        let info: NodeInfo = jlr_cbor::Cbor::from_cbor(&fs::read(lab.paths().node()).unwrap()).unwrap();
        let device = jlr_crypto::SigningKeypair::load(&lab.paths().device_key()).unwrap();
        let (mut l, _) =
            jlr_ledger::Ledger::open(&lab.paths().ledger(), &info.node_id, device, &anchors, [1; 16]).unwrap();
        l.append(jlr_ledger::EventDraft::new(
            "test",
            EventKind::PolicyLoad,
            &format!("policy=strict epoch=2 digest={}", p2.digest()),
        ))
        .unwrap();
    }
    assert!(Engine::open(lab.paths(), lab.cfg()).is_ok());
    // An attacker restores the old, validly signed epoch-1 policy.
    fs::write(lab.paths().policy(), old).unwrap();
    assert!(matches!(Engine::open(lab.paths(), lab.cfg()), Err(EngineError::Rollback(_))));
}

#[test]
fn unverifiable_approvals_grant_nothing_and_are_logged() {
    let lab = Lab::new();
    lab.init(PolicyKind::Strict);
    let exe = lab.file("opt/tool", &elf());
    let id;
    {
        let mut e = lab.open();
        e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
        id = id_of(&e, &exe);
        e.approve(&id.to_string(), CellClass::Cell1, NetworkMode::None, vec![], 3600, "alice").unwrap();
    }
    let f = lab.paths().approvals().join(format!("{}.cose", id.digest.hex()));
    let mut b = fs::read(&f).unwrap();
    let last = b.len() - 3;
    b[last] ^= 1;
    fs::write(&f, b).unwrap();
    let e = lab.open();
    assert!(events(&lab).iter().any(|x| x.kind == EventKind::Degraded && x.detail.contains("unverifiable")));
    // The state in the ledger still says Admitted (history is history), but a fresh evaluation
    // no longer honours the damaged approval.
    let d = e.explain(&exe).unwrap().decision;
    assert_ne!(d.state, S::Admitted);
}

#[test]
fn checkpoints_detect_rollback_of_the_whole_state_directory() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    lab.file("opt/a", &elf());
    let mut e = lab.open();
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    let cp = e.checkpoint().unwrap();
    lab.file("opt/b", &elf());
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    let full = e.verify_ledger(Some(&cp)).unwrap();
    assert!(full.external_checkpoint_matched);
    drop(e);
    // Roll the ledger back to just after init (drop its later events) and delete local checkpoints.
    let events_log = lab.paths().ledger().join("events.log");
    let data = fs::read(&events_log).unwrap();
    let mut pos = 0;
    let mut ends = vec![];
    while pos + 8 <= data.len() {
        let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 8 + len;
        ends.push(pos);
    }
    fs::write(&events_log, &data[..ends[3]]).unwrap();
    fs::write(lab.paths().ledger().join("checkpoints.log"), b"").unwrap();
    let e = Engine::open(lab.paths(), lab.cfg()).unwrap();
    assert!(e.verify_ledger(None).is_ok(), "self-consistent after a full local rollback");
    assert!(e.verify_ledger(Some(&cp)).is_err(), "only the independent checkpoint exposes the rollback");
}

#[test]
fn observed_software_runs_in_a_bare_cell_and_denied_software_does_not_run() {
    let lab = Lab::new();
    if !helper_available(&lab) {
        return;
    }
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    // Use a real, self-contained system binary as the unmanaged workload.
    let sh = fs::canonicalize("/bin/sh").unwrap();
    let copy = lab.file("opt/sh", &fs::read(&sh).unwrap());
    let r = match e.run(
        &copy,
        &["-c".into(), "echo inside; test -e /home && echo LEAK".into()],
        &["PATH=/usr/bin:/bin".into()],
        &[],
        true,
    ) {
        Ok(r) => r,
        Err(EngineError::Cell(jlr_cell::CellError::Refused(rep))) => {
            eprintln!("SKIPPED: kernel refused namespaces: {:?}", rep.unavailable);
            return;
        }
        Err(e) => panic!("{e}"),
    };
    assert_eq!(r.decision.state, S::Observed);
    assert_eq!(String::from_utf8_lossy(&r.stdout).trim(), "inside");
    assert_eq!(r.exit_code, 1, "the final `test -e /home` is false inside the cell");
    assert!(r.report.mandatory_missing.is_empty());
    let evs = events(&lab);
    assert!(evs.iter().any(|x| x.kind == EventKind::Enforcement && x.detail.contains("started")));
    assert!(evs.iter().any(|x| x.kind == EventKind::Enforcement && x.detail.contains("exited with code 1")));

    // Under the strict policy the same file is quarantined and must not run.
    let lab2 = Lab::new();
    lab2.init(PolicyKind::Strict);
    let mut e2 = lab2.open();
    let copy2 = lab2.file("opt/sh", &fs::read(&sh).unwrap());
    match e2.run(&copy2, &[], &[], &[], true) {
        Err(EngineError::NotRunnable(d)) => assert_eq!(d.state, S::Quarantined),
        other => panic!("{other:?}"),
    }
    assert!(events(&lab2).iter().any(|x| x.kind == EventKind::Enforcement && x.detail.contains("denied execution")));
}

#[test]
fn a_file_swapped_after_measurement_never_runs() {
    let lab = Lab::new();
    if !helper_available(&lab) {
        return;
    }
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    let sh = fs::canonicalize("/bin/sh").unwrap();
    let prog = lab.file("opt/prog", &fs::read(&sh).unwrap());
    // A run measures, seals and executes the same bytes; the file on disk is irrelevant after sealing.
    let r = e.run(&prog, &["-c".into(), "echo ok".into()], &["PATH=/usr/bin:/bin".into()], &[], true);
    match r {
        Ok(r) => assert_eq!(String::from_utf8_lossy(&r.stdout).trim(), "ok"),
        Err(EngineError::Cell(jlr_cell::CellError::Refused(_))) => {}
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn set_policy_requires_a_higher_epoch_and_takes_effect() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let exe = lab.file("opt/tool", &elf());
    let mut e = lab.open();
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    let id = id_of(&e, &exe);
    assert_eq!(e.state_of(&id), Some(S::Observed));

    assert!(
        matches!(e.set_policy(jlr_policy::Policy::strict(1)), Err(EngineError::Rollback(_))),
        "same epoch must be refused"
    );
    let mut invalid = jlr_policy::Policy::strict(2);
    invalid.tiers.pop();
    assert!(matches!(e.set_policy(invalid), Err(EngineError::Invalid(_))), "an invalid policy must be refused");
    assert_eq!(e.policy().epoch, 1);

    e.set_policy(jlr_policy::Policy::strict(2)).unwrap();
    assert_eq!((e.policy().name.as_str(), e.policy().epoch), ("strict", 2));
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    assert_eq!(e.state_of(&id), Some(S::Quarantined), "the stricter policy re-evaluates known artifacts");
    drop(e);
    assert_eq!(lab.open().policy().epoch, 2, "the new policy survives a restart");
    assert!(events(&lab).iter().any(|x| x.kind == EventKind::PolicyLoad && x.detail.contains("epoch=2")));
}

#[test]
fn the_same_file_has_the_same_identity_at_different_times() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let exe = lab.file("opt/prog", &elf());
    let mut e = lab.open();
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    let first = id_of(&e, &exe);
    lab.clock.fetch_add(86_400, Ordering::SeqCst);
    let second = id_of(&e, &exe);
    assert_eq!(first, second, "identity must not depend on when the file is observed");
    assert_eq!(e.state_of(&second), Some(S::Observed), "and the recorded state must be found again");
    let before = e.status().ledger_events;
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    assert_eq!(e.status().ledger_events, before, "rescanning later must not look like a new artifact");
}

#[test]
fn exec_verdict_measures_the_descriptor_not_the_path() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    let exe = lab.file("opt/tool", &elf());
    let file = fs::File::open(&exe).unwrap();
    // Swap the path after the descriptor was opened, as an attacker racing the gate would.
    let mut evil = elf();
    evil[100] = 0xee;
    fs::remove_file(&exe).unwrap();
    fs::write(&exe, &evil).unwrap();
    let v = e.decide_exec(file, &exe).unwrap();
    assert_eq!(v.decision.state, S::Observed);
    assert!(!v.allowed, "an unknown binary may not run outside an observation cell");
    assert!(!v.enforce, "the built-in policies audit until enforcement is switched on");
    // The identity is that of the ORIGINAL bytes, which is what would have executed.
    let original = jlr_crypto::Digest::of(&elf());
    let record_digest = e.explain(&exe).unwrap().record.digest;
    assert_ne!(record_digest, original, "the file on disk now differs");
    assert_eq!(e.state_of(&v.id), Some(S::Observed));
    assert_ne!(v.id, id_of(&e, &exe), "the decision must not be about the swapped file");
}

#[test]
fn include_unmanaged_enrols_everything_that_is_not_known_bad() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    let a = lab.file("usr/bin/a", &elf());
    let mut other = elf();
    other[90] = 1;
    let b = lab.file("opt/b", &other);
    let (_, members) = e
        .enroll_baseline(std::slice::from_ref(&lab.sys), &enroll("base-image", "installer", true), &Lab::scan_opts())
        .unwrap();
    assert_eq!(members, 2, "no package database vouches for these, but the installer chose to");
    assert_eq!(e.state_of(&id_of(&e, &a)), Some(S::Admitted));
    assert_eq!(e.state_of(&id_of(&e, &b)), Some(S::Admitted));
    // Enrolled state is recorded as a manual override.
    assert!(events(&lab).iter().any(|x| x.kind == EventKind::Override && x.detail.contains("base-image")));
}

#[test]
fn scanning_in_bounded_slices_gives_the_same_result_as_one_scan() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    for i in 0..7u8 {
        let mut b = elf();
        b[80] = i;
        lab.file(&format!("opt/p{i}"), &b);
    }
    let opts = Lab::scan_opts();
    let files = list_artifacts(std::slice::from_ref(&lab.sys), &opts).unwrap();
    assert_eq!(files.len(), 7);
    let mut e = lab.open();
    let mut examined = 0;
    for chunk in files.chunks(3) {
        examined += e.scan_files(chunk, &opts).unwrap().examined;
    }
    assert_eq!(examined, 7);
    assert_eq!(e.status().by_state.get(&S::Observed), Some(&7));
}

#[test]
fn open_wait_waits_for_the_lock_then_gives_up() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let held = lab.open();
    let t = std::time::Instant::now();
    let r = Engine::open_wait(lab.paths(), lab.cfg(), std::time::Duration::from_millis(200));
    assert!(matches!(r, Err(EngineError::Ledger(jlr_ledger::LedgerError::Locked))));
    assert!(t.elapsed() >= std::time::Duration::from_millis(190), "it must actually wait");
    drop(held);
    assert!(Engine::open_wait(lab.paths(), lab.cfg(), std::time::Duration::from_millis(200)).is_ok());
}
