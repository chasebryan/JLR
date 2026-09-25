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
    let vid = v.id.expect("the file was measurable");
    assert_eq!(e.state_of(&vid), Some(S::Observed));
    assert_ne!(vid, id_of(&e, &exe), "the decision must not be about the swapped file");
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

#[test]
fn unchanged_files_are_rehashed_once_their_evidence_is_older_than_the_policy_allows() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation); // evidence_max_age_secs = 7 days
    lab.file("opt/prog", &elf());
    let mut e = lab.open();
    let mut opts = Lab::scan_opts();
    opts.full = false;
    e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    let r = e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    assert_eq!((r.examined, r.unchanged), (0, 1), "fresh evidence is reused");

    lab.clock.fetch_add(6 * 86_400, Ordering::SeqCst);
    let r = e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    assert_eq!((r.examined, r.unchanged), (0, 1), "still inside the limit");

    lab.clock.fetch_add(2 * 86_400, Ordering::SeqCst);
    let r = e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    assert_eq!(
        (r.examined, r.unchanged),
        (1, 0),
        "stale evidence must be re-collected even though the metadata is unchanged"
    );
    // ...and the re-measurement resets the clock.
    let r = e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    assert_eq!((r.examined, r.unchanged), (0, 1));
}

// ---- adversarial-review follow-ups -------------------------------------------------------------------------

#[test]
fn a_file_that_cannot_be_measured_is_a_denial_not_an_internal_error() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    // A sparse file costs nothing to create and is larger than the measurement limit. The user who executes a
    // file controls its size, so "too large" must not be a way to slip past the gate.
    let big = lab.file("opt/padded", &elf());
    fs::OpenOptions::new().write(true).open(&big).unwrap().set_len(600 << 20).unwrap();
    let before = e.status().by_state.clone();
    let v = e.decide_exec(fs::File::open(&big).unwrap(), &big).expect("an unmeasurable file yields a verdict");
    assert!(!v.allowed, "unmeasurable means not allowed");
    assert!(v.id.is_none() && v.unmeasurable.is_some());
    assert_eq!((v.decision.state, v.decision.cell), (S::Quarantined, CellClass::Cell0));
    assert_eq!(v.decision.network, NetworkMode::None);
    assert!(v.max_age_secs <= 10, "a denial that may be transient must not be cached for long");
    assert_eq!(e.status().by_state, before, "nothing is recorded as an artifact for a file that was never measured");

    // A directory and a FIFO are decisions too, not errors.
    let dir = lab.sys.join("opt");
    let v = e.decide_exec(fs::File::open(&dir).unwrap(), &dir).unwrap();
    assert!(!v.allowed && v.unmeasurable.is_some());
}

#[test]
fn a_repeat_exec_decision_for_an_unchanged_file_writes_nothing() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    let exe = lab.file("opt/tool", &elf());
    let first = e.decide_exec(fs::File::open(&exe).unwrap(), &exe).unwrap();
    let events_after_first = e.status().ledger_events;
    let index_after_first = fs::read(lab.paths().index()).unwrap();

    lab.clock.fetch_add(30, Ordering::SeqCst);
    for _ in 0..5 {
        let v = e.decide_exec(fs::File::open(&exe).unwrap(), &exe).unwrap();
        assert_eq!(v.id, first.id);
        assert_eq!(v.decision.state, first.decision.state);
    }
    assert_eq!(e.status().ledger_events, events_after_first, "an uncached exec must not grow the ledger");
    assert_eq!(
        fs::read(lab.paths().index()).unwrap(),
        index_after_first,
        "nor rewrite the index: every exec by any user would otherwise cost a full-file write"
    );
}

#[test]
fn an_expired_approval_is_noticed_by_an_incremental_scan() {
    let lab = Lab::new();
    lab.init(PolicyKind::Strict);
    let mut e = lab.open();
    let exe = lab.file("opt/tool", &elf());
    let mut opts = Lab::scan_opts();
    opts.full = false;
    e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    let id = id_of(&e, &exe);
    e.approve(&id.to_string(), CellClass::Cell1, NetworkMode::None, vec![], 3600, "alice").unwrap();
    assert_eq!(e.state_of(&id), Some(S::Admitted));
    let r = e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    assert_eq!((r.examined, r.unchanged), (0, 1), "inside the approval window nothing needs re-deciding");

    // Metadata is unchanged, so only the row's own validity window can reveal that the approval ran out.
    lab.clock.fetch_add(7200, Ordering::SeqCst);
    let r = e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    assert_eq!(r.examined, 1, "an incremental scan must re-decide once the approval has expired");
    assert_ne!(e.state_of(&id), Some(S::Admitted), "an expired approval grants nothing");
}

#[test]
fn a_new_policy_epoch_re_decides_files_an_incremental_scan_would_skip() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    let exe = lab.file("opt/tool", &elf());
    let mut opts = Lab::scan_opts();
    opts.full = false;
    e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    let id = id_of(&e, &exe);
    assert_eq!(e.state_of(&id), Some(S::Observed));
    e.set_policy(jlr_policy::Policy::strict(2)).unwrap();
    let r = e.scan(std::slice::from_ref(&lab.sys), &opts).unwrap();
    assert_eq!(r.examined, 1, "rows recorded under an older policy epoch are not reused");
    assert_eq!(e.state_of(&id), Some(S::Quarantined));
}

#[test]
fn losing_the_object_store_still_degrades_a_trusted_file_that_changes() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let bytes = elf();
    let tool = lab.file("usr/bin/tool", &bytes);
    lab.package("tool", &[(&tool, &bytes)]);
    let mut e = lab.open();
    e.enroll_baseline(std::slice::from_ref(&lab.sys), &enroll("host", "operator", false), &Lab::scan_opts()).unwrap();
    let id = id_of(&e, &tool);
    assert_eq!(e.state_of(&id), Some(S::Admitted));

    // The object store is an unauthenticated cache. Whoever can delete from it must not be able to turn
    // "changed after it was trusted" into silence.
    fs::remove_dir_all(lab.paths().objects().join("epn")).unwrap();
    let mut evil = elf();
    evil[100] = 0x99;
    fs::write(&tool, &evil).unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    assert_eq!(e.state_of(&id), Some(S::Degraded), "the previously admitted identity must still be degraded");
    assert_eq!(e.status().posture, Posture::Degraded);
}

#[test]
fn revocation_targets_are_validated_and_put_in_the_form_the_matcher_compares() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    let exe = lab.file("opt/tool", &elf());
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    let id = id_of(&e, &exe);
    let hex = e.explain(&exe).unwrap().record.digest.hex();
    let epoch = e.status().revocations_epoch;

    // Malformed targets are refused outright and consume nothing.
    for bad in ["", "zz", &hex[..63], &format!("{hex}0"), "EPN-1-EXE-short", "epn", "sha256:"] {
        for kind in [RevocationKind::Digest, RevocationKind::Epn] {
            assert!(
                matches!(e.revoke(kind, bad, "x"), Err(EngineError::Invalid(_))),
                "{kind:?} {bad:?} must be refused"
            );
        }
    }
    assert!(e.revoke(RevocationKind::Signer, "bad\nsigner", "x").is_err());
    assert_eq!(e.status().revocations_epoch, epoch, "refused revocations must not be signed or counted");

    // Every natural spelling of the same digest works and is stored once, in the canonical form.
    let upper = hex.to_uppercase();
    assert_eq!(e.revoke(RevocationKind::Digest, &format!("SHA256:{upper}"), "stolen").unwrap(), 1);
    assert_eq!(e.state_of(&id), Some(S::Revoked));
    let stored: Vec<_> = e.revocations().entries.iter().map(|x| x.target.clone()).collect();
    assert_eq!(stored, vec![format!("sha256:{hex}")]);

    // EPN spelling: lower-case class and upper-case hex.
    let mut other = elf();
    other[90] = 7;
    let exe2 = lab.file("opt/tool2", &other);
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    let id2 = id_of(&e, &exe2);
    let sloppy = id2.to_string().to_lowercase();
    assert_eq!(e.revoke(RevocationKind::Epn, &sloppy, "stolen").unwrap(), 1);
    assert_eq!(e.state_of(&id2), Some(S::Revoked));
}

#[test]
fn the_policy_epoch_floor_ignores_prose_an_author_controls() {
    // The floor is read back from event details the engine wrote; text before the fixed fields must never count.
    let digest = "a".repeat(64);
    assert_eq!(crate::engine::parse_epoch(&format!("policy=x epoch=2 digest={digest}")), Some(2));
    assert_eq!(crate::engine::parse_epoch(&format!("policy=site epoch=900000 epoch=2 digest={digest}")), Some(2));
    assert_eq!(crate::engine::parse_epoch(&format!("policy=x epoch=0 epoch=7 digest={digest}")), Some(7));
    assert_eq!(crate::engine::parse_epoch("revocations epoch=4 added Digest sha256:00: reason epoch=99"), Some(4));
    assert_eq!(crate::engine::parse_epoch("epoch=5 without the fixed shape"), None);
    assert_eq!(crate::engine::parse_epoch(""), None);

    // And a policy cannot smuggle such a name in any more.
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    let mut hostile = jlr_policy::Policy::strict(2);
    hostile.name = "site-policy epoch=900000".into();
    assert!(matches!(e.set_policy(hostile), Err(EngineError::Invalid(_))));
    assert_eq!(e.policy().epoch, 1);
    e.set_policy(jlr_policy::Policy::strict(2)).unwrap();
}

#[test]
fn attacker_chosen_names_cannot_inject_control_characters_into_the_ledger() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let mut e = lab.open();
    let evil = "opt/x\n\u{1b}[2J\u{202e}forged: ALLOWED";
    let exe = lab.file(evil, &elf());
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    let v = e.decide_exec(fs::File::open(&exe).unwrap(), &exe).unwrap();
    e.record_exec(v.id.as_ref(), &exe.to_string_lossy(), "denied", &v.decision).unwrap();
    let bad = |c: char| c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    let evs = events(&lab);
    assert!(evs.iter().any(|x| x.detail.contains("forged")), "the event must still be recorded and identifiable");
    for ev in &evs {
        assert!(!ev.detail.chars().any(bad), "unsanitised detail in the ledger: {:?}", ev.detail);
    }
}

#[test]
fn run_detached_gives_the_ledger_back_while_the_workload_runs() {
    let lab = Lab::new();
    if !helper_available(&lab) {
        return;
    }
    lab.init(PolicyKind::Workstation);
    let sh = fs::canonicalize("/bin/sh").unwrap();
    let prog = lab.file("opt/sh", &fs::read(&sh).unwrap());
    // The workload cannot write to the host, so it signals by being alive: it sleeps, and we probe the lock.
    let (paths, cfg, prog2) = (lab.paths(), lab.cfg(), prog.clone());
    let worker = std::thread::spawn(move || {
        Engine::run_detached(
            paths,
            cfg,
            &prog2,
            &["-c".into(), "sleep 3".into()],
            &["PATH=/usr/bin:/bin".into()],
            &[],
            true,
        )
    });
    // Wait until the start has been logged (before the program runs), then require the lock to be free while the program sleeps.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut acquired = false;
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if events(&lab).iter().any(|x| x.detail.contains("starting")) && !worker.is_finished() {
            acquired = Engine::open_wait(lab.paths(), lab.cfg(), std::time::Duration::from_millis(500)).is_ok();
            break;
        }
        if worker.is_finished() {
            break;
        }
    }
    let result = worker.join().unwrap();
    match result {
        Err(EngineError::Cell(jlr_cell::CellError::Refused(_))) => return, // kernel cannot host cells here
        Err(e) => panic!("{e}"),
        Ok(_) => {}
    }
    assert!(acquired, "the exclusive ledger lock must not be held for the lifetime of the workload");
    assert!(events(&lab).iter().any(|x| x.detail.contains("exited with code 0")), "the end is recorded afterwards");
}

#[test]
fn a_withdrawn_approval_cannot_be_put_back_from_a_copy() {
    let lab = Lab::new();
    lab.init(PolicyKind::Strict);
    let exe = lab.file("opt/tool", &elf());
    let (id, old_copy);
    {
        let mut e = lab.open();
        e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
        id = id_of(&e, &exe);
        e.approve(&id.to_string(), CellClass::Cell2, NetworkMode::FullUserNetwork, vec![], 720 * 3600, "alice")
            .unwrap();
        assert_eq!(e.state_of(&id), Some(S::Admitted));
        // The operator keeps a copy of the broad grant, then narrows it (a shorter, smaller approval).
        let f = lab.paths().approvals().join(format!("{}.cose", id.digest.hex()));
        old_copy = fs::read(&f).unwrap();
        lab.clock.fetch_add(1, Ordering::SeqCst);
        e.approve(&id.to_string(), CellClass::Cell0, NetworkMode::None, vec![], 1, "alice").unwrap();
    }
    let f = lab.paths().approvals().join(format!("{}.cose", id.digest.hex()));
    let narrowed = fs::read(&f).unwrap();
    assert_ne!(old_copy, narrowed);

    // Someone puts the old, still-unexpired, correctly signed grant back over the file.
    fs::write(&f, &old_copy).unwrap();
    let e = lab.open();
    let d = e.explain(&exe).unwrap().decision;
    assert_ne!(
        (d.cell, d.network),
        (CellClass::Cell2, NetworkMode::FullUserNetwork),
        "a superseded approval came back to life: {d:?}"
    );
    let noted = |lab: &Lab| {
        events(lab)
            .iter()
            .filter(|x| x.kind == EventKind::Degraded && x.detail.contains("not the approval the ledger records"))
            .count()
    };
    assert_eq!(noted(&lab), 1, "the ignored file must be reported");
    drop(e);
    // ...and reported once, not once per start.
    drop(lab.open());
    drop(lab.open());
    assert_eq!(noted(&lab), 1, "the same problem must not be logged again on every open");

    // A copy stored under another name, sorting after the real file, cannot shadow the current approval.
    fs::write(&f, &narrowed).unwrap();
    fs::write(lab.paths().approvals().join("zzz-copy.cose"), &old_copy).unwrap();
    let e = lab.open();
    let d = e.explain(&exe).unwrap().decision;
    assert_ne!((d.cell, d.network), (CellClass::Cell2, NetworkMode::FullUserNetwork), "{d:?}");
}

#[test]
fn a_superseded_baseline_cannot_be_restored_from_a_copy() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let (a, b) = (elf(), {
        let mut o = elf();
        o[90] = 9;
        o
    });
    let tool_a = lab.file("usr/bin/a", &a);
    let tool_b = lab.file("usr/bin/b", &b);
    lab.package("both", &[(&tool_a, &a), (&tool_b, &b)]);
    let old_copy;
    {
        let mut e = lab.open();
        let (_, n) = e
            .enroll_baseline(std::slice::from_ref(&lab.sys), &enroll("host", "operator", false), &Lab::scan_opts())
            .unwrap();
        assert_eq!(n, 2);
        old_copy = fs::read(lab.paths().baselines().join("host.cose")).unwrap();
    }
    // The operator drops b (removes it, re-enrols the baseline under the same name), then someone restores the copy.
    fs::remove_file(&tool_b).unwrap();
    lab.clock.fetch_add(5, Ordering::SeqCst);
    {
        let mut e = lab.open();
        let (_, n) = e
            .enroll_baseline(std::slice::from_ref(&lab.sys), &enroll("host", "operator", false), &Lab::scan_opts())
            .unwrap();
        assert_eq!(n, 1, "only a remains");
    }
    let current = fs::read(lab.paths().baselines().join("host.cose")).unwrap();
    assert_ne!(current, old_copy);
    fs::write(lab.paths().baselines().join("host.cose"), &old_copy).unwrap();
    let e = lab.open();
    assert_eq!(e.status().baselines.iter().map(|(_, n)| *n).sum::<usize>(), 0, "the restored baseline must not count");
    assert!(
        events(&lab)
            .iter()
            .any(|x| x.kind == EventKind::Degraded && x.detail.contains("not the baseline the ledger records"))
    );
}

#[test]
fn losing_the_path_index_does_not_hide_that_a_trusted_file_was_replaced() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let bytes = elf();
    let tool = lab.file("usr/bin/tool", &bytes);
    lab.package("tool", &[(&tool, &bytes)]);
    let id;
    {
        let mut e = lab.open();
        e.enroll_baseline(std::slice::from_ref(&lab.sys), &enroll("host", "operator", false), &Lab::scan_opts())
            .unwrap();
        id = id_of(&e, &tool);
        assert_eq!(e.state_of(&id), Some(S::Admitted));
    }
    // The index is an unauthenticated cache: whoever can delete it must not thereby erase what was trusted where.
    fs::remove_file(lab.paths().index()).unwrap();
    let mut evil = elf();
    evil[100] = 0x77;
    fs::write(&tool, &evil).unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();

    let mut e = lab.open();
    assert!(
        events(&lab).iter().any(|x| x.kind == EventKind::Degraded && x.detail.contains("path index was missing")),
        "the loss must be recorded"
    );
    let r = e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    assert_eq!(r.degraded.len(), 1, "the replaced file must still be noticed: {r:?}");
    assert_eq!(e.state_of(&id), Some(S::Degraded));
    assert_eq!(e.status().posture, Posture::Degraded);
    drop(e);

    // A damaged index is a loss too, and it is reported once, not on every start afterwards.
    fs::write(lab.paths().index(), b"\xff\xfe not cbor").unwrap();
    drop(lab.open());
    drop(lab.open());
    let n = events(&lab).iter().filter(|x| x.detail.contains("path index was missing")).count();
    assert_eq!(n, 2, "one event for each of the two losses, none for the reopen");
}

#[test]
fn a_fresh_installation_without_an_index_is_not_a_loss() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    drop(lab.open());
    assert!(!events(&lab).iter().any(|x| x.detail.contains("path index was missing")));
}

#[test]
fn a_truncated_object_is_rewritten_the_next_time_the_artifact_is_seen() {
    let lab = Lab::new();
    lab.init(PolicyKind::Workstation);
    let exe = lab.file("opt/tool", &elf());
    let mut e = lab.open();
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    let id = id_of(&e, &exe);
    let hex = id.digest.hex();
    let obj = lab.paths().objects().join("epn").join(&hex[..2]).join(format!("{}.cbor", &hex[2..]));
    let good = fs::read(&obj).unwrap();
    fs::write(&obj, &good[..good.len() / 2]).unwrap(); // what a crash before the data reached the disk leaves
    assert!(e.explain(&exe).is_ok());
    e.scan(std::slice::from_ref(&lab.sys), &Lab::scan_opts()).unwrap();
    assert_eq!(fs::read(&obj).unwrap(), good, "an object with the wrong length must be written again");
}
