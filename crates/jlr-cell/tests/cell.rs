#![allow(clippy::unwrap_used)]
//! Integration tests that launch real cells and check that confinement holds.
//!
//! They use the host's own `sh` and `bash` as workloads. Where the kernel does
//! not permit unprivileged namespaces the tests skip themselves loudly instead
//! of passing silently.

use jlr_cell::{CellError, CellSpec, Control, Outcome, SealedExe, Status, Stdio3, launch};
use jlr_measure::open_measured;
use jlr_model::{AdmissionState, Basis, Capability, CellClass, Decision, NetworkMode, ReasonCode};
use std::fs;
use std::path::{Path, PathBuf};

const HELPER: &str = env!("CARGO_BIN_EXE_jlr-cell-init");

fn decision(cell: CellClass, net: NetworkMode, caps: Vec<Capability>, state: AdmissionState) -> Decision {
    Decision {
        state,
        cell,
        network: net,
        capabilities: caps,
        reasons: vec![ReasonCode::DefaultTier],
        basis: Basis::None,
        needs_user: None,
        policy: jlr_crypto::Digest::ZERO,
    }
}

fn spec_for(d: &Decision, argv: &[&str]) -> CellSpec {
    CellSpec::from_decision(
        d,
        argv.iter().map(|s| (*s).to_owned()).collect(),
        vec!["PATH=/usr/bin:/bin".into(), "HOME=/tmp".into(), "LC_ALL=C".into()],
    )
    .unwrap()
}

fn seal(path: &str) -> SealedExe {
    // The measurement layer refuses a final symlink by design, so resolve to the real binary.
    let real = fs::canonicalize(path).unwrap();
    let (mut f, m) = open_measured(&real, 1 << 30).unwrap();
    SealedExe::seal(&mut f, &m.digest, 1 << 30).unwrap()
}

/// Runs a shell command in a cell; returns None (after a loud notice) when the
/// kernel forbids unprivileged namespaces.
fn run_sh(d: &Decision, script: &str) -> Option<(Outcome, String, String)> {
    run_prog("/bin/sh", d, &["sh", "-c", script])
}

fn run_prog(path: &str, d: &Decision, argv: &[&str]) -> Option<(Outcome, String, String)> {
    let exe = seal(path);
    let spec = spec_for(d, argv);
    match launch(Path::new(HELPER), &exe, &spec, Stdio3::captured()) {
        Ok(running) => {
            let (o, out, err) = running.wait_with_output().unwrap();
            Some((o, String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned()))
        }
        Err(CellError::Refused(r))
            if r.unavailable.iter().any(|u| u.starts_with("mount-ns") || u.starts_with("user-ns")) =>
        {
            eprintln!("SKIPPED: this kernel does not allow unprivileged namespaces: {:?}", r.unavailable);
            None
        }
        Err(e) => panic!("launch failed: {e}"),
    }
}

fn cell0() -> Decision {
    decision(CellClass::Cell0, NetworkMode::None, vec![], AdmissionState::Observed)
}

#[test]
fn program_runs_and_exit_code_propagates() {
    let Some((o, out, _)) = run_sh(&cell0(), "echo hello; exit 7") else { return };
    assert_eq!(o.code, 7);
    assert_eq!(out.trim(), "hello");
    assert_ne!(o.report.status, Status::Refused);
    for c in ["mount-ns", "pid-ns", "net-ns", "no-new-privs", "cap-drop", "seccomp"] {
        assert!(o.report.active.iter().any(|a| a == c), "{c} must be active: {:?}", o.report);
    }
    assert!(o.report.mandatory_missing.is_empty());
}

#[test]
fn report_accounts_for_every_requested_control() {
    let Some((o, _, _)) = run_sh(&cell0(), "true") else { return };
    let r = &o.report;
    assert!(!r.kernel.is_empty());
    for c in &r.requested {
        let active = r.active.contains(c);
        let listed = r.unavailable.iter().any(|u| u.starts_with(&format!("{c}:")));
        assert!(active || listed, "control {c} is neither active nor reported unavailable: {r:?}");
    }
    assert_eq!(r.status == Status::Full, r.requested.iter().all(|c| r.active.contains(c)));
    assert!(r.seccomp_denied > 30);
}

#[test]
fn host_files_are_invisible() {
    let marker = tempfile::Builder::new().prefix("jlr-secret-").tempdir_in(std::env::var("HOME").unwrap()).unwrap();
    fs::write(marker.path().join("secret"), "top secret").unwrap();
    let script = format!(
        "ls / | tr '\\n' ' '; echo; test -e {} && echo LEAK || echo hidden; test -e /home && echo HOME || echo nohome; \
         cat /etc/shadow 2>&1 | head -1; cat /root/x 2>&1 | head -1",
        marker.path().join("secret").display()
    );
    let Some((o, out, _)) = run_sh(&cell0(), &script) else { return };
    assert_eq!(o.code, 0, "{out}");
    assert!(out.contains("hidden") && !out.contains("LEAK"), "{out}");
    assert!(out.contains("nohome"), "{out}");
    assert!(!out.contains("root:"), "shadow must not be readable: {out}");
    let root_listing = out.lines().next().unwrap();
    for allowed in root_listing.split_whitespace() {
        assert!(
            ["bin", "dev", "etc", "lib", "lib32", "lib64", "libx32", "proc", "run", "sbin", "tmp", "usr"]
                .contains(&allowed),
            "unexpected entry {allowed:?} in the private root: {root_listing}"
        );
    }
}

#[test]
fn filesystem_is_read_only_except_scratch_and_nothing_persists() {
    let host_tmp_probe: PathBuf = std::env::temp_dir().join(format!("jlr-probe-{}", std::process::id()));
    let script = format!(
        "echo x > /tmp/scratch && echo tmp-ok; (echo y > /usr/evil) 2>/dev/null && echo USR-WRITABLE || echo usr-ro; \
         (echo z > /etc/evil) 2>/dev/null && echo ETC-WRITABLE || echo etc-ro; (echo w > /evil) 2>/dev/null && echo ROOT-WRITABLE || echo root-ro; \
         echo p > {}; true",
        host_tmp_probe.display()
    );
    let Some((_, out, _)) = run_sh(&cell0(), &script) else { return };
    assert!(
        out.contains("tmp-ok") && out.contains("usr-ro") && out.contains("etc-ro") && out.contains("root-ro"),
        "{out}"
    );
    assert!(!host_tmp_probe.exists(), "a write inside the cell reached the host filesystem");
}

#[test]
fn network_is_unreachable_even_on_host_loopback() {
    // A listener on the host's loopback must not be reachable from a NONE-network cell.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port} && echo CONNECTED || echo blocked");
    let Some((_, out, _)) = run_prog("/bin/bash", &cell0(), &["bash", "-c", &script]) else { return };
    assert!(out.contains("blocked") && !out.contains("CONNECTED"), "{out}");
    listener.set_nonblocking(true).unwrap();
    assert!(listener.accept().is_err(), "the cell must not have reached the host listener");
}

#[test]
fn loopback_only_cell_reaches_its_own_loopback_but_not_the_hosts() {
    let host = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = host.local_addr().unwrap().port();
    let d = decision(CellClass::Cell1, NetworkMode::LoopbackOnly, vec![], AdmissionState::Verified);
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port} && echo REACHED-HOST || echo not-host");
    let Some((o, out, _)) = run_prog("/bin/bash", &d, &["bash", "-c", &script]) else { return };
    assert!(out.contains("not-host"), "{out}");
    assert!(o.report.active.iter().any(|a| a == "net-ns"));
}

#[test]
fn dangerous_syscalls_are_denied() {
    // unshare(1) calls unshare(2); the seccomp filter must answer EPERM.
    let Some((_, out, err)) = run_sh(&cell0(), "unshare -U true 2>&1; echo status=$?") else { return };
    assert!(!out.contains("status=0"), "unshare succeeded inside a cell: {out} {err}");
    // chroot is denied too.
    let Some((_, out, _)) = run_sh(&cell0(), "chroot / true 2>&1; echo status=$?") else { return };
    assert!(!out.contains("status=0"), "{out}");
}

#[test]
fn privileges_are_dropped() {
    let Some((_, out, _)) = run_sh(&cell0(), "grep -E '^(NoNewPrivs|CapEff|CapPrm|CapBnd|CapAmb):' /proc/self/status")
    else {
        return;
    };
    assert!(out.contains("NoNewPrivs:\t1"), "{out}");
    for cap in ["CapEff", "CapPrm", "CapBnd", "CapAmb"] {
        assert!(out.contains(&format!("{cap}:\t0000000000000000")), "{cap} not empty: {out}");
    }
}

#[test]
fn pid_namespace_hides_host_processes() {
    let Some((_, out, _)) = run_sh(&cell0(), "echo pid=$$; ls /proc | grep -c '^[0-9]'") else { return };
    assert!(out.contains("pid=1"), "the workload should be PID 1 of its namespace: {out}");
    let visible: u32 = out.lines().last().unwrap().trim().parse().unwrap();
    assert!(visible < 10, "too many processes visible ({visible}): the PID namespace is not isolating");
}

#[test]
fn environment_comes_only_from_the_spec() {
    // SAFETY-free: set a variable in the test process; it must not leak into the cell.
    let Some((_, out, _)) = run_sh(&cell0(), "env | sort | tr '\\n' ' '") else { return };
    assert!(!out.contains("CARGO"), "{out}");
    assert!(out.contains("HOME=/tmp") && out.contains("LC_ALL=C"), "{out}");
}

#[test]
fn executed_bytes_are_the_measured_bytes_even_if_the_file_is_replaced_or_edited() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("prog");
    fs::write(&script, "#!/bin/sh\necho ORIGINAL\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let (mut f, m) = open_measured(&script, 1 << 20).unwrap();
    let sealed = SealedExe::seal(&mut f, &m.digest, 1 << 20).unwrap();
    assert!(sealed.is_fully_sealed());

    // The attacker replaces the file, and also edits the original inode in place.
    fs::write(&script, "#!/bin/sh\necho EVIL\n").unwrap();
    fs::remove_file(&script).unwrap();
    fs::write(&script, "#!/bin/sh\necho EVIL2\n").unwrap();

    let spec = spec_for(&cell0(), &["prog"]);
    match launch(Path::new(HELPER), &sealed, &spec, Stdio3::captured()) {
        Ok(running) => {
            let (o, out, err) = running.wait_with_output().unwrap();
            assert_eq!(String::from_utf8_lossy(&out).trim(), "ORIGINAL", "stderr: {}", String::from_utf8_lossy(&err));
            assert_eq!(o.code, 0);
        }
        Err(CellError::Refused(r))
            if r.unavailable.iter().any(|u| u.starts_with("mount-ns") || u.starts_with("user-ns")) =>
        {
            eprintln!("SKIPPED: unprivileged namespaces unavailable");
        }
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn sealing_refuses_content_that_changed_after_measurement() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("prog");
    fs::write(&p, "#!/bin/sh\ntrue\n").unwrap();
    let (mut f, m) = open_measured(&p, 1 << 20).unwrap();
    // In-place modification of the very inode that was measured.
    fs::write(&p, "#!/bin/sh\nfalse\n").unwrap();
    match SealedExe::seal(&mut f, &m.digest, 1 << 20) {
        Err(jlr_cell::SealError::DigestMismatch { .. }) => {}
        other => panic!("expected a digest mismatch, got {other:?}"),
    }
}

#[test]
fn sealed_memfd_cannot_be_written() {
    let sealed = seal("/bin/true");
    use std::io::Write;
    let mut f = sealed.file().try_clone().unwrap();
    assert!(f.write_all(b"x").is_err(), "sealed memfd accepted a write");
    assert!(sealed.file().set_len(1).is_err(), "sealed memfd accepted a resize");
}

#[test]
fn missing_mandatory_control_refuses_and_runs_nothing() {
    let marker = std::env::temp_dir().join(format!("jlr-must-not-exist-{}", std::process::id()));
    let _ = fs::remove_file(&marker);
    let d = decision(CellClass::Cell2, NetworkMode::FullUserNetwork, vec![], AdmissionState::Admitted);
    let mut spec = spec_for(&d, &["sh", "-c", &format!("touch {}", marker.display())]);
    // NetNs is impossible for a full-network cell, so it can never be active.
    spec.mandatory.push(Control::NetNs.as_str().to_owned());
    let exe = seal("/bin/sh");
    match launch(Path::new(HELPER), &exe, &spec, Stdio3::captured()) {
        Err(CellError::Refused(r)) => {
            assert_eq!(r.status, Status::Refused);
            assert!(r.mandatory_missing.iter().any(|m| m == "net-ns"), "{r:?}");
        }
        Err(CellError::Setup(_)) | Err(CellError::Io(_)) => {}
        Ok(_) => panic!("a cell with a missing mandatory control was started"),
        Err(e) => panic!("{e}"),
    }
    assert!(!marker.exists(), "the workload ran despite a missing mandatory control");
}

#[test]
fn wall_clock_limit_kills_the_cell() {
    let mut spec = spec_for(&cell0(), &["sh", "-c", "sleep 30"]);
    spec.wall_secs = Some(1);
    let exe = seal("/bin/sh");
    let started = std::time::Instant::now();
    match launch(Path::new(HELPER), &exe, &spec, Stdio3::captured()) {
        Ok(running) => {
            let (o, _, _) = running.wait_with_output().unwrap();
            assert_eq!(o.code, 137);
            assert!(started.elapsed().as_secs() < 10);
        }
        Err(CellError::Refused(_)) => eprintln!("SKIPPED: namespaces unavailable"),
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn filesystem_capabilities_bind_exact_paths() {
    let dir = tempfile::Builder::new().prefix("jlr-cap-").tempdir_in(std::env::var("HOME").unwrap()).unwrap();
    let ro = dir.path().join("ro");
    let rw = dir.path().join("rw");
    let other = dir.path().join("other");
    for d in [&ro, &rw, &other] {
        fs::create_dir(d).unwrap();
        fs::write(d.join("f"), "data").unwrap();
    }
    let caps = vec![
        Capability::parse(&format!("FS_READ:{}", ro.display())).unwrap(),
        Capability::parse(&format!("FS_WRITE:{}", rw.display())).unwrap(),
    ];
    let d = decision(CellClass::Cell1, NetworkMode::None, caps, AdmissionState::Verified);
    let script = format!(
        "cat {ro}/f; (echo x > {ro}/g) 2>/dev/null && echo RO-WRITABLE || echo ro-ok; echo new > {rw}/g && echo rw-ok; \
         test -e {other}/f && echo OTHER-VISIBLE || echo other-hidden",
        ro = ro.display(),
        rw = rw.display(),
        other = other.display()
    );
    let Some((_, out, err)) = run_sh(&d, &script) else { return };
    assert!(
        out.contains("data") && out.contains("ro-ok") && out.contains("rw-ok") && out.contains("other-hidden"),
        "{out} {err}"
    );
    assert!(!out.contains("OTHER-VISIBLE") && !out.contains("RO-WRITABLE"));
    assert_eq!(
        fs::read_to_string(rw.join("g")).unwrap().trim(),
        "new",
        "writes to a granted path must persist on the host"
    );
    assert!(!ro.join("g").exists());
}

#[test]
fn decision_to_spec_is_pure_and_refuses_states_that_may_not_run() {
    let d = cell0();
    assert_eq!(
        CellSpec::from_decision(&d, vec!["a".into()], vec![]).unwrap(),
        CellSpec::from_decision(&d, vec!["a".into()], vec![]).unwrap()
    );
    for s in [
        AdmissionState::Unknown,
        AdmissionState::Quarantined,
        AdmissionState::Degraded,
        AdmissionState::Revoked,
        AdmissionState::PolicyBlocked,
    ] {
        let bad = decision(CellClass::Cell0, NetworkMode::None, vec![], s);
        assert!(matches!(CellSpec::from_decision(&bad, vec![], vec![]), Err(CellError::NotRunnable(_))), "{s}");
    }
    let privileged = decision(CellClass::Cell3, NetworkMode::None, vec![], AdmissionState::Admitted);
    assert!(matches!(CellSpec::from_decision(&privileged, vec![], vec![]), Err(CellError::Unsupported(_))));
    let proxy = decision(CellClass::Cell2, NetworkMode::MediatedProxy, vec![], AdmissionState::Admitted);
    assert!(matches!(CellSpec::from_decision(&proxy, vec![], vec![]), Err(CellError::Unsupported(_))));
    let observed_big = decision(CellClass::Cell2, NetworkMode::None, vec![], AdmissionState::Observed);
    assert!(CellSpec::from_decision(&observed_big, vec![], vec![]).is_err());

    let s = CellSpec::from_decision(&d, vec!["x".into()], vec![]).unwrap();
    let m = s.mandatory_controls();
    for c in [Control::MountNs, Control::PidNs, Control::NoNewPrivs, Control::CapDrop, Control::Seccomp, Control::NetNs]
    {
        assert!(m.contains(&c), "CELL-0 without network must require {c}");
    }
    // Round trip through the helper's wire format.
    use jlr_cbor::Cbor;
    assert_eq!(CellSpec::from_cbor(&s.to_cbor()).unwrap(), s);
}
