use super::*;
use jlr_cbor::Cbor;
use jlr_crypto::{Digest, Role, SigningKeypair, TrustAnchors};
use jlr_model::{
    AdmissionState as S, ArtifactClass, Basis, Capability, CellClass, EpnRecord, EvidenceItem, EvidenceKind as E,
    NetworkMode, ProvenanceRank as P, ReasonCode, Source,
};
use proptest::prelude::*;

const NOW: u64 = 1_800_000_000;

fn artifact(class: ArtifactClass, prov: P, name: &str) -> EpnRecord {
    EpnRecord {
        schema: 1,
        class,
        name: name.into(),
        version: None,
        size: 10,
        digest: Digest::of(name.as_bytes()),
        provenance: prov,
        signer: Some("vendor-a".into()),
        source: Source { channel: "test".into(), origin: None, path: None },
        dependencies: vec![],
    }
}

fn ev(kinds: &[E]) -> Vec<EvidenceItem> {
    kinds
        .iter()
        .map(|k| EvidenceItem { kind: *k, source: "test".into(), at: NOW, detail: String::new(), digest: None })
        .collect()
}

struct Case {
    policy: Policy,
    revocations: Revocations,
}

impl Case {
    fn new() -> Self {
        Case { policy: Policy::workstation(1), revocations: Revocations::empty() }
    }

    fn run(&self, a: &EpnRecord, kinds: &[E], requested: &[Capability], prior: Option<S>) -> jlr_model::Decision {
        let evidence = ev(kinds);
        evaluate(
            &self.policy,
            &Facts {
                artifact: a,
                evidence: &evidence,
                requested,
                prior,
                revocations: &self.revocations,
                approval: None,
            },
            NOW,
        )
    }
}

#[test]
fn built_in_policies_validate() {
    Policy::workstation(1).validate().unwrap();
    Policy::strict(1).validate().unwrap();
    assert_ne!(Policy::workstation(1).digest(), Policy::strict(1).digest());
    assert_ne!(Policy::workstation(1).digest(), Policy::workstation(2).digest());
}

#[test]
fn policy_roundtrips_canonically() {
    let p = Policy::workstation(7);
    assert_eq!(Policy::from_cbor(&p.to_cbor()).unwrap(), p);
}

#[test]
fn validation_rejects_unsafe_policies() {
    let base = Policy::workstation(1);
    let mut cases: Vec<(&str, Policy)> = Vec::new();

    let mut p = base.clone();
    p.tiers.clear();
    cases.push(("no tiers", p));

    let mut p = base.clone();
    p.epoch = 0;
    cases.push(("epoch zero", p));

    let mut p = base.clone();
    p.tiers.pop(); // last tier is no longer a catch-all
    cases.push(("no catch-all", p));

    let mut p = base.clone();
    let last = p.tiers.len() - 1;
    p.tiers[last].state = S::Admitted; // unknown software admitted silently
    p.tiers[last].cell = CellClass::Cell2;
    cases.push(("catch-all admits everything", p));

    let mut p = base.clone();
    p.tiers[1].require_evidence.clear(); // admits on nothing
    cases.push(("admit without evidence", p));

    let mut p = base.clone();
    p.tiers[1].max_provenance = P::SourceKnown; // admits on weak provenance
    cases.push(("admit on weak provenance", p));

    let mut p = base.clone();
    p.tiers[1].name = p.tiers[0].name.clone();
    cases.push(("duplicate names", p));

    let mut p = base.clone();
    p.tiers[1].cell = CellClass::Cell3;
    p.tiers[1].require_evidence = vec![E::ManagedInstaller]; // cell-3 without package signature or human
    cases.push(("cell-3 without strong basis", p));

    let mut p = base.clone();
    let last = p.tiers.len() - 1;
    p.tiers[last].network = N::FullUserNetwork;
    cases.push(("observed with network", p));

    let mut p = base.clone();
    p.tiers[1].cell = CellClass::CellR;
    cases.push(("CELL-R in tier", p));

    let mut p = base.clone();
    p.max_manual_cell = CellClass::CellR;
    cases.push(("manual cell-R", p));

    let mut p = base;
    p.schema = 9;
    cases.push(("bad schema", p));

    for (name, p) in cases {
        assert!(p.validate().is_err(), "policy with {name} must be rejected");
    }
}
use jlr_model::NetworkMode as N;

#[test]
fn managed_package_is_admitted_silently() {
    let d = Case::new().run(
        &artifact(ArtifactClass::Exe, P::DistroSigned, "ls"),
        &[E::ManagedInstaller, E::PackageSignature, E::ContentDigestMatch],
        &[],
        None,
    );
    assert_eq!(d.state, S::Admitted);
    assert_eq!(d.cell, CellClass::Cell2);
    assert_eq!(d.basis, Basis::Cryptographic);
    assert_eq!(d.needs_user, None);
    assert_eq!(d.reasons, vec![ReasonCode::ManagedInstall]);
}

#[test]
fn boot_artifacts_need_a_verified_package_transaction() {
    let c = Case::new();
    let k = artifact(ArtifactClass::Kernel, P::DistroSigned, "vmlinuz");
    let d = c.run(&k, &[E::ManagedInstaller, E::PackageSignature], &[], None);
    assert_eq!((d.state, d.cell), (S::Admitted, CellClass::Cell3));
    // The same kernel without the package signature falls through to observation, not admission.
    let d = c.run(&k, &[E::ManagedInstaller], &[], None);
    assert_eq!(d.state, S::Observed);
    assert!(!d.state.permits_normal_execution());
}

#[test]
fn unknown_software_is_observed_in_a_bare_cell() {
    let d = Case::new().run(&artifact(ArtifactClass::Exe, P::Unknown, "dropper"), &[], &[], None);
    assert_eq!((d.state, d.cell, d.network), (S::Observed, CellClass::Cell0, NetworkMode::None));
    assert_eq!(d.reasons, vec![ReasonCode::DefaultTier]);
    assert!(d.capabilities.is_empty());
}

#[test]
fn strict_policy_quarantines_unknown_and_asks() {
    let mut c = Case::new();
    c.policy = Policy::strict(1);
    let d = c.run(&artifact(ArtifactClass::Exe, P::Unknown, "x"), &[], &[], None);
    assert_eq!(d.state, S::Quarantined);
    assert!(d.needs_user.is_some());
}

#[test]
fn checksum_verified_gets_a_restricted_cell() {
    let d = Case::new().run(
        &artifact(ArtifactClass::Exe, P::VerifiedChecksum, "tool"),
        &[E::ContentDigestMatch],
        &[],
        None,
    );
    assert_eq!((d.state, d.cell, d.network), (S::Verified, CellClass::Cell1, NetworkMode::LoopbackOnly));
}

#[test]
fn missing_evidence_never_promotes() {
    // Good provenance recorded on the artifact, but none of the required evidence is present now.
    let d = Case::new().run(&artifact(ArtifactClass::Exe, P::DistroSigned, "ls"), &[], &[], Some(S::Admitted));
    assert!(!d.state.permits_normal_execution(), "{:?}", d);
}

#[test]
fn revocation_by_digest_signer_and_epn_wins() {
    let a = artifact(ArtifactClass::Exe, P::DistroSigned, "ls");
    let all_good = [E::ManagedInstaller, E::PackageSignature, E::SignatureValid];
    for entry in [
        RevocationEntry { kind: RevocationKind::Digest, target: a.digest.to_string(), reason: "cve".into() },
        RevocationEntry { kind: RevocationKind::Signer, target: "vendor-a".into(), reason: "stolen key".into() },
        RevocationEntry { kind: RevocationKind::Epn, target: a.id().to_string(), reason: "bad".into() },
    ] {
        let mut c = Case::new();
        c.revocations.entries.push(entry);
        let d = c.run(&a, &all_good, &[], Some(S::Admitted));
        assert_eq!(d.state, S::Revoked);
        assert_eq!(d.reasons, vec![ReasonCode::Revoked]);
    }
    // An unrelated revocation changes nothing.
    let mut c = Case::new();
    c.revocations.entries.push(RevocationEntry {
        kind: RevocationKind::Signer,
        target: "someone-else".into(),
        reason: String::new(),
    });
    assert_eq!(c.run(&a, &all_good, &[], None).state, S::Admitted);
}

#[test]
fn previously_revoked_stays_revoked() {
    let d = Case::new().run(
        &artifact(ArtifactClass::Exe, P::DistroSigned, "ls"),
        &[E::ManagedInstaller, E::PackageSignature],
        &[],
        Some(S::Revoked),
    );
    assert_eq!((d.state, d.reasons), (S::Revoked, vec![ReasonCode::PreviouslyRevoked]));
}

#[test]
fn changed_content_degrades_trusted_and_quarantines_others() {
    let c = Case::new();
    let a = artifact(ArtifactClass::Exe, P::DistroSigned, "ls");
    let ev = [E::ContentDigestMismatch, E::ManagedInstaller, E::PackageSignature];
    assert_eq!(c.run(&a, &ev, &[], Some(S::Admitted)).state, S::Degraded);
    assert_eq!(c.run(&a, &ev, &[], Some(S::Verified)).state, S::Degraded);
    assert_eq!(c.run(&a, &ev, &[], Some(S::Observed)).state, S::Quarantined);
    assert_eq!(c.run(&a, &ev, &[], None).state, S::Quarantined);
    assert_eq!(c.run(&a, &ev, &[], Some(S::Admitted)).reasons, vec![ReasonCode::ContentChanged]);
}

#[test]
fn forbidden_behavior_and_blocked_classes_are_policy_blocked() {
    let a = artifact(ArtifactClass::Exe, P::DistroSigned, "ls");
    let d =
        Case::new().run(&a, &[E::ForbiddenBehavior, E::ManagedInstaller, E::PackageSignature], &[], Some(S::Admitted));
    assert_eq!(d.state, S::PolicyBlocked);

    let mut c = Case::new();
    c.policy.block_classes.push(ArtifactClass::Module);
    let m = artifact(ArtifactClass::Module, P::DistroSigned, "evil.ko");
    assert_eq!(c.run(&m, &[E::ManagedInstaller, E::PackageSignature], &[], None).state, S::PolicyBlocked);
}

#[test]
fn invalid_signature_quarantines_even_with_managed_install() {
    let d = Case::new().run(
        &artifact(ArtifactClass::Exe, P::DistroSigned, "ls"),
        &[E::SignatureInvalid, E::ManagedInstaller, E::PackageSignature],
        &[],
        None,
    );
    assert_eq!(d.state, S::Quarantined);
    assert!(d.reasons.contains(&ReasonCode::BadSignature));
}

#[test]
fn setuid_needs_strong_provenance() {
    let c = Case::new();
    let good = artifact(ArtifactClass::Exe, P::DistroSigned, "sudo");
    let d = c.run(&good, &[E::SetuidBit, E::ManagedInstaller, E::PackageSignature], &[], None);
    assert_eq!(d.state, S::Admitted);
    let weak = artifact(ArtifactClass::Exe, P::VerifiedChecksum, "sudo2");
    let d = c.run(&weak, &[E::SetuidBit, E::ContentDigestMatch], &[], None);
    assert_eq!((d.state, d.cell), (S::Quarantined, CellClass::Cell0));
    assert!(d.reasons.contains(&ReasonCode::SetuidExecutable));
    assert!(d.needs_user.is_some());
}

#[test]
fn writable_location_caps_cell_and_network() {
    let a = artifact(ArtifactClass::Exe, P::DistroSigned, "app");
    let d = Case::new().run(&a, &[E::WritablePath, E::ManagedInstaller, E::PackageSignature], &[], None);
    assert_eq!(d.state, S::Admitted);
    assert_eq!(d.cell, CellClass::Cell1);
    assert_eq!(d.network, NetworkMode::DestinationAllowlist);
    assert!(d.reasons.contains(&ReasonCode::WritableLocation) && d.reasons.contains(&ReasonCode::CellCapped));
}

#[test]
fn high_risk_capabilities_are_withheld_and_ask_a_human() {
    let a = artifact(ArtifactClass::Exe, P::DistroSigned, "tool");
    let req =
        [Capability::parse("FS_READ:/home/u/Documents").unwrap(), Capability::KernelModuleLoad, Capability::DevAudio];
    let d = Case::new().run(&a, &[E::ManagedInstaller, E::PackageSignature], &req, None);
    assert_eq!(d.state, S::Admitted);
    assert!(d.capabilities.contains(&Capability::DevAudio));
    assert!(!d.capabilities.contains(&Capability::KernelModuleLoad));
    assert!(d.reasons.contains(&ReasonCode::HighRiskCapability));
    assert!(d.needs_user.is_some());
}

#[test]
fn unadmitted_artifacts_receive_no_capabilities() {
    let a = artifact(ArtifactClass::Exe, P::Unknown, "x");
    let d = Case::new().run(&a, &[], &[Capability::DevAudio, Capability::DevGpu], None);
    assert!(d.capabilities.is_empty());
}

// ---- approvals ----

fn operator() -> (SigningKeypair, TrustAnchors) {
    let k = SigningKeypair::from_seed([5; 32], Role::Policy);
    let mut a = TrustAnchors::new();
    a.insert(k.public());
    (k, a)
}

fn approval_for(a: &EpnRecord, cell: CellClass, caps: Vec<Capability>, expires: u64) -> Approval {
    Approval {
        epn: a.id().to_string(),
        cell,
        network: NetworkMode::FullUserNetwork,
        capabilities: caps,
        expires_at: expires,
        granted_by: "operator".into(),
    }
}

fn run_with(
    c: &Case,
    a: &EpnRecord,
    kinds: &[E],
    ap: Option<&VerifiedApproval>,
    prior: Option<S>,
) -> jlr_model::Decision {
    let evidence = ev(kinds);
    evaluate(
        &c.policy,
        &Facts { artifact: a, evidence: &evidence, requested: &[], prior, revocations: &c.revocations, approval: ap },
        NOW,
    )
}

#[test]
fn approval_raises_unknown_software_and_is_recorded_as_override() {
    let (key, anchors) = operator();
    let a = artifact(ArtifactClass::Exe, P::Unknown, "tool");
    let ap = approval_for(&a, CellClass::Cell1, vec![Capability::DevAudio], NOW + 60);
    let verified = Approval::verify(&ap.sign("node", &key), "node", &anchors).unwrap();
    let d = run_with(&Case::new(), &a, &[], Some(&verified), None);
    assert_eq!(d.state, S::Admitted);
    assert_eq!(d.basis, Basis::ManualOverride, "an approval must never look like automatic verification");
    assert_eq!(d.cell, CellClass::Cell1);
    assert_eq!(d.network, NetworkMode::DestinationAllowlist, "network is capped to what the cell allows");
    assert_eq!(d.capabilities, vec![Capability::DevAudio]);
    assert!(d.reasons.contains(&ReasonCode::OperatorAuthorized));
    assert!(d.reasons.contains(&ReasonCode::DefaultTier), "the weakness that was overridden stays on the record");
}

#[test]
fn approval_is_capped_by_policy_and_expires() {
    let (key, anchors) = operator();
    let a = artifact(ArtifactClass::Exe, P::Unknown, "tool");
    let ap = approval_for(&a, CellClass::Cell3, vec![], NOW + 60);
    let verified = Approval::verify(&ap.sign("node", &key), "node", &anchors).unwrap();
    let c = Case::new();
    let d = run_with(&c, &a, &[], Some(&verified), None);
    assert_eq!(d.cell, CellClass::Cell2, "workstation policy caps manual grants at CELL-2");
    assert!(d.reasons.contains(&ReasonCode::CellCapped));

    let mut later = c.policy.clone();
    later.epoch = 2;
    let evidence = ev(&[]);
    let d = evaluate(
        &later,
        &Facts {
            artifact: &a,
            evidence: &evidence,
            requested: &[],
            prior: None,
            revocations: &c.revocations,
            approval: Some(&verified),
        },
        NOW + 61,
    );
    assert_eq!(d.state, S::Observed, "an expired approval grants nothing");
}

#[test]
fn approval_never_lifts_revocation_or_prohibition() {
    let (key, anchors) = operator();
    let a = artifact(ArtifactClass::Exe, P::Unknown, "tool");
    let ap = approval_for(&a, CellClass::Cell1, vec![], NOW + 60);
    let verified = Approval::verify(&ap.sign("node", &key), "node", &anchors).unwrap();

    let mut c = Case::new();
    c.revocations.entries.push(RevocationEntry {
        kind: RevocationKind::Digest,
        target: a.digest.to_string(),
        reason: String::new(),
    });
    assert_eq!(run_with(&c, &a, &[], Some(&verified), None).state, S::Revoked);
    assert_eq!(run_with(&Case::new(), &a, &[E::ForbiddenBehavior], Some(&verified), None).state, S::PolicyBlocked);
    assert_eq!(run_with(&Case::new(), &a, &[], Some(&verified), Some(S::Revoked)).state, S::Revoked);
}

#[test]
fn approval_for_another_artifact_is_ignored() {
    let (key, anchors) = operator();
    let a = artifact(ArtifactClass::Exe, P::Unknown, "tool");
    let other = artifact(ArtifactClass::Exe, P::Unknown, "other");
    let ap = approval_for(&other, CellClass::Cell1, vec![], NOW + 60);
    let verified = Approval::verify(&ap.sign("node", &key), "node", &anchors).unwrap();
    assert_eq!(run_with(&Case::new(), &a, &[], Some(&verified), None).state, S::Observed);
}

#[test]
fn approval_signature_scope_and_role_are_enforced() {
    let (key, anchors) = operator();
    let a = artifact(ArtifactClass::Exe, P::Unknown, "tool");
    let bytes = approval_for(&a, CellClass::Cell1, vec![], NOW + 60).sign("node-a", &key);
    assert!(Approval::verify(&bytes, "node-a", &anchors).is_ok());
    assert!(Approval::verify(&bytes, "node-b", &anchors).is_err(), "approval must not be replayable on another node");
    // A device key (used by the machine itself) must not be able to approve software.
    let device = SigningKeypair::from_seed([6; 32], Role::Device);
    let mut da = TrustAnchors::new();
    da.insert(device.public());
    let forged = approval_for(&a, CellClass::Cell1, vec![], NOW + 60).sign("node-a", &device);
    assert!(Approval::verify(&forged, "node-a", &da).is_err());
}

// ---- properties ----

fn arb_kinds() -> impl Strategy<Value = Vec<E>> {
    prop::collection::vec(
        prop::sample::select(vec![
            E::ContentDigestMatch,
            E::ContentDigestMismatch,
            E::SignatureValid,
            E::SignatureInvalid,
            E::ManagedInstaller,
            E::PackageSignature,
            E::ReproducibleMatch,
            E::SetuidBit,
            E::WritablePath,
            E::StaticFinding,
            E::Observation,
            E::OperatorApproval,
            E::RevocationHit,
            E::Missing,
            E::ForbiddenBehavior,
        ]),
        0..8,
    )
}

fn arb_prior() -> impl Strategy<Value = Option<S>> {
    prop::option::of(prop::sample::select(S::ALL.to_vec()))
}

fn arb_prov() -> impl Strategy<Value = P> {
    prop::sample::select(P::ALL.to_vec())
}

fn arb_class() -> impl Strategy<Value = ArtifactClass> {
    prop::sample::select(ArtifactClass::ALL.to_vec())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn evaluation_is_deterministic_and_order_independent(
        class in arb_class(), prov in arb_prov(), kinds in arb_kinds(), prior in arb_prior(), strict in any::<bool>()
    ) {
        let mut c = Case::new();
        if strict { c.policy = Policy::strict(1); }
        let a = artifact(class, prov, "p");
        let d1 = c.run(&a, &kinds, &[], prior);
        let d2 = c.run(&a, &kinds, &[], prior);
        prop_assert_eq!(&d1, &d2);
        let mut rev = kinds.clone();
        rev.reverse();
        prop_assert_eq!(&d1, &c.run(&a, &rev, &[], prior));
    }

    #[test]
    fn revocation_dominates_everything(class in arb_class(), prov in arb_prov(), kinds in arb_kinds(), prior in arb_prior()) {
        let a = artifact(class, prov, "p");
        let mut c = Case::new();
        c.revocations.entries.push(RevocationEntry { kind: RevocationKind::Digest, target: a.digest.to_string(), reason: String::new() });
        prop_assert_eq!(c.run(&a, &kinds, &[], prior).state, S::Revoked);
    }

    #[test]
    fn no_promotion_without_matching_evidence(
        class in arb_class(), prov in arb_prov(), kinds in arb_kinds(), prior in arb_prior(), strict in any::<bool>()
    ) {
        let mut c = Case::new();
        if strict { c.policy = Policy::strict(1); }
        let a = artifact(class, prov, "p");
        let d = c.run(&a, &kinds, &[], prior);
        if d.state.permits_normal_execution() {
            // Some tier that yields this state must be fully satisfied by the evidence.
            let satisfied = c.policy.tiers.iter().any(|t| {
                t.state == d.state
                    && (t.classes.is_empty() || t.classes.contains(&class))
                    && prov.satisfies(t.max_provenance)
                    && t.require_evidence.iter().all(|k| kinds.contains(k))
            });
            prop_assert!(satisfied, "state {:?} without a satisfied tier", d.state);
            prop_assert!(!kinds.contains(&E::ForbiddenBehavior));
            prop_assert!(!kinds.contains(&E::SignatureInvalid));
            prop_assert!(!kinds.contains(&E::ContentDigestMismatch));
            prop_assert!(!kinds.contains(&E::RevocationHit));
            prop_assert_ne!(prior, Some(S::Revoked));
        }
    }

    #[test]
    fn decisions_are_always_internally_consistent(
        class in arb_class(), prov in arb_prov(), kinds in arb_kinds(), prior in arb_prior(),
        caps in prop::collection::vec(prop::sample::select(vec![
            Capability::DevAudio, Capability::DevGpu, Capability::KernelModuleLoad, Capability::RawNetwork,
        ]), 0..4),
    ) {
        let c = Case::new();
        let a = artifact(class, prov, "p");
        let d = c.run(&a, &kinds, &caps, prior);
        // Non-running states have no authority at all.
        if !d.state.permits_normal_execution() {
            prop_assert!(d.capabilities.is_empty());
            prop_assert_eq!(d.cell, CellClass::Cell0, "state {:?}", d.state);
            prop_assert_eq!(d.network, NetworkMode::None);
        }
        // High-risk capabilities are never granted without an approval.
        prop_assert!(d.capabilities.iter().all(|x| !x.is_high_risk()));
        // Cell-0 has no network.
        if d.cell == CellClass::Cell0 { prop_assert_eq!(d.network, NetworkMode::None); }
        prop_assert!(!d.reasons.is_empty());
        prop_assert_eq!(d.policy, c.policy.digest());
    }
}

#[test]
fn baseline_members_get_manual_override_approvals() {
    let (key, anchors) = operator();
    let member = artifact(ArtifactClass::Exe, P::SourceKnown, "coreutils-ls");
    let outsider = artifact(ArtifactClass::Exe, P::SourceKnown, "dropper");
    let mut b = Baseline {
        schema: 1,
        name: "initial-host".into(),
        cell: CellClass::Cell2,
        network: NetworkMode::FullUserNetwork,
        capabilities: vec![],
        granted_by: "operator".into(),
        expires_at: NOW + 3600,
        members: vec![member.id().digest],
    };
    b.normalize();
    let verified = Baseline::verify(&b.sign("node", &key), "node", &anchors).unwrap();
    assert!(verified.contains(&member.id()));
    assert!(!verified.contains(&outsider.id()));

    let c = Case::new();
    let ap = verified.approval_for(&member.id(), NOW).unwrap();
    let d = run_with(&c, &member, &[], Some(&ap), None);
    assert_eq!((d.state, d.cell), (S::Admitted, CellClass::Cell2));
    assert_eq!(d.basis, Basis::ManualOverride, "a baseline is authority, not proof");
    assert!(verified.approval_for(&outsider.id(), NOW).is_none());
    assert!(verified.approval_for(&member.id(), NOW + 3600).is_none(), "expired baseline grants nothing");

    // Baseline membership does not survive a revocation or a content change.
    let mut c2 = Case::new();
    c2.revocations.entries.push(RevocationEntry {
        kind: RevocationKind::Digest,
        target: member.digest.to_string(),
        reason: String::new(),
    });
    assert_eq!(run_with(&c2, &member, &[], Some(&ap), None).state, S::Revoked);
    assert_eq!(run_with(&c, &member, &[E::ContentDigestMismatch], Some(&ap), Some(S::Admitted)).state, S::Degraded);
}

#[test]
fn baseline_rejects_unsorted_members_and_wrong_signers() {
    let (key, anchors) = operator();
    let a = artifact(ArtifactClass::Exe, P::SourceKnown, "a").id().digest;
    let b = artifact(ArtifactClass::Exe, P::SourceKnown, "b").id().digest;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let mk = |members: Vec<Digest>| Baseline {
        schema: 1,
        name: "x".into(),
        cell: CellClass::Cell1,
        network: NetworkMode::None,
        capabilities: vec![],
        granted_by: "op".into(),
        expires_at: NOW,
        members,
    };
    assert!(Baseline::verify(&mk(vec![lo, hi]).sign("n", &key), "n", &anchors).is_ok());
    assert!(Baseline::verify(&mk(vec![hi, lo]).sign("n", &key), "n", &anchors).is_err());
    assert!(Baseline::verify(&mk(vec![lo, lo]).sign("n", &key), "n", &anchors).is_err());
    let device = SigningKeypair::from_seed([6; 32], Role::Device);
    let mut da = TrustAnchors::new();
    da.insert(device.public());
    assert!(Baseline::verify(&mk(vec![lo]).sign("n", &device), "n", &da).is_err());
}
