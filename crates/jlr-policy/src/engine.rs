//! The deterministic decision function.

use crate::approval::VerifiedApproval;
use crate::policy::{Policy, Tier};
use crate::revocation::Revocations;
use jlr_model::{
    AdmissionState, Basis, Capability, CellClass, Decision, EpnRecord, EvidenceItem, EvidenceKind, NetworkMode,
    ReasonCode,
};

/// Everything the engine may look at. Nothing else influences a decision.
#[derive(Clone, Copy, Debug)]
pub struct Facts<'a> {
    /// Immutable identity of the artifact.
    pub artifact: &'a EpnRecord,
    /// Normalized evidence collected for it.
    pub evidence: &'a [EvidenceItem],
    /// Capabilities the artifact asks for.
    pub requested: &'a [Capability],
    /// State recorded in the ledger before this evaluation.
    pub prior: Option<AdmissionState>,
    /// Active revocations.
    pub revocations: &'a Revocations,
    /// A verified operator approval, if one was presented.
    pub approval: Option<&'a VerifiedApproval>,
}

fn network_rank(n: NetworkMode) -> u8 {
    n as u8
}

/// Reduces a network mode to what a cell may hold.
fn cap_network(cell: CellClass, net: NetworkMode) -> NetworkMode {
    match cell {
        CellClass::Cell0 => NetworkMode::None,
        CellClass::Cell1 if network_rank(net) > network_rank(NetworkMode::DestinationAllowlist) => {
            NetworkMode::DestinationAllowlist
        }
        _ => net,
    }
}

#[allow(clippy::too_many_arguments)]
fn finish(
    policy_digest: jlr_crypto::Digest,
    state: AdmissionState,
    cell: CellClass,
    network: NetworkMode,
    mut caps: Vec<Capability>,
    mut reasons: Vec<ReasonCode>,
    basis: Basis,
    needs_user: Option<String>,
) -> Decision {
    caps.sort();
    caps.dedup();
    reasons.sort();
    reasons.dedup();
    Decision { state, cell, network, capabilities: caps, reasons, basis, needs_user, policy: policy_digest }
}

fn tier_matches(t: &Tier, f: &Facts<'_>, has: &dyn Fn(EvidenceKind) -> bool) -> bool {
    (t.classes.is_empty() || t.classes.contains(&f.artifact.class))
        && f.artifact.provenance.satisfies(t.max_provenance)
        && t.require_evidence.iter().all(|k| has(*k))
}

fn tier_basis(t: &Tier) -> Basis {
    let cryptographic = [EvidenceKind::SignatureValid, EvidenceKind::PackageSignature, EvidenceKind::ReproducibleMatch];
    if t.require_evidence.iter().any(|k| cryptographic.contains(k)) {
        Basis::Cryptographic
    } else if t.state.permits_normal_execution() {
        Basis::Policy
    } else {
        Basis::None
    }
}

/// Evaluates one artifact under one policy.
///
/// `now` is seconds since the Unix epoch and is used only to expire
/// approvals. The caller has already validated `policy`.
pub fn evaluate(policy: &Policy, f: &Facts<'_>, now: u64) -> Decision {
    let pd = policy.digest();
    let has = |k: EvidenceKind| f.evidence.iter().any(|e| e.kind == k);
    let id = f.artifact.id();

    // 1. Revocation wins over everything, including stale admission and approvals (I-14).
    if f.revocations.hit(f.artifact).is_some() || has(EvidenceKind::RevocationHit) {
        return finish(
            pd,
            AdmissionState::Revoked,
            CellClass::Cell0,
            NetworkMode::None,
            vec![],
            vec![ReasonCode::Revoked],
            Basis::Policy,
            None,
        );
    }
    if f.prior == Some(AdmissionState::Revoked) {
        // Revoked is terminal until a later signed record supersedes it.
        return finish(
            pd,
            AdmissionState::Revoked,
            CellClass::Cell0,
            NetworkMode::None,
            vec![],
            vec![ReasonCode::PreviouslyRevoked],
            Basis::Policy,
            None,
        );
    }

    // 2. Changed content of something that was trusted must leave that state (I-08).
    if has(EvidenceKind::ContentDigestMismatch) {
        let state = match f.prior {
            Some(AdmissionState::Verified | AdmissionState::Admitted) => AdmissionState::Degraded,
            _ => AdmissionState::Quarantined,
        };
        return finish(
            pd,
            state,
            CellClass::Cell0,
            NetworkMode::None,
            vec![],
            vec![ReasonCode::ContentChanged],
            Basis::None,
            None,
        );
    }

    // 3. Prohibitions cannot be overridden by an approval.
    if has(EvidenceKind::ForbiddenBehavior) || policy.block_classes.contains(&f.artifact.class) {
        return finish(
            pd,
            AdmissionState::PolicyBlocked,
            CellClass::Cell0,
            NetworkMode::None,
            vec![],
            vec![ReasonCode::PolicyProhibition],
            Basis::Policy,
            None,
        );
    }

    // 4-5. Base decision from the first matching tier, then guards.
    let mut reasons: Vec<ReasonCode> = Vec::new();
    let (mut state, mut cell, mut network, mut needs_user, mut basis) = if has(EvidenceKind::SignatureInvalid) {
        reasons.push(ReasonCode::BadSignature);
        (
            AdmissionState::Quarantined,
            CellClass::Cell0,
            NetworkMode::None,
            Some("signature did not verify".to_owned()),
            Basis::None,
        )
    } else {
        // The validated policy ends with a catch-all tier, so a match always exists.
        let tier = policy.tiers.iter().find(|t| tier_matches(t, f, &has)).unwrap_or_else(|| {
            #[allow(clippy::expect_used)]
            policy.tiers.last().expect("validated policy has tiers")
        });
        reasons.push(tier.reason);
        let question = tier.needs_user.then(|| format!("Allow {} ({})?", f.artifact.name, tier.name));
        (tier.state, tier.cell, tier.network, question, tier_basis(tier))
    };

    if has(EvidenceKind::SetuidBit) && !f.artifact.provenance.satisfies(policy.setuid_min_provenance) {
        state = AdmissionState::Quarantined;
        cell = CellClass::Cell0;
        network = NetworkMode::None;
        basis = Basis::None;
        needs_user = Some(format!("{} is setuid and its origin is not trusted enough", f.artifact.name));
        reasons.push(ReasonCode::SetuidExecutable);
    }
    if has(EvidenceKind::WritablePath) && cell > policy.writable_path_max_cell {
        cell = policy.writable_path_max_cell;
        network = cap_network(cell, network);
        reasons.push(ReasonCode::WritableLocation);
        reasons.push(ReasonCode::CellCapped);
    }

    // Capabilities: only artifacts that run normally receive any, and never in CELL-0.
    let mut caps: Vec<Capability> = Vec::new();
    if state.permits_normal_execution() && cell > CellClass::Cell0 {
        for c in f.requested {
            if c.is_high_risk() {
                reasons.push(ReasonCode::HighRiskCapability);
                needs_user.get_or_insert_with(|| format!("{} requests {c}", f.artifact.name));
            } else {
                caps.push(c.clone());
            }
        }
    }

    // 6. An operator approval raises the artifact within the policy's manual ceiling (I-13).
    if let Some(a) = f.approval.filter(|a| a.applies_to(&id, now)) {
        let a = a.get();
        let was_running = state.permits_normal_execution();
        state = AdmissionState::Admitted;
        cell = a.cell.min(policy.max_manual_cell);
        if a.cell > policy.max_manual_cell {
            reasons.push(ReasonCode::CellCapped);
        }
        network = cap_network(cell, a.network);
        caps = if cell > CellClass::Cell0 { a.capabilities.clone() } else { Vec::new() };
        if !was_running {
            basis = Basis::ManualOverride;
        }
        needs_user = None;
        reasons.push(ReasonCode::OperatorAuthorized);
    }

    finish(pd, state, cell, network, caps, reasons, basis, needs_user)
}
