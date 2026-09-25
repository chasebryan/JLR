//! Built-in policies.

use crate::policy::{Policy, Tier};
use jlr_model::{
    AdmissionState as S, ArtifactClass as C, CellClass, EvidenceKind as E, NetworkMode as N, ProvenanceRank as P,
    ReasonCode as R,
};

#[allow(clippy::too_many_arguments)]
fn tier(
    name: &str,
    classes: &[C],
    max_provenance: P,
    require_evidence: &[E],
    state: S,
    cell: CellClass,
    network: N,
    needs_user: bool,
    reason: R,
) -> Tier {
    Tier {
        name: name.into(),
        classes: classes.to_vec(),
        max_provenance,
        require_evidence: require_evidence.to_vec(),
        state,
        cell,
        network,
        needs_user,
        reason,
    }
}

fn evidence_tiers() -> Vec<Tier> {
    vec![
        tier(
            "managed-boot",
            &[C::Boot, C::Kernel, C::Initrd, C::Module, C::Firmware],
            P::DistroSigned,
            &[E::ManagedInstaller, E::PackageSignature],
            S::Admitted,
            CellClass::Cell3,
            N::None,
            false,
            R::ManagedInstall,
        ),
        tier(
            "managed-package",
            &[],
            P::DistroSigned,
            &[E::ManagedInstaller, E::PackageSignature],
            S::Admitted,
            CellClass::Cell2,
            N::FullUserNetwork,
            false,
            R::ManagedInstall,
        ),
        tier(
            "pinned-vendor",
            &[],
            P::PinnedVendor,
            &[E::SignatureValid],
            S::Admitted,
            CellClass::Cell2,
            N::FullUserNetwork,
            false,
            R::PinnedVendorSignature,
        ),
        tier(
            "reproduced",
            &[],
            P::Reproduced,
            &[E::ReproducibleMatch],
            S::Admitted,
            CellClass::Cell2,
            N::FullUserNetwork,
            false,
            R::ReproducedBuild,
        ),
    ]
}

impl Policy {
    /// The default policy for an ordinary workstation.
    ///
    /// Software that arrives through a signed package transaction or carries a
    /// pinned vendor signature is admitted silently. Everything else runs, if
    /// it runs at all, in an isolated observation cell with no network, and
    /// stays there until a human decides.
    pub fn workstation(epoch: u64) -> Policy {
        let mut tiers = evidence_tiers();
        tiers.push(tier(
            "checksum-verified",
            &[],
            P::VerifiedChecksum,
            &[E::ContentDigestMatch],
            S::Verified,
            CellClass::Cell1,
            N::LoopbackOnly,
            false,
            R::ChecksumVerified,
        ));
        tiers.push(tier(
            "observe-unknown",
            &[],
            P::Unknown,
            &[],
            S::Observed,
            CellClass::Cell0,
            N::None,
            false,
            R::DefaultTier,
        ));
        Policy {
            schema: Policy::SCHEMA,
            name: "workstation".into(),
            epoch,
            tiers,
            block_classes: vec![],
            setuid_min_provenance: P::DistroSigned,
            writable_path_max_cell: CellClass::Cell1,
            max_manual_cell: CellClass::Cell2,
            evidence_max_age_secs: 7 * 24 * 3600,
            enforce_exec: false,
        }
    }

    /// A stricter policy: anything without strong evidence is quarantined and
    /// asks for a human decision instead of running in an observation cell.
    pub fn strict(epoch: u64) -> Policy {
        let mut tiers = evidence_tiers();
        tiers.push(tier(
            "quarantine-unknown",
            &[],
            P::Unknown,
            &[],
            S::Quarantined,
            CellClass::Cell0,
            N::None,
            true,
            R::DefaultTier,
        ));
        Policy {
            schema: Policy::SCHEMA,
            name: "strict".into(),
            epoch,
            tiers,
            block_classes: vec![],
            setuid_min_provenance: P::PinnedVendor,
            writable_path_max_cell: CellClass::Cell0,
            max_manual_cell: CellClass::Cell1,
            evidence_max_age_secs: 24 * 3600,
            enforce_exec: false,
        }
    }
}
