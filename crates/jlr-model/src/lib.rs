//! The JLR domain model.
//!
//! Two orthogonal state machines are used and never conflated:
//!
//! * [`AdmissionState`] is the trust state of one artifact (identified by an
//!   [`EpnRecord`]).
//! * [`Posture`] is the trust state of a whole scope such as the boot chain or
//!   a governed host, always reported together with an [`Assurance`] label.
//!
//! An EPN (Encryption Protocol Number) is a **content-addressed identity**: its
//! identifier is derived from the SHA-256 of the canonical immutable record, so
//! anyone can recompute and check it. Mutable facts (state, approvals,
//! revocations) never live in the record; they are events in the evidence
//! ledger that reference the EPN.

#![forbid(unsafe_code)]

mod artifact;
mod capability;
mod decision;
mod event;
mod state;

pub use artifact::{ArtifactClass, EpnId, EpnRecord, ProvenanceRank, Source};
pub use capability::{Capability, CapabilityError, CellClass, NetworkMode};
pub use decision::{Decision, EvidenceItem, EvidenceKind, ReasonCode};
pub use event::{Basis, Event, EventKind};
pub use state::{AdmissionState, Assurance, Posture, TransitionError};

/// Record-type names used in envelope headers and signing scope.
pub mod record_type {
    use jlr_crypto::Role;

    /// Immutable artifact identity record.
    pub const EPN: &str = "epn";
    /// Signed policy bundle.
    pub const POLICY: &str = "policy";
    /// Signed list of revocations.
    pub const REVOCATIONS: &str = "revocations";
    /// Signed release manifest.
    pub const RELEASE: &str = "release-manifest";
    /// Signed evidence event.
    pub const EVENT: &str = "event";
    /// Signed ledger checkpoint.
    pub const CHECKPOINT: &str = "checkpoint";
    /// Signed recovery authorization.
    pub const RECOVERY: &str = "recovery-authorization";
    /// Signed operator approval.
    pub const APPROVAL: &str = "approval";

    /// Roles allowed to sign a given record type.
    pub fn allowed_signers(record_type: &str) -> &'static [Role] {
        match record_type {
            EPN => &[Role::Device, Role::Release],
            POLICY => &[Role::Policy],
            REVOCATIONS => &[Role::Root, Role::Policy, Role::Release],
            RELEASE => &[Role::Release],
            EVENT | CHECKPOINT => &[Role::Device],
            RECOVERY => &[Role::Recovery],
            APPROVAL => &[Role::Policy, Role::Recovery],
            _ => &[],
        }
    }
}

#[cfg(test)]
mod tests;
