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

/// Makes untrusted text safe to store in an event and to print on a terminal.
///
/// File names, paths and error strings come from whoever controls the file system. Left raw they can
/// carry newlines (forging ledger rows in `jlr ledger log`), terminal escape sequences, and Unicode
/// bidirectional or zero-width controls that make one string read as another. Backslashes, control
/// characters and those format characters are written as `\\` and `\u{..}` escapes, and overlong text is
/// truncated, so the result is one line of visible text.
pub fn sanitize(s: &str) -> String {
    use std::fmt::Write as _;
    const LIMIT: usize = 1024;
    let mut out = String::with_capacity(s.len().min(LIMIT + 16));
    for c in s.chars() {
        if out.len() >= LIMIT {
            out.push_str("\u{2026}[truncated]");
            break;
        }
        let format_control = matches!(c as u32, 0x00AD | 0x061C | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB);
        if c == '\\' {
            out.push_str("\\\\");
        } else if c.is_control() || format_control {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

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
