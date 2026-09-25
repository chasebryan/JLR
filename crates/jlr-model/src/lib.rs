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

/// Whether a character must not reach a terminal or a log line as itself: control characters (including the C1
/// range), line and paragraph separators, and the format and invisible characters that let one string read as
/// another (bidirectional overrides, zero-width characters, tag characters, variation selectors, fillers).
fn is_hostile(c: char) -> bool {
    c.is_control()
        || matches!(
            c as u32,
            0x00AD
                | 0x034F
                | 0x0600..=0x0605
                | 0x061C
                | 0x06DD
                | 0x070F
                | 0x08E2
                | 0x115F
                | 0x1160
                | 0x17B4
                | 0x17B5
                | 0x180B..=0x180F
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x206F
                | 0x2800
                | 0x3164
                | 0xFE00..=0xFE0F
                | 0xFEFF
                | 0xFFA0
                | 0xFFF9..=0xFFFC
                | 0x110BD
                | 0x1D173..=0x1D17A
                | 0xE0000..=0xE0FFF
        )
}

/// Makes untrusted text safe to store in an event and to print on a terminal, at most 1024 bytes of it.
///
/// See [`sanitize_to`].
pub fn sanitize(s: &str) -> String {
    sanitize_to(s, 1024)
}

/// Makes untrusted text safe to store in an event and to print on a terminal, keeping at most `limit` bytes.
///
/// File names, paths and error strings come from whoever controls the file system. Left raw they can carry
/// newlines (forging ledger rows in `jlr ledger log`), terminal escape sequences, and Unicode bidirectional,
/// zero-width or separator characters that make one string read as another. Every such character is written as
/// a `\u{..}` escape and overlong text is truncated, so the result is one line of visible text.
///
/// The function is **idempotent**: applying it to its own output changes nothing. That is why a backslash is left
/// as it is. Text passes through several layers (an operator's reason, the event that records it, the command that
/// prints the event), and escaping backslashes would double them at every layer. The cost is that a name which
/// literally contains the text `\u{1b}` reads the same as one containing an escape character, which harms nothing.
///
/// Use this on each attacker-influenced *part* of a message before composing it, so that truncation never removes
/// the fixed fields that follow it.
pub fn sanitize_to(s: &str, limit: usize) -> String {
    use std::fmt::Write as _;
    const MARKER: &str = "\u{2026}[truncated]";
    // Text that is already safe (no hostile character) and short enough, including this function's own output
    // (which is at most `limit` bytes of safe text plus the marker), is returned as it is. That is what makes the
    // function idempotent, whatever the limit falls in the middle of.
    if s.len() <= limit + MARKER.len() && !s.chars().any(is_hostile) {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len().min(limit + MARKER.len()));
    let mut escape = String::new();
    let mut buf = [0u8; 4];
    for c in s.chars() {
        escape.clear();
        let piece: &str = if is_hostile(c) {
            let _ = write!(escape, "\\u{{{:x}}}", c as u32);
            &escape
        } else {
            c.encode_utf8(&mut buf)
        };
        // A character or an escape is written whole or not at all, so the limit never cuts one in half.
        if out.len() + piece.len() > limit {
            out.push_str(MARKER);
            break;
        }
        out.push_str(piece);
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
