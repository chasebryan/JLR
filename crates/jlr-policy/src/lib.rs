//! The JLR trust engine.
//!
//! [`evaluate`] is a pure function: the same policy, artifact, evidence,
//! revocations, approval and clock reading always yield the same
//! [`Decision`] (invariant I-17). It performs no I/O, holds no state, and
//! never turns missing evidence into positive trust (I-01, I-06, I-11).
//!
//! Precedence, highest first:
//!
//! 1. revocation (I-14)
//! 2. changed content of a previously trusted artifact (I-08)
//! 3. policy prohibitions: forbidden behavior, prohibited classes
//! 4. invalid signatures
//! 5. the first matching tier
//! 6. an operator approval, which may raise a quarantined or observed
//!    artifact but can never lift a revocation or a prohibition (I-13)

#![forbid(unsafe_code)]

mod approval;
mod baseline;
mod defaults;
mod engine;
mod policy;
mod revocation;

pub use approval::{Approval, ApprovalError, VerifiedApproval};
pub use baseline::{Baseline, VerifiedBaseline};
pub use engine::{Facts, evaluate};
pub use policy::{Policy, PolicyError, Tier};
pub use revocation::{RevocationEntry, RevocationKind, Revocations};

#[cfg(test)]
mod tests;
