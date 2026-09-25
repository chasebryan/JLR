//! Admission states, system posture and assurance labels.

use crate::artifact::coded_enum;
use std::fmt;

coded_enum! {
    /// Trust state of one artifact.
    pub enum AdmissionState: u8 {
        /// Not yet classified, or evidence is insufficient.
        Unknown = 1 => "UNKNOWN",
        /// Present but denied normal execution.
        Quarantined = 2 => "QUARANTINED",
        /// May run only inside a high-restriction observation cell.
        Observed = 3 => "OBSERVED",
        /// Identity and required evidence match policy.
        Verified = 4 => "VERIFIED",
        /// Explicitly permitted for a defined capability set.
        Admitted = 5 => "ADMITTED",
        /// Previously admitted, but a measurement no longer matches.
        Degraded = 6 => "DEGRADED",
        /// Explicitly denied by current policy.
        Revoked = 7 => "REVOKED",
        /// Evidence satisfies a prohibition in the active policy.
        PolicyBlocked = 8 => "POLICY_BLOCKED",
    }
}

/// A refused state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionError {
    /// State the artifact is in.
    pub from: AdmissionState,
    /// State that was requested.
    pub to: AdmissionState,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transition {} -> {} is not permitted", self.from, self.to)
    }
}
impl std::error::Error for TransitionError {}

impl AdmissionState {
    /// Whether the transition is one the state machine permits at all.
    ///
    /// Permission here is necessary but not sufficient: promotion into
    /// `Verified` or `Admitted` additionally needs a recorded decision and
    /// evidence (invariant I-01), enforced by the engine.
    pub fn can_become(self, to: AdmissionState) -> bool {
        use AdmissionState::*;
        if self == to {
            return true;
        }
        match (self, to) {
            // Revocation is reachable from everywhere except itself (handled above).
            (_, Revoked) => true,
            (Unknown, Quarantined) => true,
            (Unknown, Observed | Verified | PolicyBlocked) => true,
            (Quarantined, Observed | Verified | PolicyBlocked) => true,
            (Observed, Verified | Quarantined | PolicyBlocked) => true,
            (Verified, Admitted | Degraded | Quarantined | PolicyBlocked) => true,
            (Admitted, Degraded | Quarantined | PolicyBlocked) => true,
            (Degraded, Quarantined | Verified | Observed | PolicyBlocked) => true,
            (PolicyBlocked, Quarantined) => true,
            // Revoked is terminal until a later signed record supersedes it,
            // which creates a new decision rather than a transition.
            _ => false,
        }
    }

    /// Checks a transition.
    pub fn transition(self, to: AdmissionState) -> Result<AdmissionState, TransitionError> {
        if self.can_become(to) { Ok(to) } else { Err(TransitionError { from: self, to }) }
    }

    /// Whether the state grants any execution outside an observation cell.
    pub fn permits_normal_execution(self) -> bool {
        matches!(self, AdmissionState::Verified | AdmissionState::Admitted)
    }

    /// Whether moving from `self` to `to` grants more authority.
    pub fn is_promotion_to(self, to: AdmissionState) -> bool {
        to.permits_normal_execution() && !self.permits_normal_execution()
    }
}

coded_enum! {
    /// Trust posture of a scope. `Proven` is always relative to a named scope
    /// and never means "free of malware".
    pub enum Posture: u8 {
        /// Boot checks or evidence are pending, missing, stale or contradictory.
        Degraded = 1 => "DEGRADED",
        /// Required evidence for the named scope is fresh and consistent.
        Proven = 2 => "PROVEN",
        /// Policy has fenced the scope.
        Isolated = 3 => "ISOLATED",
        /// The independent recovery image is active.
        Recovery = 4 => "RECOVERY",
    }
}

coded_enum! {
    /// How much a report can honestly claim, from the boundary it runs behind.
    pub enum Assurance: u8 {
        /// Evidence comes only from an emulator or test harness.
        Prototype = 1 => "prototype",
        /// JLR runs beside the host on the host kernel; host root can subvert it.
        Companion = 2 => "companion",
        /// JLR boots first from verified media and governs the host as a workload.
        Supervisor = 3 => "supervisor",
        /// Separately booted rescue environment.
        Recovery = 4 => "recovery",
    }
}
