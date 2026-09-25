//! The evidence-ledger event schema.

use crate::artifact::coded_enum;
use crate::state::AdmissionState;
use jlr_cbor::record;
use jlr_crypto::Digest;

coded_enum! {
    /// On what basis a state was reached. Overrides are never disguised as
    /// automatic verification (invariant I-13).
    pub enum Basis: u8 {
        /// Cryptographic evidence satisfied policy.
        Cryptographic = 1 => "CRYPTOGRAPHIC",
        /// Policy rules were satisfied without a cryptographic anchor.
        Policy = 2 => "POLICY",
        /// A human authorized despite incomplete evidence.
        ManualOverride = 3 => "MANUAL_OVERRIDE",
        /// No positive basis; a restrictive or neutral outcome.
        None = 4 => "NONE",
    }
}

coded_enum! {
    /// What kind of security-relevant action an event records.
    pub enum EventKind: u8 {
        /// The ledger was created.
        Genesis = 1 => "GENESIS",
        /// A boot completed its checks.
        Boot = 2 => "BOOT",
        /// A component measured itself or the base image.
        SelfMeasure = 3 => "SELF_MEASURE",
        /// A new artifact was discovered.
        Discover = 4 => "DISCOVER",
        /// An artifact changed state.
        Transition = 5 => "TRANSITION",
        /// A measurement did not match its expected value.
        Mismatch = 6 => "MISMATCH",
        /// An operator override was recorded.
        Override = 7 => "OVERRIDE",
        /// A cell started, ended or violated its profile.
        Enforcement = 8 => "ENFORCEMENT",
        /// Policy was loaded, replaced or rejected.
        PolicyLoad = 9 => "POLICY_LOAD",
        /// Key enrolment, rotation or revocation.
        KeyEvent = 10 => "KEY_EVENT",
        /// A ledger checkpoint was written.
        Checkpoint = 11 => "CHECKPOINT",
        /// A recovery action was previewed or executed.
        Recovery = 12 => "RECOVERY",
        /// Missing enforcement or another degraded condition was recorded.
        Degraded = 13 => "DEGRADED",
        /// A revocation was applied.
        Revocation = 14 => "REVOCATION",
    }
}

record! {
    /// One entry of the append-only evidence ledger.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Event {
        /// Position in the ledger, starting at 0.
        1 => seq: u64,
        /// Random identifier of the boot that produced the event.
        2 => boot_id: [u8; 16],
        /// Wall clock seconds since the Unix epoch (advisory only).
        3 => wall_time: u64,
        /// Nanoseconds of monotonic time since boot.
        4 => mono_ns: u64,
        /// Component or operator identity that caused the event.
        5 => actor: String,
        /// EPN identifier of the subject when there is one.
        6 => subject: Option<String>,
        /// Kind of event.
        7 => kind: EventKind,
        /// State before, for transitions.
        8 => old_state: Option<AdmissionState>,
        /// State after, for transitions.
        9 => new_state: Option<AdmissionState>,
        /// Digest of the policy in force.
        10 => policy: Digest,
        /// Digests of the evidence records this event rests on.
        11 => evidence: Vec<Digest>,
        /// Basis of the decision.
        12 => basis: Basis,
        /// Short human-readable detail.
        13 => detail: String,
        /// Envelope digest of the previous event, or zero for the first.
        14 => prev: Digest,
    }
}
