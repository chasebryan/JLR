//! Policy records and their validation.

use jlr_cbor::{Cbor, record};
use jlr_crypto::Digest;
use jlr_model::{AdmissionState, ArtifactClass, CellClass, EvidenceKind, NetworkMode, ProvenanceRank, ReasonCode};
use std::fmt;

record! {
    /// One rule of the tier list. The first tier whose conditions hold decides.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Tier {
        /// Tier name, unique within a policy.
        1 => name: String,
        /// Classes the tier applies to; empty means every class.
        2 => classes: Vec<ArtifactClass>,
        /// The artifact's provenance must be at least this strong.
        3 => max_provenance: ProvenanceRank,
        /// Every listed kind of evidence must be present.
        4 => require_evidence: Vec<EvidenceKind>,
        /// State assigned when the tier matches.
        5 => state: AdmissionState,
        /// Cell the artifact must run in.
        6 => cell: CellClass,
        /// Network policy for that cell.
        7 => network: NetworkMode,
        /// Whether a human must answer a question before the artifact improves.
        8 => needs_user: bool,
        /// Reason recorded when the tier matches.
        9 => reason: ReasonCode,
    }
}

record! {
    /// A complete, signed-and-versioned trust policy.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Policy {
        /// Schema version, currently 1.
        1 => schema: u32,
        /// Human-readable policy name.
        2 => name: String,
        /// Monotonic policy epoch; a verifier refuses to go backwards.
        3 => epoch: u64,
        /// Ordered tiers; the last must match everything.
        4 => tiers: Vec<Tier>,
        /// Classes that policy prohibits outright.
        5 => block_classes: Vec<ArtifactClass>,
        /// Setuid and setgid artifacts need at least this provenance.
        6 => setuid_min_provenance: ProvenanceRank,
        /// Cell ceiling for artifacts found in less-trusted writable paths.
        7 => writable_path_max_cell: CellClass,
        /// Most permissive cell an operator approval may assign.
        8 => max_manual_cell: CellClass,
        /// Seconds after which evidence is stale and must be re-collected.
        9 => evidence_max_age_secs: u64,
        /// Whether the exec gate denies artifacts that may not run normally.
        /// When false, the gate only records what it would have denied (audit mode).
        10 => enforce_exec: bool,
    }
}

/// A policy that failed validation, with the rule it broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid policy: {}", self.0)
    }
}
impl std::error::Error for PolicyError {}

/// Names reach the ledger and operator terminals. Keeping them to a plain alphabet means a name can never carry
/// control characters, line breaks or text that reads like another field (for example `epoch=9`).
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn bad<T>(msg: impl Into<String>) -> Result<T, PolicyError> {
    Err(PolicyError(msg.into()))
}

impl Policy {
    /// Current schema version.
    pub const SCHEMA: u32 = 1;

    /// Digest of the canonical encoding: the policy's identity.
    pub fn digest(&self) -> Digest {
        Digest::of(&self.to_cbor())
    }

    /// Checks structural rules that keep a policy from silently granting
    /// trust it should not. A policy that fails validation must be refused;
    /// the caller must not fall back to a permissive default (I-11).
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.validate_with(true)
    }

    /// Validation for a policy that was **already signed and installed**. Every rule of [`Policy::validate`]
    /// applies except the alphabet of names: policies installed before names were restricted may use spaces and
    /// punctuation, and refusing to open such an installation would leave the operator unable to replace the
    /// policy. The name is only ever printed after escaping, so accepting it is safe. New policies still go
    /// through [`Policy::validate`].
    pub fn validate_loaded(&self) -> Result<(), PolicyError> {
        self.validate_with(false)
    }

    fn validate_with(&self, strict_names: bool) -> Result<(), PolicyError> {
        let name_ok = |n: &str| if strict_names { plain_name(n) } else { !n.is_empty() && n.len() <= 128 };
        if self.schema != Self::SCHEMA {
            return bad(format!("unsupported schema {}", self.schema));
        }
        if !name_ok(&self.name) {
            return bad("name must be 1 to 128 characters from A-Z a-z 0-9 . _ -");
        }
        if self.epoch == 0 {
            return bad("epoch must be positive");
        }
        let Some(last) = self.tiers.last() else { return bad("at least one tier is required") };
        if self.tiers.len() > 64 {
            return bad("too many tiers");
        }
        if !(last.classes.is_empty()
            && last.max_provenance == ProvenanceRank::Unknown
            && last.require_evidence.is_empty())
        {
            return bad("the final tier must match every artifact");
        }
        if self.max_manual_cell > CellClass::Cell3 {
            return bad("max_manual_cell may not be CELL-R");
        }
        let mut seen = std::collections::BTreeSet::new();
        for t in &self.tiers {
            if !name_ok(&t.name) || !seen.insert(t.name.as_str()) {
                return bad(format!(
                    "tier names must be unique, 1 to 128 characters from A-Z a-z 0-9 . _ -: {:?}",
                    jlr_model::sanitize(&t.name)
                ));
            }
            let grants_run = t.state.permits_normal_execution();
            if grants_run && !t.max_provenance.satisfies(ProvenanceRank::VerifiedChecksum) {
                return bad(format!(
                    "tier {}: {} requires provenance of VERIFIED_CHECKSUM or stronger",
                    t.name, t.state
                ));
            }
            if grants_run && t.require_evidence.is_empty() {
                return bad(format!("tier {}: a tier that permits execution must require evidence", t.name));
            }
            if matches!(t.state, AdmissionState::Degraded | AdmissionState::Revoked | AdmissionState::Unknown) {
                return bad(format!("tier {}: {} is not an assignable initial state", t.name, t.state));
            }
            if t.cell == CellClass::CellR {
                return bad(format!("tier {}: CELL-R is reserved for the recovery context", t.name));
            }
            if t.cell >= CellClass::Cell2
                && !grants_run
                && !matches!(t.state, AdmissionState::Observed | AdmissionState::Quarantined)
            {
                return bad(format!("tier {}: inconsistent state and cell", t.name));
            }
            if !grants_run && t.cell != CellClass::Cell0 {
                return bad(format!("tier {}: {} artifacts must stay in CELL-0", t.name, t.state));
            }
            if t.cell == CellClass::Cell3
                && !(t.needs_user
                    || (t.require_evidence.contains(&EvidenceKind::ManagedInstaller)
                        && t.require_evidence.contains(&EvidenceKind::PackageSignature)))
            {
                return bad(format!(
                    "tier {}: CELL-3 needs a human decision or a verified package transaction",
                    t.name
                ));
            }
            if !grants_run && t.network != NetworkMode::None {
                return bad(format!("tier {}: {} artifacts may not have any network access", t.name, t.state));
            }
            if t.network == NetworkMode::PrivilegedNetwork && !t.needs_user {
                return bad(format!("tier {}: PRIVILEGED_NETWORK needs a human decision", t.name));
            }
        }
        Ok(())
    }
}
