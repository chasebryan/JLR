//! Evidence items and trust decisions.

use crate::artifact::coded_enum;
use crate::capability::{Capability, CellClass, NetworkMode};
use crate::event::Basis;
use crate::state::AdmissionState;
use jlr_cbor::record;
use jlr_crypto::Digest;

coded_enum! {
    /// Normalized kinds of evidence the trust engine understands.
    pub enum EvidenceKind: u8 {
        /// The bytes hash to the digest recorded in the EPN.
        ContentDigestMatch = 1 => "CONTENT_DIGEST_MATCH",
        /// The bytes no longer match the recorded digest.
        ContentDigestMismatch = 2 => "CONTENT_DIGEST_MISMATCH",
        /// A signature verified against a pinned trusted key.
        SignatureValid = 3 => "SIGNATURE_VALID",
        /// A signature was present but did not verify.
        SignatureInvalid = 4 => "SIGNATURE_INVALID",
        /// The artifact was written by a signed package transaction.
        ManagedInstaller = 5 => "MANAGED_INSTALLER",
        /// A package or repository signature verified.
        PackageSignature = 6 => "PACKAGE_SIGNATURE",
        /// A local rebuild reproduced the bytes.
        ReproducibleMatch = 7 => "REPRODUCIBLE_MATCH",
        /// The artifact carries the setuid or setgid bit.
        SetuidBit = 8 => "SETUID_BIT",
        /// The path is writable by a less-trusted actor.
        WritablePath = 9 => "WRITABLE_PATH",
        /// Static analysis finding.
        StaticFinding = 10 => "STATIC_FINDING",
        /// Behavior recorded in an observation cell.
        Observation = 11 => "OBSERVATION",
        /// An operator authorized the artifact.
        OperatorApproval = 12 => "OPERATOR_APPROVAL",
        /// A revocation entry matched.
        RevocationHit = 13 => "REVOCATION_HIT",
        /// Expected evidence could not be obtained.
        Missing = 14 => "MISSING",
        /// Observed behavior that policy forbids.
        ForbiddenBehavior = 15 => "FORBIDDEN_BEHAVIOR",
        /// The installed bytes match the package manager's own file manifest.
        /// That manifest is unauthenticated, so this is weaker than a package signature.
        PackageManifestMatch = 16 => "PACKAGE_MANIFEST_MATCH",
        /// The artifact is a member of a signed baseline.
        BaselineMember = 17 => "BASELINE_MEMBER",
    }
}

coded_enum! {
    /// Machine-readable reasons attached to decisions.
    pub enum ReasonCode: u8 {
        /// Artifact revoked by digest, signer or EPN.
        Revoked = 1 => "REVOKED",
        /// Content changed since admission.
        ContentChanged = 2 => "CONTENT_CHANGED",
        /// Installed by a verified package transaction.
        ManagedInstall = 3 => "MANAGED_INSTALL",
        /// Signed by a pinned vendor key.
        PinnedVendorSignature = 4 => "PINNED_VENDOR_SIGNATURE",
        /// Provenance too weak for the requested tier.
        WeakProvenance = 5 => "WEAK_PROVENANCE",
        /// No provenance evidence at all.
        NoProvenance = 6 => "NO_PROVENANCE",
        /// A requested capability is high risk.
        HighRiskCapability = 7 => "HIGH_RISK_CAPABILITY",
        /// Setuid or setgid executable.
        SetuidExecutable = 8 => "SETUID_EXECUTABLE",
        /// Located in a path writable by a less-trusted actor.
        WritableLocation = 9 => "WRITABLE_LOCATION",
        /// Policy forbids this class or behavior.
        PolicyProhibition = 10 => "POLICY_PROHIBITION",
        /// Signature was present but invalid.
        BadSignature = 11 => "BAD_SIGNATURE",
        /// An operator authorization is the basis.
        OperatorAuthorized = 12 => "OPERATOR_AUTHORIZED",
        /// A required piece of evidence is missing.
        EvidenceMissing = 13 => "EVIDENCE_MISSING",
        /// Default tier applied because nothing stronger matched.
        DefaultTier = 14 => "DEFAULT_TIER",
        /// Signature verified.
        SignatureVerified = 15 => "SIGNATURE_VERIFIED",
        /// Observation window has not completed.
        ObservationPending = 16 => "OBSERVATION_PENDING",
        /// A local rebuild reproduced the bytes.
        ReproducedBuild = 17 => "REPRODUCED_BUILD",
        /// Verified against an upstream checksum only.
        ChecksumVerified = 18 => "CHECKSUM_VERIFIED",
        /// Reduced to a smaller cell than the tier grants.
        CellCapped = 19 => "CELL_CAPPED",
        /// The artifact was previously revoked.
        PreviouslyRevoked = 20 => "PREVIOUSLY_REVOKED",
    }
}

record! {
    /// One normalized piece of evidence with its source and time.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EvidenceItem {
        /// Kind of evidence.
        1 => kind: EvidenceKind,
        /// Component that produced it, for example `measure`, `dpkg`, `cell`.
        2 => source: String,
        /// Seconds since the Unix epoch when it was produced (advisory).
        3 => at: u64,
        /// Short human-readable detail.
        4 => detail: String,
        /// Digest of the raw measurement when one exists.
        5 => digest: Option<Digest>,
    }
}

record! {
    /// The trust engine's output for one artifact under one policy version.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Decision {
        /// New admission state.
        1 => state: AdmissionState,
        /// Cell class the artifact must run in.
        2 => cell: CellClass,
        /// Network policy for that cell.
        3 => network: NetworkMode,
        /// Exact capabilities granted.
        4 => capabilities: Vec<Capability>,
        /// Reasons, in a stable order.
        5 => reasons: Vec<ReasonCode>,
        /// Basis of the decision (cryptographic, policy, or manual override).
        6 => basis: Basis,
        /// A question the user must answer before this decision can improve.
        7 => needs_user: Option<String>,
        /// Digest of the policy that produced it.
        8 => policy: Digest,
    }
}
