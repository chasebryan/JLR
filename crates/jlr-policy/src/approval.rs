//! Operator approvals: authority, not proof.

use jlr_cbor::{Cbor, record};
use jlr_crypto::{Envelope, EnvelopeError, TrustAnchors};
use jlr_model::{Capability, CellClass, EpnId, NetworkMode, record_type};
use std::fmt;

record! {
    /// A signed grant by an operator for one artifact.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Approval {
        /// The artifact being authorized.
        1 => epn: String,
        /// Cell the artifact may run in.
        2 => cell: CellClass,
        /// Network policy for that cell.
        3 => network: NetworkMode,
        /// Exact capabilities granted.
        4 => capabilities: Vec<Capability>,
        /// Seconds since the Unix epoch after which the approval is void.
        5 => expires_at: u64,
        /// Operator identity for the audit trail.
        6 => granted_by: String,
    }
}

/// An approval whose signature and scope have been verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedApproval(Approval);

/// Why an approval was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ApprovalError {
    /// The signature or its signer is not acceptable.
    Envelope(EnvelopeError),
    /// The payload was malformed.
    Payload(String),
    /// The EPN text is not a valid identifier.
    BadEpn,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalError::Envelope(e) => write!(f, "approval refused: {e}"),
            ApprovalError::Payload(e) => write!(f, "approval malformed: {e}"),
            ApprovalError::BadEpn => write!(f, "approval names an invalid EPN"),
        }
    }
}
impl std::error::Error for ApprovalError {}

impl Approval {
    /// Signs an approval for `scope` (the node it is valid on).
    pub fn sign(&self, scope: &str, key: &jlr_crypto::SigningKeypair) -> Vec<u8> {
        Envelope::sign(record_type::APPROVAL, scope, &self.to_cbor(), key)
    }

    /// Verifies an enveloped approval for `scope`.
    pub fn verify(bytes: &[u8], scope: &str, anchors: &TrustAnchors) -> Result<VerifiedApproval, ApprovalError> {
        let v = Envelope::verify(
            bytes,
            record_type::APPROVAL,
            scope,
            anchors,
            record_type::allowed_signers(record_type::APPROVAL),
        )
        .map_err(ApprovalError::Envelope)?;
        let a = Approval::from_cbor(&v.payload).map_err(|e| ApprovalError::Payload(e.to_string()))?;
        EpnId::parse(&a.epn).ok_or(ApprovalError::BadEpn)?;
        Ok(VerifiedApproval(a))
    }
}

impl VerifiedApproval {
    /// Wraps an approval derived from an already-verified signed object.
    pub(crate) fn from_parts(a: Approval) -> Self {
        VerifiedApproval(a)
    }

    /// The approval contents.
    pub fn get(&self) -> &Approval {
        &self.0
    }

    /// Whether the approval is for `id` and has not expired at `now`.
    pub fn applies_to(&self, id: &EpnId, now: u64) -> bool {
        self.0.epn == id.to_string() && now < self.0.expires_at
    }
}
