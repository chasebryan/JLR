//! Signed baselines: the enrolled initial state of a host.
//!
//! A baseline is an operator's signed statement that a specific set of
//! artifacts, identified by their EPN record digests, is the machine's known
//! initial state. It is authority, not proof: members are admitted on the
//! basis of a manual override, and the ledger says so (I-13).

use crate::approval::{Approval, ApprovalError, VerifiedApproval};
use jlr_cbor::{Cbor, record};
use jlr_crypto::{Digest, Envelope, TrustAnchors};
use jlr_model::{Capability, CellClass, EpnId, NetworkMode, record_type};

record! {
    /// A signed set of enrolled artifacts.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Baseline {
        /// Schema version, currently 1.
        1 => schema: u32,
        /// Baseline name, for example `initial-host`.
        2 => name: String,
        /// Cell members may run in.
        3 => cell: CellClass,
        /// Network policy for that cell.
        4 => network: NetworkMode,
        /// Capabilities every member receives.
        5 => capabilities: Vec<Capability>,
        /// Operator identity for the audit trail.
        6 => granted_by: String,
        /// Seconds since the Unix epoch after which the baseline is void.
        7 => expires_at: u64,
        /// EPN record digests of the members, sorted ascending.
        8 => members: Vec<Digest>,
    }
}

/// A baseline whose signature has been verified.
#[derive(Clone, Debug)]
pub struct VerifiedBaseline(Baseline);

impl Baseline {
    /// Sorts and de-duplicates the member list so encodings are unique.
    pub fn normalize(&mut self) {
        self.members.sort();
        self.members.dedup();
    }

    /// Signs the baseline for `scope`.
    pub fn sign(&self, scope: &str, key: &jlr_crypto::SigningKeypair) -> Vec<u8> {
        Envelope::sign(record_type::APPROVAL, scope, &self.to_cbor(), key)
    }

    /// Verifies an enveloped baseline. Members must already be sorted and unique.
    pub fn verify(bytes: &[u8], scope: &str, anchors: &TrustAnchors) -> Result<VerifiedBaseline, ApprovalError> {
        let v = Envelope::verify(
            bytes,
            record_type::APPROVAL,
            scope,
            anchors,
            record_type::allowed_signers(record_type::APPROVAL),
        )
        .map_err(ApprovalError::Envelope)?;
        let b = Baseline::from_cbor(&v.payload).map_err(|e| ApprovalError::Payload(e.to_string()))?;
        if b.members.windows(2).any(|w| w[0] >= w[1]) {
            return Err(ApprovalError::Payload("baseline members must be sorted and unique".into()));
        }
        Ok(VerifiedBaseline(b))
    }
}

impl VerifiedBaseline {
    /// The baseline contents.
    pub fn get(&self) -> &Baseline {
        &self.0
    }

    /// Whether `id` is a member.
    pub fn contains(&self, id: &EpnId) -> bool {
        self.0.members.binary_search(&id.digest).is_ok()
    }

    /// The per-artifact approval implied by membership, valid at `now`.
    pub fn approval_for(&self, id: &EpnId, now: u64) -> Option<VerifiedApproval> {
        if now >= self.0.expires_at || !self.contains(id) {
            return None;
        }
        Some(VerifiedApproval::from_parts(Approval {
            epn: id.to_string(),
            cell: self.0.cell,
            network: self.0.network,
            capabilities: self.0.capabilities.clone(),
            expires_at: self.0.expires_at,
            granted_by: format!("baseline:{}:{}", self.0.name, self.0.granted_by),
        }))
    }
}
