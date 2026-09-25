//! Creating a new installation: the key ceremony and the first ledger entries.

use crate::error::EngineError;
use crate::paths::Paths;
use crate::store::{NodeInfo, mkdir_private, write_atomic};
use jlr_cbor::Cbor;
use jlr_crypto::{Envelope, Role, SigningKeypair, TrustAnchors, random_bytes};
use jlr_ledger::{EventDraft, Ledger};
use jlr_model::{Basis, EventKind, record_type};
use jlr_policy::{Policy, Revocations};

/// Which built-in policy to install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyKind {
    /// Silent admission of managed software, observation of the rest.
    Workstation,
    /// Quarantine of everything without strong evidence.
    Strict,
}

/// What `init` created.
#[derive(Debug)]
pub struct InitReport {
    /// The new node identity.
    pub node: NodeInfo,
    /// Key identifiers that were enrolled, with their roles.
    pub keys: Vec<(Role, String)>,
    /// Digest of the installed policy.
    pub policy_digest: String,
}

/// Initialises a state directory.
///
/// Companion mode generates the device key and the policy key locally. The
/// policy key can approve software and change policy, so on a production
/// machine it belongs on a separate device; a policy key stored beside the
/// engine can be used by anything that can read the state directory, which is
/// why companion mode reports itself as such.
pub fn init(paths: &Paths, kind: PolicyKind, now: u64) -> Result<InitReport, EngineError> {
    if paths.node().exists() {
        return Err(EngineError::AlreadyInitialised);
    }
    for d in [
        paths.root().to_owned(),
        paths.keys(),
        paths.root().join("trust"),
        paths.root().join("policy"),
        paths.approvals(),
        paths.baselines(),
        paths.objects(),
    ] {
        mkdir_private(&d)?;
    }
    let map = |e: jlr_crypto::KeyError| EngineError::Invalid(e.to_string());
    let device = SigningKeypair::generate(Role::Device).map_err(map)?;
    let policy_key = SigningKeypair::generate(Role::Policy).map_err(map)?;
    device.save(&paths.device_key()).map_err(map)?;
    policy_key.save(&paths.policy_key()).map_err(map)?;

    let mut anchors = TrustAnchors::new();
    anchors.insert(device.public());
    anchors.insert(policy_key.public());
    write_atomic(&paths.anchors(), &anchors.to_cbor())?;

    let policy = match kind {
        PolicyKind::Workstation => Policy::workstation(1),
        PolicyKind::Strict => Policy::strict(1),
    };
    policy.validate().map_err(|e| EngineError::Invalid(e.to_string()))?;
    write_atomic(&paths.policy(), &Envelope::sign(record_type::POLICY, "*", &policy.to_cbor(), &policy_key))?;
    write_atomic(
        &paths.revocations(),
        &Envelope::sign(record_type::REVOCATIONS, "*", &Revocations::empty().to_cbor(), &policy_key),
    )?;

    let id = random_bytes::<16>().map_err(|e| EngineError::Invalid(e.to_string()))?;
    let node = NodeInfo { node_id: format!("node-{}", hex(&id)), created_at: now, mode: "companion".into() };

    let boot = random_bytes::<16>().map_err(|e| EngineError::Invalid(e.to_string()))?;
    let mut ledger = Ledger::create(&paths.ledger(), &node.node_id, device, boot)?;
    for k in [&anchors.iter().map(|k| (k.role, k.id())).collect::<Vec<_>>()].into_iter().flatten() {
        let mut d = EventDraft::new("jlr-init", EventKind::KeyEvent, &format!("enrolled {} key {}", k.0, k.1));
        d.basis = Basis::Policy;
        ledger.append(d)?;
    }
    let mut d = EventDraft::new(
        "jlr-init",
        EventKind::PolicyLoad,
        &format!("policy={} epoch={} digest={}", policy.name, policy.epoch, policy.digest()),
    );
    d.policy = policy.digest();
    d.basis = Basis::Policy;
    ledger.append(d)?;
    ledger.checkpoint()?;
    drop(ledger);

    write_atomic(&paths.node(), &node.to_cbor())?;
    let keys = anchors.iter().map(|k| (k.role, k.id().short())).collect();
    Ok(InitReport { node, keys, policy_digest: policy.digest().to_string() })
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
