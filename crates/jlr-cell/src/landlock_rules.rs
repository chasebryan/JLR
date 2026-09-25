//! Landlock rules for a cell.
//!
//! Landlock is defence in depth on top of the mount namespace: even if a
//! process could reach a path outside its private root, the kernel would
//! still refuse the access. `EXECUTE` is deliberately not handled, because a
//! sealed memfd has no place in the file hierarchy for a path rule to name;
//! executability is controlled by read-only, `noexec` mounts instead.

use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};

/// What Landlock managed to enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockOutcome {
    /// Filesystem rules are fully enforced.
    pub fs: bool,
    /// TCP port rules are fully enforced.
    pub net: bool,
}

/// Inputs to the ruleset.
pub struct LandlockPlan<'a> {
    /// Paths readable (directories recursively).
    pub read: &'a [String],
    /// Paths readable and writable.
    pub write: &'a [String],
    /// When set, TCP `connect` is limited to these ports and `bind` to `bind_ports`.
    pub tcp: Option<(&'a [u16], &'a [u16])>,
}

/// Applies the ruleset to the calling process.
pub fn apply(plan: &LandlockPlan<'_>) -> Result<LandlockOutcome, String> {
    let abi = ABI::V4;
    let handled_fs = AccessFs::from_all(abi) & !AccessFs::Execute;
    let mut ruleset = Ruleset::default().set_compatibility(CompatLevel::BestEffort);
    ruleset = ruleset.handle_access(handled_fs).map_err(|e| e.to_string())?;
    if plan.tcp.is_some() {
        ruleset = ruleset.handle_access(AccessNet::from_all(abi)).map_err(|e| e.to_string())?;
    }
    let mut created = ruleset.create().map_err(|e| e.to_string())?;

    let read_access = AccessFs::from_read(abi) & !AccessFs::Execute;
    for p in plan.read {
        if let Ok(fd) = PathFd::new(p) {
            created = created.add_rule(PathBeneath::new(fd, read_access)).map_err(|e| e.to_string())?;
        }
    }
    for p in plan.write {
        if let Ok(fd) = PathFd::new(p) {
            created = created.add_rule(PathBeneath::new(fd, handled_fs)).map_err(|e| e.to_string())?;
        }
    }
    if let Some((connect, bind)) = plan.tcp {
        for port in connect {
            created = created.add_rule(NetPort::new(*port, AccessNet::ConnectTcp)).map_err(|e| e.to_string())?;
        }
        for port in bind {
            created = created.add_rule(NetPort::new(*port, AccessNet::BindTcp)).map_err(|e| e.to_string())?;
        }
    }
    let status = created.restrict_self().map_err(|e| e.to_string())?;
    let full = status.ruleset == RulesetStatus::FullyEnforced;
    Ok(LandlockOutcome {
        fs: full || status.ruleset == RulesetStatus::PartiallyEnforced,
        net: full && plan.tcp.is_some(),
    })
}
