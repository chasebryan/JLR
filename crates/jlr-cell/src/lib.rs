//! The JLR jail fabric.
//!
//! A *cell* is an execution environment assembled from Linux primitives:
//! user, mount, PID, IPC, UTS and network namespaces, a private root built
//! from read-only bind mounts, `no_new_privs`, dropped capabilities, a
//! seccomp-BPF filter, Landlock rules and resource limits.
//!
//! Three properties are built in:
//!
//! * **The measured bytes are the executed bytes.** The launcher copies the
//!   file into a sealed memfd, hashes what it copied, and executes that
//!   descriptor. Swapping the path or editing the original file afterwards
//!   changes nothing.
//! * **Missing enforcement is visible.** Every launch produces an
//!   [`EnforcementReport`] listing controls requested, controls active and
//!   mandatory controls that could not be established. A launch whose
//!   mandatory controls are missing is refused, never downgraded silently.
//! * **The jail is a function of the decision.** [`CellSpec::from_decision`]
//!   is deterministic, so the same decision always produces the same jail.
//!
//! Containers share the host kernel. A hostile kernel defeats every control
//! here; see `docs/SECURITY_BOUNDARIES.md`.

#![deny(unsafe_code)]

mod init;
mod landlock_rules;
mod launch;
mod sealed;
mod seccomp;
mod spec;
#[allow(unsafe_code)]
mod sys;

pub use init::cell_main;
pub use launch::{Outcome, Running, Stdio3, launch};
pub use sealed::{SealError, SealedExe};
pub use spec::{CellError, CellSpec, Control, EnforcementReport, Limits, Status};
