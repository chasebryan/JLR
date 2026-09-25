//! The JLR engine.
//!
//! The engine owns the state directory and connects the pieces:
//! measurement produces evidence, the trust engine turns evidence and policy
//! into decisions, the ledger records every state change with the evidence
//! behind it, and the jail fabric enforces the decision when software runs.
//!
//! Loading is fail-closed. A policy, revocation list or baseline whose
//! signature does not verify is never replaced by a permissive default
//! (invariant I-11), and a policy epoch may never go backwards.

#![forbid(unsafe_code)]

mod engine;
mod error;
mod paths;
mod setup;
mod store;

pub use engine::{
    Config, Engine, EnrollOptions, ExecVerdict, Explanation, RunResult, ScanOptions, ScanReport, Status,
    list_artifacts, verify_ledger_at,
};
pub use error::EngineError;
pub use paths::Paths;
pub use setup::{InitReport, PolicyKind, init};
pub use store::NodeInfo;

#[cfg(test)]
mod tests;
