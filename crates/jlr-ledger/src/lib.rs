//! The JLR evidence ledger.
//!
//! Events are signed COSE_Sign1 envelopes appended to `events.log` as
//! `u32 length || u32 length-check || envelope`. Each event carries the envelope digest
//! of its predecessor (a streaming convenience) and is also a leaf of an
//! RFC 9162 Merkle tree. Signed [`Checkpoint`]s commit to the tree head so a
//! verifier that holds an independently stored checkpoint can detect
//! truncation, rollback and rewriting, none of which a bare hash chain can
//! prove.
//!
//! What this crate does **not** provide: a hardware monotonic counter. The
//! checkpoint counter is a software counter and each checkpoint says so in
//! its `anchor` field; a verifier must state which anchors were present.

#![forbid(unsafe_code)]

mod store;

pub mod merkle;

pub use store::{
    Anchor, Checkpoint, EventDraft, Ledger, LedgerError, OpenReport, VerifyReport, read_events, verify_dir,
};

#[cfg(test)]
mod merkle_tests;
#[cfg(test)]
mod store_tests;
