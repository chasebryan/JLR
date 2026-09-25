//! The JLR boot chain.
//!
//! This crate holds the parts of boot that make security decisions, written
//! as plain functions so they can be tested exhaustively without a virtual
//! machine:
//!
//! * [`ReleaseManifest`]: a signed statement binding a release to the exact
//!   digest of its base image, plus an `epoch` used for rollback protection.
//! * [`verify_manifest`] and [`verify_image`]: authenticate the manifest with
//!   trust anchors baked into the initramfs, then hash the image while it is
//!   copied into RAM, so the bytes that get mounted are the bytes that were
//!   verified.
//! * [`BootState`]: ChromeOS-style A/B slot selection (priority, tries
//!   remaining, successful flag) with a monotonic rollback floor.
//!
//! The I/O halves are the `jlr-init` binary (initramfs) and `jlr-release`
//! (build-time signing tool).
//!
//! What this does **not** yet provide: the boot state file lives on the boot
//! media, so an attacker who can write that media can lower the rollback
//! floor. Anchoring the floor in a TPM NV counter is the next milestone, and
//! the prototype says so at every boot.

#![deny(unsafe_code)]

pub mod confirm;
mod manifest;
pub mod media;
mod state;
#[allow(unsafe_code)]
pub mod sys;

pub use manifest::{BootError, Component, ReleaseManifest, verify_image, verify_manifest};
pub use state::{BootState, Choice, SlotState, choose};

#[cfg(test)]
mod tests;
