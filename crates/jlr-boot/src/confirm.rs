//! Deciding what a wrong image read means.
//!
//! A digest or size mismatch is either a bad image or unreliable media (a flaky cable, a dying stick) that returned
//! wrong bytes without any error. Retiring a proven slot for the second is how one bad read strands a machine, so a
//! mismatch is confirmed by reading again, and only the **same** wrong answer twice is proof.

use crate::manifest::BootError;

/// Why an image could not be loaded.
#[derive(Debug)]
pub enum LoadFailure {
    /// Nothing proves the content is bad: an I/O error, no memory, or reads that disagreed with each other.
    Transient(String),
    /// Two reads returned the same wrong bytes: the content is bad, on every boot.
    ProvenBad(BootError),
}

/// Which read this is. The confirming read must not be answered from a cache that already holds the wrong bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    /// The first attempt.
    First,
    /// The read that confirms or clears a mismatch. The caller drops cached pages before it.
    Confirming,
}

/// Whether two verification failures are the same wrong answer.
pub fn same_mismatch(a: &BootError, b: &BootError) -> bool {
    match (a, b) {
        (BootError::ImageDigest { actual: x, .. }, BootError::ImageDigest { actual: y, .. }) => x == y,
        (BootError::ImageSize { actual: x, .. }, BootError::ImageSize { actual: y, .. }) => x == y,
        _ => false,
    }
}

/// Runs `read` once and, if it reports a mismatch, once more to confirm.
///
/// * The first read succeeds: its result is used and nothing else happens.
/// * A transient failure ends the attempt at once (nothing is confirmed by reading a medium that errors).
/// * A mismatch is read again with [`Reading::Confirming`]: if that read verifies, its result is used (the first
///   read was the fluke); if it fails the **same** way, the content is proven bad; if it fails differently, or
///   transiently, the medium is unreliable and nothing is proven.
///
/// `note` receives a line for each step that is worth telling the operator about.
pub fn confirm<T>(
    mut read: impl FnMut(Reading) -> Result<T, LoadFailure>,
    note: &mut dyn FnMut(&str),
) -> Result<T, LoadFailure> {
    let first = match read(Reading::First) {
        Err(LoadFailure::ProvenBad(e)) => e,
        other => return other,
    };
    note(&format!("image mismatch ({first}); reading the image once more to confirm"));
    match read(Reading::Confirming) {
        Ok(v) => {
            note("the second read verified: the first returned different bytes, so this medium is unreliable");
            Ok(v)
        }
        Err(LoadFailure::ProvenBad(second)) if same_mismatch(&first, &second) => Err(LoadFailure::ProvenBad(first)),
        Err(LoadFailure::ProvenBad(second)) => Err(LoadFailure::Transient(format!(
            "two reads of the image disagreed with each other ({first}; {second}): the medium is unreliable"
        ))),
        Err(other) => Err(other),
    }
}
