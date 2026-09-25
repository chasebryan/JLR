//! Engine errors.

use jlr_cell::CellError;
use jlr_model::{AdmissionState, Decision};
use std::fmt;

/// Everything that can go wrong in the engine.
#[derive(Debug)]
pub enum EngineError {
    /// The state directory is already initialised.
    AlreadyInitialised,
    /// The state directory has not been initialised.
    NotInitialised,
    /// A signed object failed verification. It was not used.
    Verification(String),
    /// A policy or list would move an epoch backwards.
    Rollback(String),
    /// The ledger could not be opened or verified.
    Ledger(jlr_ledger::LedgerError),
    /// Measurement failed.
    Measure(jlr_measure::MeasureError),
    /// The decision forbids execution.
    NotRunnable(Box<Decision>),
    /// The jail could not be established.
    Cell(CellError),
    /// The sealed executable could not be prepared.
    Seal(jlr_cell::SealError),
    /// Invalid input.
    Invalid(String),
    /// I/O failure.
    Io(std::io::Error),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::AlreadyInitialised => write!(f, "state directory is already initialised"),
            EngineError::NotInitialised => write!(f, "state directory is not initialised; run `jlr init`"),
            EngineError::Verification(s) => write!(f, "verification failed: {s}"),
            EngineError::Rollback(s) => write!(f, "rollback refused: {s}"),
            EngineError::Ledger(e) => write!(f, "{e}"),
            EngineError::Measure(e) => write!(f, "measurement failed: {e}"),
            EngineError::NotRunnable(d) => {
                let reasons: Vec<String> = d.reasons.iter().map(ToString::to_string).collect();
                write!(f, "execution denied: state {} ({})", d.state, reasons.join(", "))?;
                if let Some(q) = &d.needs_user {
                    write!(f, "; {q}")?;
                }
                Ok(())
            }
            EngineError::Cell(e) => write!(f, "{e}"),
            EngineError::Seal(e) => write!(f, "{e}"),
            EngineError::Invalid(s) => write!(f, "invalid input: {s}"),
            EngineError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EngineError {}
impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        EngineError::Io(e)
    }
}
impl From<jlr_ledger::LedgerError> for EngineError {
    fn from(e: jlr_ledger::LedgerError) -> Self {
        EngineError::Ledger(e)
    }
}
impl From<jlr_measure::MeasureError> for EngineError {
    fn from(e: jlr_measure::MeasureError) -> Self {
        EngineError::Measure(e)
    }
}
impl From<CellError> for EngineError {
    fn from(e: CellError) -> Self {
        EngineError::Cell(e)
    }
}
impl From<jlr_cell::SealError> for EngineError {
    fn from(e: jlr_cell::SealError) -> Self {
        EngineError::Seal(e)
    }
}

/// Whether a state permits running at all (used for messages).
pub(crate) fn runnable(s: AdmissionState) -> bool {
    matches!(s, AdmissionState::Observed | AdmissionState::Verified | AdmissionState::Admitted)
}
