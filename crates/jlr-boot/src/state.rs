//! A/B slot selection with a rollback floor.
//!
//! The rules follow ChromeOS's kernel-slot triple, which needs no cooperation
//! from a possibly broken running system:
//!
//! * a slot is bootable when it is verified and is either marked successful or
//!   still has tries left;
//! * the bootable slot with the highest priority is chosen;
//! * before booting an unproven slot, its tries are decremented and the state is
//!   made durable, so a crash or power cut during boot consumes a try and the
//!   next boot falls back;
//! * only after the booted system passes its self-test is the slot marked
//!   successful and the rollback floor raised (never before, or a bad update
//!   could strand the machine with no bootable slot).

use crate::manifest::{BootError, ReleaseManifest};
use jlr_cbor::record;

/// Tries granted to a freshly installed slot.
pub const DEFAULT_TRIES: u16 = 3;

/// Highest slot priority.
pub const MAX_PRIORITY: u16 = 15;

record! {
    /// Boot bookkeeping for one slot.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SlotState {
        /// Slot name, for example `a`.
        1 => name: String,
        /// Higher boots first; zero means never boot.
        2 => priority: u16,
        /// Remaining attempts while the slot is unproven.
        3 => tries: u16,
        /// Whether the slot has booted and passed its self-test.
        4 => successful: bool,
    }
}

record! {
    /// The persistent boot state.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BootState {
        /// Releases with a lower epoch may not boot.
        1 => floor: u64,
        /// Slots in any order.
        2 => slots: Vec<SlotState>,
    }
}

/// The outcome of slot selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    /// Slot to boot.
    pub slot: String,
    /// State to write durably **before** booting it.
    pub next: BootState,
}

impl BootState {
    /// A state with one proven slot `a` and nothing else.
    pub fn fresh() -> BootState {
        BootState {
            floor: 0,
            slots: vec![SlotState { name: "a".into(), priority: MAX_PRIORITY, tries: 0, successful: true }],
        }
    }

    fn slot_mut(&mut self, name: &str) -> Option<&mut SlotState> {
        self.slots.iter_mut().find(|s| s.name == name)
    }

    /// Installs a new, unproven release into `name` and prefers it.
    ///
    /// The new slot gets the maximum priority and every other slot is demoted
    /// below it, so the update is tried first but the previous proven slot
    /// remains the fallback.
    pub fn install(&mut self, name: &str) {
        for s in &mut self.slots {
            if s.name != name && s.priority >= MAX_PRIORITY {
                s.priority = MAX_PRIORITY - 1;
            }
        }
        let slot = SlotState { name: name.into(), priority: MAX_PRIORITY, tries: DEFAULT_TRIES, successful: false };
        match self.slot_mut(name) {
            Some(s) => *s = slot,
            None => self.slots.push(slot),
        }
    }

    /// Marks a slot unbootable, for example after its image failed verification.
    pub fn mark_bad(&mut self, name: &str) {
        if let Some(s) = self.slot_mut(name) {
            s.priority = 0;
            s.successful = false;
            s.tries = 0;
        }
    }

    /// Records that `name` booted and passed its self-test, and raises the
    /// rollback floor to the release's `min_epoch`.
    pub fn mark_successful(&mut self, name: &str, m: &ReleaseManifest) {
        if let Some(s) = self.slot_mut(name) {
            s.successful = true;
            s.tries = 0;
        }
        self.floor = self.floor.max(m.min_epoch);
    }
}

/// Picks the slot to boot from those whose manifests verified.
///
/// `verified` lists `(slot name, manifest)` for slots that passed signature
/// and floor checks. Slots absent from it are unbootable regardless of their
/// recorded state.
pub fn choose(state: &BootState, verified: &[(String, ReleaseManifest)]) -> Result<Choice, BootError> {
    let mut order: Vec<&SlotState> = state.slots.iter().filter(|s| s.priority > 0).collect();
    // Highest priority first; ties broken by name for determinism.
    order.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.name.cmp(&b.name)));
    for s in order {
        let Some((_, m)) = verified.iter().find(|(n, _)| *n == s.name) else { continue };
        if m.epoch < state.floor {
            continue;
        }
        if !(s.successful || s.tries > 0) {
            continue;
        }
        let mut next = state.clone();
        if !s.successful
            && let Some(t) = next.slot_mut(&s.name)
        {
            t.tries -= 1;
        }
        return Ok(Choice { slot: s.name.clone(), next });
    }
    Err(BootError::NoBootableSlot)
}
