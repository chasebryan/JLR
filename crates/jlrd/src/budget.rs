//! Per-user allowance of slow-path time.
//!
//! The gate answers events on one thread, and answering a file it has not seen costs real work: opening the
//! engine, hashing, recording. Without a bound, one unprivileged user running `touch big; ./big` in a loop
//! makes everyone's `exec` wait behind that work. A budget caps how much slow-path time each user can spend
//! per window; beyond it their unmeasured executions are answered by policy (denied when enforcing) without
//! any measurement, so the cost falls on the user who caused it.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Sliding per-user allowance.
#[derive(Debug)]
pub struct Budgets {
    window: Duration,
    allowance: Duration,
    users: HashMap<u32, (Instant, Duration)>,
}

impl Budgets {
    /// `allowance` of slow-path time per `window`, per user.
    pub fn new(allowance: Duration, window: Duration) -> Self {
        Budgets { window, allowance, users: HashMap::new() }
    }

    /// Whether `uid` has used up its allowance in the current window.
    pub fn exhausted(&mut self, uid: u32, now: Instant) -> bool {
        match self.users.get_mut(&uid) {
            Some((start, spent)) => {
                if now.duration_since(*start) >= self.window {
                    *start = now;
                    *spent = Duration::ZERO;
                }
                *spent >= self.allowance
            }
            None => false,
        }
    }

    /// Records slow-path time spent for `uid`.
    pub fn charge(&mut self, uid: u32, spent: Duration, now: Instant) {
        let entry = self.users.entry(uid).or_insert((now, Duration::ZERO));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, Duration::ZERO);
        }
        entry.1 += spent;
        // Bound the table itself: forget users whose window has long passed.
        if self.users.len() > 4096 {
            let window = self.window;
            self.users.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_who_spends_the_allowance_is_throttled_until_the_window_passes() {
        let t0 = Instant::now();
        let mut b = Budgets::new(Duration::from_secs(10), Duration::from_secs(60));
        assert!(!b.exhausted(1000, t0));
        b.charge(1000, Duration::from_secs(6), t0);
        assert!(!b.exhausted(1000, t0));
        b.charge(1000, Duration::from_secs(5), t0);
        assert!(b.exhausted(1000, t0), "11 s of slow-path work exceeds a 10 s allowance");
        assert!(b.exhausted(1000, t0 + Duration::from_secs(59)));
        assert!(!b.exhausted(1000, t0 + Duration::from_secs(60)), "a new window starts fresh");
    }

    #[test]
    fn users_are_independent_so_an_attacker_cannot_throttle_a_victim() {
        let t0 = Instant::now();
        let mut b = Budgets::new(Duration::from_secs(1), Duration::from_secs(60));
        b.charge(1000, Duration::from_secs(5), t0);
        assert!(b.exhausted(1000, t0));
        assert!(!b.exhausted(1001, t0));
    }

    #[test]
    fn the_table_stays_bounded() {
        let t0 = Instant::now();
        let mut b = Budgets::new(Duration::from_secs(1), Duration::from_secs(1));
        for uid in 0..10_000 {
            b.charge(uid, Duration::from_millis(1), t0);
        }
        b.charge(20_000, Duration::from_millis(1), t0 + Duration::from_secs(5));
        assert!(b.users.len() <= 4097);
    }
}
