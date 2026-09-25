//! Per-user allowance of slow-path time.
//!
//! The gate answers events on one thread, and answering a file it has not seen costs real work: opening the
//! engine, hashing, recording. Without a bound, one unprivileged user running `touch big; ./big` in a loop
//! makes everyone's `exec` wait behind that work. A budget caps how much slow-path time each user can spend
//! per window; beyond it their unmeasured executions are answered by policy (denied when enforcing) without
//! any measurement, so the cost falls on the user who caused it.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Sliding per-user allowance, plus a cap on what all non-root users may spend together.
///
/// The per-user allowance stops one account from stalling everyone. The global cap stops one *person* from
/// presenting as many accounts: a user with a range of subordinate ids and unprivileged user namespaces
/// appears to the kernel as thousands of distinct uids, each of which would otherwise get its own allowance.
#[derive(Debug)]
pub struct Budgets {
    window: Duration,
    allowance: Duration,
    global_allowance: Duration,
    global: (Option<Instant>, Duration),
    users: HashMap<u32, (Instant, Duration)>,
}

impl Budgets {
    /// `allowance` of slow-path time per `window`, per user, and `global_allowance` for all users together.
    pub fn new(allowance: Duration, global_allowance: Duration, window: Duration) -> Self {
        Budgets { window, allowance, global_allowance, global: (None, Duration::ZERO), users: HashMap::new() }
    }

    /// Starts a new global window when the current one has run out (or none has started).
    fn roll_global(&mut self, now: Instant) {
        match self.global.0 {
            Some(start) if now.duration_since(start) < self.window => {}
            _ => self.global = (Some(now), Duration::ZERO),
        }
    }

    /// Whether `uid` (or every unprivileged user together) has used up its allowance in the current window.
    pub fn exhausted(&mut self, uid: u32, now: Instant) -> bool {
        self.roll_global(now);
        if self.global.1 >= self.global_allowance {
            return true;
        }
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
        self.roll_global(now);
        self.global.1 += spent;
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
        let mut b = Budgets::new(Duration::from_secs(10), Duration::from_secs(1000), Duration::from_secs(60));
        assert!(!b.exhausted(1000, t0));
        b.charge(1000, Duration::from_secs(6), t0);
        assert!(!b.exhausted(1000, t0));
        b.charge(1000, Duration::from_secs(5), t0);
        assert!(b.exhausted(1000, t0), "11 s of slow-path work exceeds a 10 s allowance");
        assert!(b.exhausted(1000, t0 + Duration::from_secs(59)));
        assert!(!b.exhausted(1000, t0 + Duration::from_secs(60)), "a new window starts fresh");
    }

    #[test]
    fn a_few_accounts_can_use_up_the_shared_cap_and_throttle_everyone_else() {
        // The price of the shared cap, stated as a test with the production numbers (10 s per user, 30 s together,
        // 60 s window): three accounts that each spend their whole allowance make `exhausted` true for a fourth
        // account that has spent nothing. Its *cached* and known-good files are unaffected (the daemon answers those
        // before asking), but an unknown file it runs in that minute is answered by policy, unmeasured.
        let t0 = Instant::now();
        let mut b = Budgets::new(Duration::from_secs(10), Duration::from_secs(30), Duration::from_secs(60));
        for uid in [2001, 2002, 2003] {
            b.charge(uid, Duration::from_secs(10), t0);
        }
        assert!(b.exhausted(1000, t0), "a user who spent nothing is throttled once the shared cap is used up");
        assert!(!b.exhausted(1000, t0 + Duration::from_secs(60)), "and served again in the next window");
    }

    #[test]
    fn per_user_allowances_are_independent_while_the_shared_cap_has_room() {
        let t0 = Instant::now();
        let mut b = Budgets::new(Duration::from_secs(1), Duration::from_secs(1000), Duration::from_secs(60));
        b.charge(1000, Duration::from_secs(5), t0);
        assert!(b.exhausted(1000, t0));
        assert!(!b.exhausted(1001, t0));
    }

    #[test]
    fn many_accounts_cannot_multiply_the_allowance() {
        // A user with a subuid range and user namespaces looks like thousands of uids to the kernel. Each has a
        // 10 s allowance of its own, but together they may spend at most the global cap.
        let t0 = Instant::now();
        let mut b = Budgets::new(Duration::from_secs(10), Duration::from_secs(30), Duration::from_secs(60));
        for uid in 100_000..100_006 {
            assert!(!b.exhausted(uid, t0), "the first six accounts, at 5 s each, are served");
            b.charge(uid, Duration::from_secs(5), t0);
        }
        assert!(b.exhausted(100_500, t0), "a brand-new uid is refused once the accounts together spent 30 s");
        assert!(!b.exhausted(100_500, t0 + Duration::from_secs(60)), "and served again in the next window");
    }

    #[test]
    fn the_table_stays_bounded() {
        let t0 = Instant::now();
        let mut b = Budgets::new(Duration::from_secs(1), Duration::from_secs(1_000_000), Duration::from_secs(1));
        for uid in 0..10_000 {
            b.charge(uid, Duration::from_millis(1), t0);
        }
        b.charge(20_000, Duration::from_millis(1), t0 + Duration::from_secs(5));
        assert!(b.users.len() <= 4097);
    }
}
