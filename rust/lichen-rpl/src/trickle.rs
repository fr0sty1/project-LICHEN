//! Trickle timer (RFC 6206) — deterministic state machine, caller-driven clock.
//!
//! Port of `python/src/lichen/rpl/trickle.py`. The caller is responsible for:
//! - Providing a random offset when starting intervals (for reproducible tests).
//! - Polling `next_event()` and advancing time.
//! - Calling `expire` / `reset` at the appropriate moments.
//!
//! No async, no allocation, no_std compatible.

/// The next scheduled timer event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrickleEvent {
    /// Transmit at or after `at_ms` if `counter < k`.
    Transmit { at_ms: u32 },
    /// Current interval ends at `at_ms`; call `expire`.
    Expire { at_ms: u32 },
}

/// RFC 6206 Trickle timer.
///
/// All times are integer milliseconds. The caller supplies random offsets so the
/// timer is deterministic and testable without a live RNG.
pub struct TrickleTimer {
    pub imin: u32,
    pub max_interval: u32,
    pub k: u32,
    pub interval: u32,
    pub counter: u32,
    pub interval_start: u32,
    pub transmit_time: u32,
    transmitted: bool,
}

impl TrickleTimer {
    /// Create a new timer. `imax_doublings` is the number of times `imin` is
    /// doubled to reach the maximum interval (RFC 6206 uses this convention).
    pub fn new(imin_ms: u32, imax_doublings: u32, k: u32) -> Self {
        let max_interval = imin_ms.checked_shl(imax_doublings).unwrap_or(u32::MAX);
        Self {
            imin: imin_ms,
            max_interval,
            k,
            interval: imin_ms,
            counter: 0,
            interval_start: 0,
            transmit_time: 0,
            transmitted: false,
        }
    }

    /// Begin the first interval (RFC 6206 step 1-2).
    ///
    /// `rand_offset` is a caller-supplied random value in `[0, imin/2)`.
    pub fn start(&mut self, now: u32, rand_offset: u32) {
        self.interval = self.imin;
        self.begin_interval(now, rand_offset);
    }

    fn begin_interval(&mut self, now: u32, rand_offset: u32) {
        self.interval_start = now;
        self.counter = 0;
        self.transmitted = false;
        let half = self.interval / 2;
        // transmit_time is uniform in [now + half, now + interval)
        let offset = if half > 0 { rand_offset % half } else { 0 };
        self.transmit_time = now + half + offset;
    }

    /// Absolute time when the current interval ends.
    pub fn interval_end(&self) -> u32 {
        self.interval_start + self.interval
    }

    /// Record a consistent transmission seen from a neighbour (RFC 6206 step 3).
    pub fn heard_consistent(&mut self) {
        self.counter += 1;
    }

    /// Whether a DIO should be sent at transmit time (c < k, RFC 6206 step 4).
    pub fn should_transmit(&self) -> bool {
        self.counter < self.k
    }

    /// Mark the transmit point reached; returns `true` if a DIO should be sent.
    pub fn fire_transmit(&mut self) -> bool {
        self.transmitted = true;
        self.should_transmit()
    }

    /// End the current interval: double (capped) and start the next one (step 5).
    ///
    /// `rand_offset` is a caller-supplied random value in `[0, new_interval/2)`.
    pub fn expire(&mut self, now: u32, rand_offset: u32) {
        self.interval = self.interval.saturating_mul(2).min(self.max_interval);
        self.begin_interval(now, rand_offset);
    }

    /// Handle an inconsistency: shrink to `imin` and restart (RFC 6206 step 6).
    ///
    /// No-op if the interval is already `imin` (RFC 6206 §4.2).
    pub fn reset(&mut self, now: u32, rand_offset: u32) {
        if self.interval != self.imin {
            self.interval = self.imin;
            self.begin_interval(now, rand_offset);
        }
    }

    /// The next scheduled event.
    pub fn next_event(&self) -> TrickleEvent {
        if !self.transmitted {
            TrickleEvent::Transmit {
                at_ms: self.transmit_time,
            }
        } else {
            TrickleEvent::Expire {
                at_ms: self.interval_end(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transmit_time_in_second_half_of_interval() {
        let mut t = TrickleTimer::new(1000, 4, 10);
        t.start(0, 0); // rand_offset=0 → transmit at 500ms
        assert_eq!(t.transmit_time, 500);
        assert_eq!(t.interval_end(), 1000);
        assert_eq!(t.next_event(), TrickleEvent::Transmit { at_ms: 500 });
    }

    #[test]
    fn fire_transmit_sets_next_event_to_expire() {
        let mut t = TrickleTimer::new(1000, 4, 10);
        t.start(0, 0);
        assert!(t.fire_transmit()); // c=0 < k=10 → should transmit
        assert_eq!(t.next_event(), TrickleEvent::Expire { at_ms: 1000 });
    }

    #[test]
    fn heard_consistent_suppresses_transmit_when_ge_k() {
        let mut t = TrickleTimer::new(1000, 4, 2);
        t.start(0, 0);
        t.heard_consistent();
        t.heard_consistent(); // counter = 2 = k
        assert!(!t.should_transmit());
        assert!(!t.fire_transmit());
    }

    #[test]
    fn expire_doubles_interval_capped_at_max() {
        let mut t = TrickleTimer::new(1000, 2, 10); // max = 4000
        t.start(0, 0);
        t.fire_transmit();
        t.expire(1000, 0);
        assert_eq!(t.interval, 2000);
        t.fire_transmit();
        t.expire(3000, 0);
        assert_eq!(t.interval, 4000);
        t.fire_transmit();
        t.expire(7000, 0);
        assert_eq!(t.interval, 4000); // capped
    }

    #[test]
    fn reset_shrinks_to_imin() {
        let mut t = TrickleTimer::new(1000, 4, 10);
        t.start(0, 0);
        t.fire_transmit();
        t.expire(1000, 0);
        assert_eq!(t.interval, 2000);
        t.reset(1000, 0);
        assert_eq!(t.interval, 1000);
    }

    #[test]
    fn reset_noop_when_already_at_imin() {
        let mut t = TrickleTimer::new(1000, 4, 10);
        t.start(0, 0);
        let tt_before = t.transmit_time;
        t.reset(0, 999); // different rand_offset — should not restart
        assert_eq!(t.transmit_time, tt_before);
    }

    #[test]
    fn rand_offset_shifts_transmit_time() {
        let mut t = TrickleTimer::new(1000, 4, 10);
        t.start(0, 200); // rand_offset=200 < 500 → transmit at 700
        assert_eq!(t.transmit_time, 700);
    }
}
