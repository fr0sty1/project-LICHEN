//! Trickle timer per RFC 6206 for RPL DIO pacing. Matches the 6-rule
//! pseudocode exactly (rules 1-6 in §4.2). Deterministic, caller-driven.

/// The next scheduled timer event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrickleEvent {
    /// No event can be represented after the monotonic clock is exhausted.
    Stopped,
    /// Transmit at or after `at_ms` if `counter < k`.
    Transmit { at_ms: u64 },
    /// Current interval ends at `at_ms`; call `expire`.
    Expire { at_ms: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrickleState {
    Stopped,
    WaitingTransmit,
    WaitingExpire,
}

impl TrickleState {
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (_, Self::Stopped)
                | (Self::Stopped, Self::WaitingTransmit)
                | (Self::WaitingTransmit, Self::WaitingTransmit)
                | (Self::WaitingTransmit, Self::WaitingExpire)
                | (Self::WaitingExpire, Self::WaitingTransmit)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidTrickleTransition {
    pub from: TrickleState,
    pub to: TrickleState,
}

/// Trickle timer matching RFC 6206 §4.2 pseudocode exactly. All times in ms.
/// Caller supplies random offset for deterministic tests (no RNG).
#[derive(Debug)]
pub struct TrickleTimer {
    pub imin: u32,
    pub max_interval: u32,
    pub k: u32,
    pub interval: u32,
    pub counter: u32,
    pub interval_start: u64,
    pub transmit_time: u64,
    pub state: TrickleState,
    transmitted: bool,
}

impl TrickleTimer {
    /// Create a new timer. `imax_doublings` is the number of times `imin` is
    /// doubled to reach the maximum interval (RFC 6206 uses this convention).
    pub fn new(imin_ms: u32, imax_doublings: u32, k: u32) -> Self {
        assert!(imin_ms > 0, "Trickle Imin must be non-zero");
        let max_interval = 1u32
            .checked_shl(imax_doublings)
            .and_then(|mult| imin_ms.checked_mul(mult))
            .unwrap_or(u32::MAX);
        Self {
            imin: imin_ms,
            max_interval,
            k,
            interval: imin_ms,
            counter: 0,
            interval_start: 0,
            transmit_time: 0,
            state: TrickleState::Stopped,
            transmitted: false,
        }
    }

    fn transition_to(&mut self, next: TrickleState) -> Result<(), InvalidTrickleTransition> {
        if self.state.can_transition_to(next) {
            self.state = next;
            Ok(())
        } else {
            Err(InvalidTrickleTransition {
                from: self.state,
                to: next,
            })
        }
    }

    /// Begin the first interval per RFC 6206 §4.2 rule 1 (I chosen in [Imin, Imax]).
    pub fn start(&mut self, now: u64, rand_offset: u32) {
        self.interval = self.imin;
        let r = self.begin_interval(now, rand_offset);
        debug_assert!(r.is_ok(), "stopped or active Trickle timer can begin an interval");
    }

    fn begin_interval(
        &mut self,
        now: u64,
        rand_offset: u32,
    ) -> Result<(), InvalidTrickleTransition> {
        if now.checked_add(u64::from(self.interval)).is_none() {
            return self.transition_to(TrickleState::Stopped);
        }
        self.interval_start = now;
        self.counter = 0;
        self.transmitted = false;
        // RFC 6206 §4.2 rule 2: t uniform in [I/2, I). Bitwise form is
        // bias-free for odd I and safe at u32::MAX (avoids overflow). Matches
        // C impl, tests, and Python equivalent.
        let half = (self.interval >> 1) + (self.interval & 1);
        let range = self.interval - half;
        let offset = if range > 0 { rand_offset % range } else { 0 };
        self.transmit_time = now
            .saturating_add(u64::from(half))
            .saturating_add(u64::from(offset));
        self.transition_to(TrickleState::WaitingTransmit)
    }

    /// Absolute time when the current interval ends.
    pub fn interval_end(&self) -> u64 {
        self.interval_start.saturating_add(u64::from(self.interval))
    }

    /// Record a consistent transmission (RFC 6206 §4.2 rule 3).
    pub fn heard_consistent(&mut self) {
        self.counter = self.counter.saturating_add(1);
    }

    /// Whether to transmit at t (counter < k per RFC 6206 §4.2 rule 4).
    pub fn should_transmit(&self) -> bool {
        self.counter < self.k
    }

    /// Mark the transmit point reached; returns `true` if a DIO should be sent.
    pub fn fire_transmit(&mut self) -> bool {
        let r = self.try_fire_transmit();
        debug_assert!(r.is_ok(), "fire_transmit only valid in WaitingTransmit state");
        r.unwrap()
    }

    pub fn try_fire_transmit(&mut self) -> Result<bool, InvalidTrickleTransition> {
        self.transition_to(TrickleState::WaitingExpire)?;
        self.transmitted = true;
        Ok(self.should_transmit())
    }

    /// End the current interval: double I (capped at Imax) and start next per RFC 6206 §4.2 rule 5.
    pub fn expire(&mut self, now: u64, rand_offset: u32) {
        let r = self.try_expire(now, rand_offset);
        debug_assert!(r.is_ok(), "expire only valid after transmit");
    }

    pub fn try_expire(
        &mut self,
        now: u64,
        rand_offset: u32,
    ) -> Result<(), InvalidTrickleTransition> {
        if self.state != TrickleState::WaitingExpire {
            return Err(InvalidTrickleTransition {
                from: self.state,
                to: TrickleState::WaitingTransmit,
            });
        }
        self.interval = self.interval.saturating_mul(2).min(self.max_interval);
        self.begin_interval(now, rand_offset)
    }

    /// Handle an inconsistency per RFC 6206 §4.2 rule 6: if Stopped or
    /// interval > imin, set I=imin and restart. No-op if at imin and running.
    /// State proxy for cross-impl (cf. C interval==0, Python generation==0).
    pub fn reset(&mut self, now: u64, rand_offset: u32) {
        let r = self.try_reset(now, rand_offset);
        debug_assert!(r.is_ok(), "invalid trickle timer transition");
    }

    pub fn try_reset(
        &mut self,
        now: u64,
        rand_offset: u32,
    ) -> Result<(), InvalidTrickleTransition> {
        if self.state == TrickleState::Stopped || self.interval > self.imin {
            self.interval = self.imin;
            self.begin_interval(now, rand_offset)?;
        }
        Ok(())
    }

    /// The next scheduled event.
    pub fn next_event(&self) -> TrickleEvent {
        if self.state == TrickleState::Stopped {
            TrickleEvent::Stopped
        } else if !self.transmitted {
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
        assert_eq!(t.state, TrickleState::Stopped);
        t.start(0, 0); // rand_offset=0 → transmit at 500ms
        assert_eq!(t.state, TrickleState::WaitingTransmit);
        assert_eq!(t.transmit_time, 500);
        assert_eq!(t.interval_end(), 1000);
        assert_eq!(t.next_event(), TrickleEvent::Transmit { at_ms: 500 });
    }

    #[test]
    fn fire_transmit_sets_next_event_to_expire() {
        let mut t = TrickleTimer::new(1000, 4, 10);
        t.start(0, 0);
        assert!(t.fire_transmit()); // c=0 < k=10 → should transmit
        assert_eq!(t.state, TrickleState::WaitingExpire);
        assert_eq!(t.next_event(), TrickleEvent::Expire { at_ms: 1000 });
    }

    #[test]
    fn checked_trickle_transitions_reject_repeated_transmit_and_early_expire() {
        let mut t = TrickleTimer::new(1000, 4, 10);
        assert_eq!(
            t.try_expire(0, 0),
            Err(InvalidTrickleTransition {
                from: TrickleState::Stopped,
                to: TrickleState::WaitingTransmit,
            })
        );

        t.start(0, 0);
        assert!(t.try_fire_transmit().unwrap());
        assert_eq!(
            t.try_fire_transmit(),
            Err(InvalidTrickleTransition {
                from: TrickleState::WaitingExpire,
                to: TrickleState::WaitingExpire,
            })
        );
    }

    #[test]
    fn heard_consistent_suppresses_transmit_when_ge_k() {
        let mut t = TrickleTimer::new(1000, 4, 2);
        t.start(0, 0);
        t.heard_consistent();
        t.heard_consistent(); // counter = 2 = k
        assert!(!t.should_transmit());
        assert!(!t.fire_transmit());
        t.counter = u32::MAX;
        t.heard_consistent();
        assert_eq!(t.counter, u32::MAX);
    }

    #[test]
    fn expire_doubles_interval_capped_at_max() {
        let mut t = TrickleTimer::new(1000, 2, 10); // max = 4000
        t.start(0, 0);
        t.fire_transmit();
        t.expire(1000, 0);
        assert_eq!(t.state, TrickleState::WaitingTransmit);
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
        t.reset(0, 999);
        assert_eq!(t.transmit_time, tt_before);
    }

    #[test]
    fn reset_from_stopped_starts_timer() {
        let mut t = TrickleTimer::new(1000, 4, 10);
        assert_eq!(t.state, TrickleState::Stopped);
        t.reset(0, 0);
        assert_eq!(t.state, TrickleState::WaitingTransmit);
        assert_eq!(t.interval, 1000);
    }

    #[test]
    fn rand_offset_shifts_transmit_time() {
        let mut t = TrickleTimer::new(1000, 4, 10);
        t.start(0, 200); // rand_offset=200 < range=500 → transmit at 700
        assert_eq!(t.transmit_time, 700);
    }

    #[test]
    fn odd_interval_bias_free_transmit_time() {
        // I=5 (odd): half=(5>>1)+(5&1)=3, range=2 → transmit in [now+3, now+5)
        // Matches C/Python; old `/ 2` was biased (only [2,4)). Safe at u32::MAX.
        let mut t = TrickleTimer::new(5, 0, 10); // no doublings
        t.start(0, 0);
        assert_eq!(t.transmit_time, 3);
        assert_eq!(t.interval_end(), 5);

        let mut t2 = TrickleTimer::new(5, 0, 10);
        t2.start(0, 1); // 1 % 2 = 1 → 0+3+1=4
        assert_eq!(t2.transmit_time, 4);
    }

    #[test]
    fn max_interval_saturates_on_overflow() {
        // imin=1000, doublings=31 → 1000 * 2^31 overflows u32
        // Bug: checked_shl doesn't detect this, would wrap to 0
        let t = TrickleTimer::new(1000, 31, 10);
        assert_eq!(t.max_interval, u32::MAX);

        // Also test shift count >= 32 (original checked_shl case)
        let t2 = TrickleTimer::new(1000, 32, 10);
        assert_eq!(t2.max_interval, u32::MAX);

        // Verify non-overflowing case still works
        let t3 = TrickleTimer::new(1000, 4, 10);
        assert_eq!(t3.max_interval, 16000);
    }

    #[test]
    #[should_panic(expected = "Trickle Imin must be non-zero")]
    fn new_rejects_zero_imin() {
        let _ = TrickleTimer::new(0, 4, 10);
    }

    #[test]
    fn interval_end_saturates_near_u32_max() {
        const WRAP: u64 = 0x1_0000_0000;
        // Test that interval_end uses saturating_add to avoid wraparound
        let mut t = TrickleTimer::new(1000, 4, 10);
        let near_max = WRAP - 500;
        t.start(near_max, 0);
        assert_eq!(t.interval_end(), WRAP + 500);
    }

    #[test]
    fn transmit_time_crosses_u32_boundary() {
        const WRAP: u64 = 0x1_0000_0000;
        let mut t = TrickleTimer::new(1000, 4, 10);
        let near_max = WRAP - 200;
        t.start(near_max, 100);
        assert_eq!(t.transmit_time, WRAP + 400);
    }

    #[test]
    fn clock_exhaustion_stops_timer() {
        let mut t = TrickleTimer::new(1000, 4, 10);
        t.start(u64::MAX - 999, 0);
        assert_eq!(t.next_event(), TrickleEvent::Stopped);
    }
}
