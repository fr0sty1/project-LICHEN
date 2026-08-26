// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! DAO transmission timing from LICHEN packet timing section 14.2.

use core::time::Duration;

/// Minimum initial DAO delay after joining, in milliseconds.
pub const DAO_INITIAL_DELAY_MIN_MS: u16 = 0;

/// Maximum initial DAO delay after joining, in milliseconds (inclusive).
pub const DAO_INITIAL_DELAY_MAX_MS: u16 = 2_000;

/// Retry delays for an unacknowledged DAO, indexed by zero-based attempt.
pub const DAO_RETRY_DELAYS_MS: [u64; 3] = [4_000, 8_000, 16_000];

/// Maximum number of DAO retries before the retry sequence is exhausted.
pub const DAO_RETRY_LIMIT: u8 = DAO_RETRY_DELAYS_MS.len() as u8;

/// DAO route soft-state lifetime, in seconds.
pub const DAO_SOFT_STATE_LIFETIME_SECONDS: u64 = 30 * 60;

/// Interval between successful DAO transmissions while a route remains valid.
///
/// Section 14.2 requires refreshing at half of the soft-state lifetime so the
/// next DAO is sent before the installed route can expire.
pub const DAO_REFRESH_INTERVAL_SECONDS: u64 = DAO_SOFT_STATE_LIFETIME_SECONDS / 2;

/// Interval between successful DAO transmissions while a route remains valid.
pub const DAO_REFRESH_INTERVAL: Duration = Duration::from_secs(DAO_REFRESH_INTERVAL_SECONDS);

const DAO_INITIAL_DELAY_OUTCOMES: u64 =
    DAO_INITIAL_DELAY_MAX_MS as u64 - DAO_INITIAL_DELAY_MIN_MS as u64 + 1;
const U32_OUTCOMES: u64 = u32::MAX as u64 + 1;
const ACCEPTANCE_LIMIT: u64 = U32_OUTCOMES - (U32_OUTCOMES % DAO_INITIAL_DELAY_OUTCOMES);

/// Map one uniformly random caller-supplied word to an initial DAO delay.
///
/// The returned delay is uniformly distributed over the inclusive
/// `0..=2000` millisecond range. Words in the small incomplete tail of the
/// `u32` domain return `None`; the caller must draw a fresh independent word
/// and retry. Rejecting that tail avoids the modulo bias that a direct `% 2001`
/// mapping would introduce.
#[must_use]
pub fn dao_initial_delay_ms(random_word: u32) -> Option<u16> {
    let random_word = u64::from(random_word);
    if random_word >= ACCEPTANCE_LIMIT {
        return None;
    }

    let offset = random_word % DAO_INITIAL_DELAY_OUTCOMES;
    Some(DAO_INITIAL_DELAY_MIN_MS + offset as u16)
}

/// Return the delay for a zero-based DAO retry attempt.
///
/// Attempt zero is the first retry and waits four seconds. Attempts one and
/// two wait eight and sixteen seconds respectively. All later attempts are
/// exhausted and return `None`.
#[must_use]
pub const fn dao_retry_delay_ms(attempt: u8) -> Option<u64> {
    match attempt {
        0 => Some(DAO_RETRY_DELAYS_MS[0]),
        1 => Some(DAO_RETRY_DELAYS_MS[1]),
        2 => Some(DAO_RETRY_DELAYS_MS[2]),
        _ => None,
    }
}

/// Return the duration for a zero-based DAO retry attempt.
#[must_use]
pub fn dao_retry_delay(attempt: u8) -> Option<Duration> {
    dao_retry_delay_ms(attempt).map(Duration::from_millis)
}

/// Return whether `attempts` completed or scheduled retries exhausts the
/// profile's retry budget.
#[must_use]
pub const fn dao_retry_exhausted(attempts: u8) -> bool {
    attempts >= DAO_RETRY_LIMIT
}

/// A DAO retry deadline could not be represented as a [`Duration`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaoRetryDeadlineOverflow;

/// Add a retry delay to a monotonic duration without saturating or wrapping.
///
/// `Ok(None)` means the retry budget is exhausted. An overflow is reported
/// separately so it cannot be mistaken for normal exhaustion.
pub fn checked_dao_retry_deadline(
    now: Duration,
    attempt: u8,
) -> Result<Option<Duration>, DaoRetryDeadlineOverflow> {
    let Some(delay) = dao_retry_delay(attempt) else {
        return Ok(None);
    };

    now.checked_add(delay)
        .map(Some)
        .ok_or(DaoRetryDeadlineOverflow)
}

/// A DAO refresh deadline could not be represented as a [`Duration`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaoRefreshDeadlineOverflow;

/// Calculate the next DAO refresh deadline without saturating or wrapping.
pub fn checked_dao_refresh_deadline(now: Duration) -> Result<Duration, DaoRefreshDeadlineOverflow> {
    now.checked_add(DAO_REFRESH_INTERVAL)
        .ok_or(DaoRefreshDeadlineOverflow)
}

/// Deadline state for periodic DAO refreshes.
///
/// The timer is initially inactive. A caller arms or reschedules it after a
/// successful DAO transmission, checks [`Self::is_due`] while the route is
/// valid, and calls [`Self::reset`] when that route becomes invalid. Scheduling
/// is based only on caller-supplied monotonic time, making the type suitable for
/// deterministic `no_std` environments.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DaoRefreshTimer {
    deadline: Option<Duration>,
}

impl DaoRefreshTimer {
    /// Construct an inactive refresh timer.
    #[must_use]
    pub const fn new() -> Self {
        Self { deadline: None }
    }

    /// Construct a timer scheduled one refresh interval after `now`.
    pub fn checked_start(now: Duration) -> Result<Self, DaoRefreshDeadlineOverflow> {
        Ok(Self {
            deadline: Some(checked_dao_refresh_deadline(now)?),
        })
    }

    /// Return the scheduled absolute deadline, or `None` when inactive.
    #[must_use]
    pub const fn deadline(&self) -> Option<Duration> {
        self.deadline
    }

    /// Return whether the timer has an active refresh deadline.
    #[must_use]
    pub const fn is_scheduled(&self) -> bool {
        self.deadline.is_some()
    }

    /// Return whether the refresh is due at `now`.
    ///
    /// An inactive timer is never due. A scheduled timer becomes due exactly
    /// at its deadline and remains due until reset or rescheduled.
    #[must_use]
    pub fn is_due(&self, now: Duration) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    /// Return the time remaining until refresh.
    ///
    /// This returns `None` for an inactive timer and zero at or after an active
    /// deadline.
    #[must_use]
    pub fn remaining(&self, now: Duration) -> Option<Duration> {
        self.deadline.map(|deadline| deadline.saturating_sub(now))
    }

    /// Schedule the next refresh one interval after `now`.
    ///
    /// Call this after each successful DAO transmission. If the deadline would
    /// overflow, the existing schedule is left unchanged.
    pub fn checked_reschedule(
        &mut self,
        now: Duration,
    ) -> Result<Duration, DaoRefreshDeadlineOverflow> {
        let deadline = checked_dao_refresh_deadline(now)?;
        self.deadline = Some(deadline);
        Ok(deadline)
    }

    /// Clear the deadline when there is no longer a valid route to refresh.
    pub const fn reset(&mut self) {
        self.deadline = None;
    }
}

/// State for one logical DAO's bounded retry sequence.
///
/// The counter records successfully consumed retry slots. A caller can peek
/// at [`Self::next_delay`] without changing state, or use
/// [`Self::checked_schedule_next`] to calculate a deadline and consume the
/// slot atomically. A deadline overflow leaves the state unchanged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DaoRetryBackoff {
    attempts: u8,
}

impl DaoRetryBackoff {
    /// Construct a fresh retry sequence whose next delay is four seconds.
    #[must_use]
    pub const fn new() -> Self {
        Self { attempts: 0 }
    }

    /// Number of retry slots already consumed.
    #[must_use]
    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    /// Whether all three retry slots have been consumed.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        dao_retry_exhausted(self.attempts)
    }

    /// Peek at the next retry delay without consuming it.
    #[must_use]
    pub fn next_delay(&self) -> Option<Duration> {
        dao_retry_delay(self.attempts)
    }

    /// Consume and return the next retry delay.
    ///
    /// Once exhausted, this remains exhausted and returns `None`.
    pub fn take_next_delay(&mut self) -> Option<Duration> {
        let delay = self.next_delay()?;
        self.attempts += 1;
        Some(delay)
    }

    /// Calculate and consume the next absolute retry deadline.
    ///
    /// The slot is consumed only after checked duration addition succeeds.
    /// `Ok(None)` means the retry sequence was already exhausted.
    pub fn checked_schedule_next(
        &mut self,
        now: Duration,
    ) -> Result<Option<Duration>, DaoRetryDeadlineOverflow> {
        let deadline = checked_dao_retry_deadline(now, self.attempts)?;
        if deadline.is_some() {
            self.attempts += 1;
        }
        Ok(deadline)
    }

    /// Reset for a new logical DAO.
    pub const fn reset(&mut self) {
        self.attempts = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_inclusive_timing_bounds() {
        assert_eq!(dao_initial_delay_ms(0), Some(0));
        assert_eq!(dao_initial_delay_ms(2_000), Some(2_000));
        assert_eq!(dao_initial_delay_ms(2_001), Some(0));
        assert_eq!(
            dao_initial_delay_ms((ACCEPTANCE_LIMIT - 1) as u32),
            Some(2_000)
        );
    }

    #[test]
    fn each_delay_has_a_deterministic_random_word() {
        for expected in DAO_INITIAL_DELAY_MIN_MS..=DAO_INITIAL_DELAY_MAX_MS {
            assert_eq!(dao_initial_delay_ms(u32::from(expected)), Some(expected));
        }
    }

    #[test]
    fn rejects_only_the_incomplete_tail() {
        assert_eq!(
            dao_initial_delay_ms((ACCEPTANCE_LIMIT - 1) as u32),
            Some(2_000)
        );

        for rejected in ACCEPTANCE_LIMIT..=u64::from(u32::MAX) {
            assert_eq!(dao_initial_delay_ms(rejected as u32), None);
        }
    }

    #[test]
    fn retry_attempts_follow_the_exact_profile_schedule() {
        assert_eq!(DAO_RETRY_DELAYS_MS, [4_000, 8_000, 16_000]);
        assert_eq!(dao_retry_delay_ms(0), Some(4_000));
        assert_eq!(dao_retry_delay_ms(1), Some(8_000));
        assert_eq!(dao_retry_delay_ms(2), Some(16_000));
        assert_eq!(dao_retry_delay_ms(3), None);
        assert_eq!(dao_retry_delay_ms(u8::MAX), None);

        assert!(!dao_retry_exhausted(0));
        assert!(!dao_retry_exhausted(2));
        assert!(dao_retry_exhausted(3));
        assert!(dao_retry_exhausted(u8::MAX));
    }

    #[test]
    fn state_consumes_three_retries_then_stays_exhausted() {
        let mut backoff = DaoRetryBackoff::new();
        let epoch = Duration::from_millis(100);

        assert_eq!(backoff.attempts(), 0);
        assert_eq!(backoff.next_delay(), Some(Duration::from_secs(4)));
        assert_eq!(
            backoff.checked_schedule_next(epoch),
            Ok(Some(Duration::from_millis(4_100)))
        );
        assert_eq!(
            backoff.checked_schedule_next(epoch),
            Ok(Some(Duration::from_millis(8_100)))
        );
        assert_eq!(
            backoff.checked_schedule_next(epoch),
            Ok(Some(Duration::from_millis(16_100)))
        );

        assert_eq!(backoff.attempts(), DAO_RETRY_LIMIT);
        assert!(backoff.is_exhausted());
        assert_eq!(backoff.next_delay(), None);
        assert_eq!(backoff.take_next_delay(), None);
        assert_eq!(backoff.checked_schedule_next(Duration::MAX), Ok(None));
        assert_eq!(backoff.attempts(), DAO_RETRY_LIMIT);
    }

    #[test]
    fn deadline_overflow_is_distinct_and_does_not_consume_attempt() {
        let mut backoff = DaoRetryBackoff::new();

        assert_eq!(
            backoff.checked_schedule_next(Duration::MAX),
            Err(DaoRetryDeadlineOverflow)
        );
        assert_eq!(backoff.attempts(), 0);
        assert_eq!(backoff.next_delay(), Some(Duration::from_secs(4)));

        let latest_safe = Duration::MAX
            .checked_sub(Duration::from_secs(4))
            .expect("four seconds is below Duration::MAX");
        assert_eq!(
            backoff.checked_schedule_next(latest_safe),
            Ok(Some(Duration::MAX))
        );
        assert_eq!(backoff.attempts(), 1);
    }

    #[test]
    fn reset_restores_the_first_retry() {
        let mut backoff = DaoRetryBackoff::new();
        assert_eq!(backoff.take_next_delay(), Some(Duration::from_secs(4)));
        assert_eq!(backoff.take_next_delay(), Some(Duration::from_secs(8)));

        backoff.reset();

        assert_eq!(backoff, DaoRetryBackoff::default());
        assert_eq!(backoff.attempts(), 0);
        assert!(!backoff.is_exhausted());
        assert_eq!(backoff.take_next_delay(), Some(Duration::from_secs(4)));
    }

    #[test]
    fn refresh_interval_is_half_the_soft_state_lifetime() {
        assert_eq!(DAO_SOFT_STATE_LIFETIME_SECONDS, 30 * 60);
        assert_eq!(DAO_REFRESH_INTERVAL_SECONDS, 15 * 60);
        assert_eq!(
            DAO_REFRESH_INTERVAL_SECONDS,
            DAO_SOFT_STATE_LIFETIME_SECONDS / 2
        );
        assert_eq!(DAO_REFRESH_INTERVAL, Duration::from_secs(15 * 60));
    }

    #[test]
    fn refresh_deadline_uses_the_exact_interval() {
        let now = Duration::from_millis(12_345);
        assert_eq!(
            checked_dao_refresh_deadline(now),
            Ok(Duration::from_millis(912_345))
        );
    }

    #[test]
    fn refresh_is_due_at_and_after_deadline_but_not_before() {
        let start = Duration::from_secs(100);
        let timer = DaoRefreshTimer::checked_start(start).expect("deadline fits");
        let deadline = start + DAO_REFRESH_INTERVAL;

        assert!(timer.is_scheduled());
        assert_eq!(timer.deadline(), Some(deadline));
        assert_eq!(
            timer.remaining(deadline - Duration::from_nanos(1)),
            Some(Duration::from_nanos(1))
        );
        assert!(!timer.is_due(deadline - Duration::from_nanos(1)));
        assert!(timer.is_due(deadline));
        assert!(timer.is_due(deadline + Duration::from_nanos(1)));
        assert_eq!(timer.remaining(deadline), Some(Duration::ZERO));
        assert_eq!(
            timer.remaining(deadline + Duration::from_secs(1)),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn refresh_reschedules_from_successful_transmission_time() {
        let start = Duration::from_secs(5);
        let mut timer = DaoRefreshTimer::checked_start(start).expect("deadline fits");
        let transmitted_at = start + DAO_REFRESH_INTERVAL + Duration::from_secs(7);

        assert!(timer.is_due(transmitted_at));
        let next = timer
            .checked_reschedule(transmitted_at)
            .expect("deadline fits");

        assert_eq!(next, transmitted_at + DAO_REFRESH_INTERVAL);
        assert_eq!(timer.deadline(), Some(next));
        assert!(!timer.is_due(transmitted_at));
    }

    #[test]
    fn refresh_reset_disarms_timer_until_route_is_valid_again() {
        let mut timer = DaoRefreshTimer::checked_start(Duration::ZERO).expect("deadline fits");
        timer.reset();

        assert_eq!(timer, DaoRefreshTimer::new());
        assert!(!timer.is_scheduled());
        assert_eq!(timer.deadline(), None);
        assert_eq!(timer.remaining(Duration::MAX), None);
        assert!(!timer.is_due(Duration::MAX));

        let deadline = timer
            .checked_reschedule(Duration::from_secs(1))
            .expect("deadline fits");
        assert_eq!(deadline, Duration::from_secs(1) + DAO_REFRESH_INTERVAL);
        assert!(timer.is_scheduled());
    }

    #[test]
    fn refresh_overflow_is_reported_without_changing_schedule() {
        assert_eq!(
            checked_dao_refresh_deadline(Duration::MAX),
            Err(DaoRefreshDeadlineOverflow)
        );
        assert_eq!(
            DaoRefreshTimer::checked_start(Duration::MAX),
            Err(DaoRefreshDeadlineOverflow)
        );

        let mut timer = DaoRefreshTimer::checked_start(Duration::ZERO).expect("deadline fits");
        let original = timer.deadline();
        assert_eq!(
            timer.checked_reschedule(Duration::MAX),
            Err(DaoRefreshDeadlineOverflow)
        );
        assert_eq!(timer.deadline(), original);

        let latest_safe = Duration::MAX
            .checked_sub(DAO_REFRESH_INTERVAL)
            .expect("refresh interval is below Duration::MAX");
        assert_eq!(timer.checked_reschedule(latest_safe), Ok(Duration::MAX));
        assert_eq!(timer.deadline(), Some(Duration::MAX));
    }
}
