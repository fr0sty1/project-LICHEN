//! Duty cycle tracking for regulatory compliance (CCP-16 integration).
//!
//! EU 868 MHz and similar bands require duty cycle limits (typically 1% per
//! sub-band over a 1-hour rolling window). This module tracks transmission
//! history and provides methods to query remaining budget. Adaptive logic
//! respects density from RPL DIOs per worker8 CCP-16 changes.
//!
//! # Fixed-Point Representation
//!
//! Duty cycle is expressed in permille (parts per thousand) to avoid floating
//! point on soft-float embedded targets. 1% = 10 permille, 0.1% = 1 permille.
//!
//! # Example
//!
//! ```
//! use lichen_core::duty_cycle::DutyCycleTracker;
//!
//! let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
//!
//! // Record a 200ms transmission at time 1000ms
//! tracker.record_tx(1000, 200);
//!
//! // Check remaining budget at time 2000ms
//! let remaining = tracker.remaining_ms(2000);
//! assert!(remaining > 0);
//! ```

use heapless::Deque;

pub const WINDOW_MS: u64 = 3_600_000;
pub const DEFAULT_DUTY_PERMILLE: u16 = 10;
pub const REGION_EU: u8 = 0;
pub const REGION_US: u8 = 1;
pub const REGION_AS: u8 = 2;

pub fn adaptive_duty_permille(density: u8, region: u8) -> u16 {
    let base = match region {
        REGION_EU => 10,
        REGION_US => 1000,
        _ => DEFAULT_DUTY_PERMILLE,
    };
    if density > 8 {
        if base > 1 {
            base / 2
        } else {
            1
        }
    } else if density < 3 {
        (base * 2).min(1000)
    } else {
        base
    }
}

/// A transmission record: (timestamp_ms, duration_ms).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxRecord {
    /// Timestamp when transmission started (milliseconds since epoch or boot).
    pub timestamp_ms: u64,
    /// Duration of the transmission in milliseconds.
    pub duration_ms: u32,
}

/// Tracks transmission history for duty cycle compliance.
///
/// Uses a ring buffer to store recent transmissions. Old records outside the
/// rolling window are lazily evicted when querying or recording.
///
/// # Type Parameter
///
/// - `N`: Maximum number of TX records to store. Should be sized for expected
///   traffic. At 1 packet/second with 200ms airtime, 64 entries covers ~13s
///   of history; for a full hour at this rate you'd need ~3600 entries, but
///   in practice LoRa nodes transmit much less frequently.
///
/// # Time Monotonicity
///
/// All methods that take `now_ms` assume time is monotonically increasing.
/// If time goes backwards (clock rollback, wrap, or test error), behavior is
/// undefined: records with future timestamps won't be evicted and budget
/// calculations will be incorrect. Callers must ensure monotonic timestamps.
#[derive(Debug)]
pub struct DutyCycleTracker<const N: usize> {
    records: Deque<TxRecord, N>,
    /// Duty cycle limit in permille (1% = 10, 0.1% = 1).
    duty_permille: u16,
    /// Last timestamp passed to any public method, for monotonicity checks.
    last_now: u64,
}

impl<const N: usize> Default for DutyCycleTracker<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DutyCycleTracker<N> {
    /// Create a new tracker with the default 1% duty cycle.
    pub const fn new() -> Self {
        Self {
            records: Deque::new(),
            duty_permille: DEFAULT_DUTY_PERMILLE,
            last_now: 0,
        }
    }

    /// Create a new tracker with a custom duty cycle limit in permille.
    ///
    /// # Arguments
    ///
    /// - `duty_permille`: Duty cycle in permille (e.g., 10 for 1%, 100 for 10%).
    ///
    /// # Panics
    ///
    /// Debug builds panic if `duty_permille` is 0 or > 1000 (invalid duty cycle).
    pub const fn with_duty_permille(duty_permille: u16) -> Self {
        debug_assert!(duty_permille > 0, "duty_permille must be > 0");
        debug_assert!(
            duty_permille <= 1000,
            "duty_permille must be <= 1000 (100%)"
        );
        Self {
            records: Deque::new(),
            duty_permille,
            last_now: 0,
        }
    }

    pub fn set_from_density(&mut self, density: u8, region: u8) {
        self.duty_permille = adaptive_duty_permille(density, region);
    }

    /// Record a transmission.
    ///
    /// # Arguments
    ///
    /// - `timestamp_ms`: When the transmission started.
    /// - `duration_ms`: How long the transmission lasted.
    ///
    /// Returns `true` if the record was added, `false` if the buffer is full
    /// (after evicting stale records). A full buffer indicates the node is
    /// transmitting faster than expected for duty cycle compliance.
    pub fn record_tx(&mut self, timestamp_ms: u64, duration_ms: u32) -> bool {
        // Evict records outside the window
        self.evict_stale(timestamp_ms);

        // Try to add the new record
        let record = TxRecord {
            timestamp_ms,
            duration_ms,
        };
        self.records.push_back(record).is_ok()
    }

    /// Calculate total TX time within the current window.
    fn total_tx_in_window(&self, now_ms: u64) -> u32 {
        let window_start = now_ms.saturating_sub(WINDOW_MS);
        let mut total: u32 = 0;

        for record in self.records.iter() {
            if record.timestamp_ms >= window_start {
                // Entire transmission is within window
                total = total.saturating_add(record.duration_ms);
            } else {
                // Transmission started before window - count only the portion within
                let tx_end = record
                    .timestamp_ms
                    .saturating_add(record.duration_ms as u64);
                if tx_end > window_start {
                    let overlap = (tx_end - window_start) as u32;
                    total = total.saturating_add(overlap);
                }
            }
        }
        total
    }

    #[inline]
    pub fn max_tx_ms(&self) -> u32 {
        (WINDOW_MS as u32 / 1000) * (self.duty_permille as u32)
    }

    /// Returns remaining TX budget in milliseconds for the current window.
    ///
    /// # Arguments
    ///
    /// - `now_ms`: Current timestamp in milliseconds.
    pub fn remaining_ms(&mut self, now_ms: u64) -> u32 {
        self.evict_stale(now_ms);
        let max_tx = self.max_tx_ms();
        let used = self.total_tx_in_window(now_ms);
        max_tx.saturating_sub(used)
    }

    /// Returns current duty cycle usage in permille (0 to 1000+).
    ///
    /// Values over the configured limit indicate the node has exceeded its
    /// duty cycle. For 1% duty cycle, 10 = at limit, >10 = over limit.
    ///
    /// # Arguments
    ///
    /// - `now_ms`: Current timestamp in milliseconds.
    pub fn usage_permille(&mut self, now_ms: u64) -> u16 {
        self.evict_stale(now_ms);
        let used = self.total_tx_in_window(now_ms);
        // used_permille = (used * 1000) / WINDOW_MS
        // Use u64 to avoid overflow
        ((used as u64) * 1000 / WINDOW_MS) as u16
    }

    /// Returns when a transmission of the given duration will be allowed.
    ///
    /// If a transmission is allowed now, returns `now_ms`. Otherwise returns
    /// the earliest timestamp when enough budget will be available.
    ///
    /// # Arguments
    ///
    /// - `now_ms`: Current timestamp in milliseconds.
    /// - `duration_ms`: Desired transmission duration.
    pub fn next_tx_available_ms(&mut self, now_ms: u64, duration_ms: u32) -> u64 {
        self.evict_stale(now_ms);

        let max_tx = self.max_tx_ms();
        let used = self.total_tx_in_window(now_ms);

        // If we have enough budget now, return immediately
        if used.saturating_add(duration_ms) <= max_tx {
            return now_ms;
        }

        // Need to wait for old transmissions to age out of the window.
        // Find how much excess we have and when it will clear.
        let needed = used.saturating_add(duration_ms).saturating_sub(max_tx);
        let mut freed: u32 = 0;

        // Records are in chronological order. Find when enough will have aged out.
        for record in self.records.iter() {
            freed = freed.saturating_add(record.duration_ms);
            if freed >= needed {
                // This record aging out frees enough budget.
                // It ages out when: record.timestamp_ms + WINDOW_MS
                return record.timestamp_ms.saturating_add(WINDOW_MS);
            }
        }

        // Edge case: even with all records aged out, still not enough budget.
        // This means duration_ms > max_tx (impossible to ever send).
        // Return a far-future time to indicate "never" (caller should check).
        u64::MAX
    }

    /// Check if a transmission of the given duration is allowed now.
    ///
    /// # Arguments
    ///
    /// - `now_ms`: Current timestamp in milliseconds.
    /// - `duration_ms`: Desired transmission duration.
    pub fn can_transmit(&mut self, now_ms: u64, duration_ms: u32) -> bool {
        self.remaining_ms(now_ms) >= duration_ms
    }

    /// Remove records that are entirely outside the rolling window.
    fn evict_stale(&mut self, now_ms: u64) {
        debug_assert!(
            now_ms >= self.last_now,
            "time went backwards: last_now={}, now_ms={}",
            self.last_now,
            now_ms
        );
        self.last_now = now_ms;
        let window_start = now_ms.saturating_sub(WINDOW_MS);

        // Pop records from the front while they're completely outside the window
        while let Some(front) = self.records.front() {
            let tx_end = front.timestamp_ms.saturating_add(front.duration_ms as u64);
            if tx_end <= window_start {
                self.records.pop_front();
            } else {
                break;
            }
        }
    }

    /// Returns the number of TX records currently stored.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Clear all records.
    pub fn clear(&mut self) {
        self.records.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tracker_has_full_budget() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        assert_eq!(tracker.remaining_ms(0), tracker.max_tx_ms());
        assert_eq!(tracker.usage_permille(0), 0);
    }

    #[test]
    fn record_tx_reduces_budget() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        tracker.record_tx(1000, 200);

        // Budget should be reduced by 200ms
        assert_eq!(tracker.remaining_ms(1000), tracker.max_tx_ms() - 200);
    }

    #[test]
    fn usage_permille_calculation() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();

        // 36000ms is 1% of 3600000ms window = 10 permille
        tracker.record_tx(0, 36000);

        // Should show 10 permille (1%)
        let usage = tracker.usage_permille(0);
        assert_eq!(usage, 10);
    }

    #[test]
    fn records_age_out_after_window() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        tracker.record_tx(0, 200);

        // Just before window ends, record is still counted
        assert_eq!(
            tracker.remaining_ms(WINDOW_MS - 1),
            tracker.max_tx_ms() - 200
        );

        // After window, record ages out (record ends at 200ms, ages out at WINDOW_MS + 200)
        assert_eq!(tracker.remaining_ms(WINDOW_MS + 201), tracker.max_tx_ms());
    }

    #[test]
    fn partial_record_in_window() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        // TX from 0-1000ms (1 second duration)
        tracker.record_tx(0, 1000);

        // At time WINDOW_MS + 500, only 500ms of the TX is in the window
        // Window starts at 500ms, TX ends at 1000ms, so 500ms overlap
        let remaining = tracker.remaining_ms(WINDOW_MS + 500);
        assert_eq!(remaining, tracker.max_tx_ms() - 500);
    }

    #[test]
    fn next_tx_available_when_budget_exists() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        tracker.record_tx(0, 100);

        // Should be able to transmit immediately
        let next = tracker.next_tx_available_ms(1000, 200);
        assert_eq!(next, 1000);
    }

    #[test]
    fn next_tx_available_when_budget_exhausted() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        let max_tx = tracker.max_tx_ms();
        // Use up all budget
        tracker.record_tx(0, max_tx);

        // Can't transmit now
        assert!(!tracker.can_transmit(1000, 200));

        // Should have to wait until the first record ages out
        let next = tracker.next_tx_available_ms(1000, 200);
        assert_eq!(next, WINDOW_MS); // Original TX at 0 ages out at WINDOW_MS
    }

    #[test]
    fn next_tx_available_for_impossible_duration() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();

        // Asking for more than max budget
        let next = tracker.next_tx_available_ms(0, tracker.max_tx_ms() + 1);
        assert_eq!(next, u64::MAX);
    }

    #[test]
    fn multiple_records_accumulate() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        tracker.record_tx(0, 100);
        tracker.record_tx(1000, 100);
        tracker.record_tx(2000, 100);

        assert_eq!(tracker.remaining_ms(2000), tracker.max_tx_ms() - 300);
        assert_eq!(tracker.record_count(), 3);
    }

    #[test]
    fn eviction_removes_old_records() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        tracker.record_tx(0, 100);
        tracker.record_tx(WINDOW_MS / 2, 100);

        assert_eq!(tracker.record_count(), 2);

        // After first record ages out (at WINDOW_MS + 100)
        tracker.remaining_ms(WINDOW_MS + 101);
        assert_eq!(tracker.record_count(), 1);
    }

    #[test]
    fn can_transmit_check() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        assert!(tracker.can_transmit(0, 200));

        let max_tx = tracker.max_tx_ms();
        tracker.record_tx(0, max_tx);
        assert!(!tracker.can_transmit(0, 1));
    }

    #[test]
    fn custom_duty_permille() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::with_duty_permille(100);

        let expected_max = (WINDOW_MS as u32 / 1000) * (100u16 as u32);
        assert_eq!(tracker.remaining_ms(0), expected_max);
        assert_eq!(tracker.max_tx_ms(), expected_max);
    }

    #[test]
    fn clear_resets_tracker() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        tracker.record_tx(0, 1000);
        tracker.clear();

        assert_eq!(tracker.record_count(), 0);
        assert_eq!(tracker.remaining_ms(0), tracker.max_tx_ms());
    }

    #[test]
    fn buffer_full_returns_false() {
        let mut tracker: DutyCycleTracker<4> = DutyCycleTracker::new();
        assert!(tracker.record_tx(0, 100));
        assert!(tracker.record_tx(1, 100));
        assert!(tracker.record_tx(2, 100));
        assert!(tracker.record_tx(3, 100));
        // Buffer is now full
        assert!(!tracker.record_tx(4, 100));
    }

    #[test]
    fn saturating_arithmetic_handles_overflow() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();

        // Extremely large timestamp near u64::MAX
        let now = u64::MAX - 1000;
        tracker.record_tx(now, 100);

        // Should not panic
        let remaining = tracker.remaining_ms(now);
        assert!(remaining > 0);
    }

    #[test]
    fn typical_lora_usage_pattern() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        tracker.set_from_density(5, REGION_EU);

        // Simulate typical LoRa usage: 60-byte packets at SF10/125kHz ~ 370ms airtime
        // Send one packet every 5 minutes (well within 1% duty cycle)
        let airtime_ms = 370u32;
        let interval_ms = 5 * 60 * 1000u64; // 5 minutes

        for i in 0..12 {
            // One hour of traffic
            let timestamp = i * interval_ms;
            assert!(tracker.can_transmit(timestamp, airtime_ms));
            tracker.record_tx(timestamp, airtime_ms);
        }

        // After 12 packets in one hour: 12 * 370ms = 4440ms
        // That's 4440 / 3600000 = 0.12% duty cycle = ~1.2 permille - well under 10 permille (1%)
        let usage = tracker.usage_permille(11 * interval_ms);
        assert!(usage < 2);
    }

    #[test]
    fn stress_test_high_traffic() {
        let mut tracker: DutyCycleTracker<256> = DutyCycleTracker::new();

        // Send 100 packets over 10 seconds (unrealistic but tests robustness)
        for i in 0..100 {
            let timestamp = i * 100; // Every 100ms
            tracker.record_tx(timestamp, 50);
        }

        // Total TX: 100 * 50 = 5000ms
        let remaining = tracker.remaining_ms(10000);
        assert_eq!(remaining, tracker.max_tx_ms() - 5000);
    }

    #[test]
    fn window_boundary_edge_case() {
        // Test 1: Record fully ages out at exactly window boundary
        {
            let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
            // TX starts at 0, duration 100, ends at 100
            tracker.record_tx(0, 100);

            // At WINDOW_MS + 100, window starts at 100, TX ends at 100
            // tx_end (100) <= window_start (100), so no overlap
            let remaining = tracker.remaining_ms(WINDOW_MS + 100);
            assert_eq!(remaining, tracker.max_tx_ms());
        }

        // Test 2: 1ms overlap at boundary - 1
        {
            let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
            tracker.record_tx(0, 100);

            // At WINDOW_MS + 99, window starts at 99, TX ends at 100
            // Overlap is 100 - 99 = 1ms
            let remaining = tracker.remaining_ms(WINDOW_MS + 99);
            assert_eq!(remaining, tracker.max_tx_ms() - 1);
        }

        // Test 3: 50ms overlap
        {
            let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
            tracker.record_tx(0, 100);

            // At WINDOW_MS + 50, window starts at 50, TX ends at 100
            // Overlap is 100 - 50 = 50ms
            let remaining = tracker.remaining_ms(WINDOW_MS + 50);
            assert_eq!(remaining, tracker.max_tx_ms() - 50);
        }
    }

    #[test]
    fn default_impl() {
        let tracker: DutyCycleTracker<64> = DutyCycleTracker::default();
        assert_eq!(tracker.record_count(), 0);
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(WINDOW_MS, 3_600_000);
        assert_eq!(DEFAULT_DUTY_PERMILLE, 10);
        let tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        assert_eq!(
            tracker.max_tx_ms(),
            (WINDOW_MS as u32 / 1000) * (DEFAULT_DUTY_PERMILLE as u32)
        );
    }

    #[test]
    fn adaptive_duty_density() {
        assert_eq!(adaptive_duty_permille(0, REGION_EU), 20);
        assert_eq!(adaptive_duty_permille(10, REGION_EU), 5);
        assert_eq!(adaptive_duty_permille(5, REGION_EU), 10);
        assert_eq!(adaptive_duty_permille(10, REGION_US), 500);
        assert_eq!(adaptive_duty_permille(10, 255), 5);
    }
}
