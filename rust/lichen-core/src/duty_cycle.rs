//! Duty cycle tracking for regulatory compliance.
//!
//! EU 868 MHz and similar bands require duty cycle limits (typically 1% per
//! sub-band over a 1-hour rolling window). This module tracks transmission
//! history and provides methods to query remaining budget.
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

/// Rolling window duration in milliseconds (1 hour).
pub const WINDOW_MS: u64 = 3_600_000;

/// Default duty cycle limit as a fraction (1% = 0.01).
pub const DEFAULT_DUTY_CYCLE: f32 = 0.01;

/// Maximum TX time allowed per window at 1% duty cycle.
pub const MAX_TX_MS: u32 = (WINDOW_MS as f32 * DEFAULT_DUTY_CYCLE) as u32; // 36000ms

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
#[derive(Debug)]
pub struct DutyCycleTracker<const N: usize> {
    records: Deque<TxRecord, N>,
    duty_cycle: f32,
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
            duty_cycle: DEFAULT_DUTY_CYCLE,
        }
    }

    /// Create a new tracker with a custom duty cycle limit.
    ///
    /// # Arguments
    ///
    /// - `duty_cycle`: Duty cycle as a fraction (e.g., 0.01 for 1%, 0.10 for 10%).
    pub const fn with_duty_cycle(duty_cycle: f32) -> Self {
        Self {
            records: Deque::new(),
            duty_cycle,
        }
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
                let tx_end = record.timestamp_ms.saturating_add(record.duration_ms as u64);
                if tx_end > window_start {
                    let overlap = (tx_end - window_start) as u32;
                    total = total.saturating_add(overlap);
                }
            }
        }
        total
    }

    /// Returns remaining TX budget in milliseconds for the current window.
    ///
    /// # Arguments
    ///
    /// - `now_ms`: Current timestamp in milliseconds.
    pub fn remaining_ms(&mut self, now_ms: u64) -> u32 {
        self.evict_stale(now_ms);
        let max_tx = (WINDOW_MS as f32 * self.duty_cycle) as u32;
        let used = self.total_tx_in_window(now_ms);
        max_tx.saturating_sub(used)
    }

    /// Returns current duty cycle usage as a percentage (0.0 to 100.0+).
    ///
    /// Values over 100.0 indicate the node has exceeded its duty cycle limit.
    ///
    /// # Arguments
    ///
    /// - `now_ms`: Current timestamp in milliseconds.
    pub fn usage_percent(&mut self, now_ms: u64) -> f32 {
        self.evict_stale(now_ms);
        let used = self.total_tx_in_window(now_ms);
        (used as f32 / WINDOW_MS as f32) * 100.0
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

        let max_tx = (WINDOW_MS as f32 * self.duty_cycle) as u32;
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
        assert_eq!(tracker.remaining_ms(0), MAX_TX_MS);
        assert_eq!(tracker.usage_percent(0), 0.0);
    }

    #[test]
    fn record_tx_reduces_budget() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        tracker.record_tx(1000, 200);

        // Budget should be reduced by 200ms
        assert_eq!(tracker.remaining_ms(1000), MAX_TX_MS - 200);
    }

    #[test]
    fn usage_percent_calculation() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();

        // 36000ms is 1% of 3600000ms window
        tracker.record_tx(0, 36000);

        // Should show 1% usage
        let usage = tracker.usage_percent(0);
        assert!((usage - 1.0).abs() < 0.001);
    }

    #[test]
    fn records_age_out_after_window() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        tracker.record_tx(0, 200);

        // Just before window ends, record is still counted
        assert_eq!(tracker.remaining_ms(WINDOW_MS - 1), MAX_TX_MS - 200);

        // After window, record ages out (record ends at 200ms, ages out at WINDOW_MS + 200)
        assert_eq!(tracker.remaining_ms(WINDOW_MS + 201), MAX_TX_MS);
    }

    #[test]
    fn partial_record_in_window() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        // TX from 0-1000ms (1 second duration)
        tracker.record_tx(0, 1000);

        // At time WINDOW_MS + 500, only 500ms of the TX is in the window
        // Window starts at 500ms, TX ends at 1000ms, so 500ms overlap
        let remaining = tracker.remaining_ms(WINDOW_MS + 500);
        assert_eq!(remaining, MAX_TX_MS - 500);
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
        // Use up all budget
        tracker.record_tx(0, MAX_TX_MS);

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
        let next = tracker.next_tx_available_ms(0, MAX_TX_MS + 1);
        assert_eq!(next, u64::MAX);
    }

    #[test]
    fn multiple_records_accumulate() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        tracker.record_tx(0, 100);
        tracker.record_tx(1000, 100);
        tracker.record_tx(2000, 100);

        assert_eq!(tracker.remaining_ms(2000), MAX_TX_MS - 300);
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

        tracker.record_tx(0, MAX_TX_MS);
        assert!(!tracker.can_transmit(0, 1));
    }

    #[test]
    fn custom_duty_cycle() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::with_duty_cycle(0.10);

        // 10% duty cycle = 360000ms max
        let expected_max = (WINDOW_MS as f32 * 0.10) as u32;
        assert_eq!(tracker.remaining_ms(0), expected_max);
    }

    #[test]
    fn clear_resets_tracker() {
        let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
        tracker.record_tx(0, 1000);
        tracker.clear();

        assert_eq!(tracker.record_count(), 0);
        assert_eq!(tracker.remaining_ms(0), MAX_TX_MS);
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
        // That's 4440 / 3600000 = 0.12% duty cycle - well under 1%
        let usage = tracker.usage_percent(11 * interval_ms);
        assert!(usage < 0.2);
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
        assert_eq!(remaining, MAX_TX_MS - 5000);
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
            assert_eq!(remaining, MAX_TX_MS);
        }

        // Test 2: 1ms overlap at boundary - 1
        {
            let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
            tracker.record_tx(0, 100);

            // At WINDOW_MS + 99, window starts at 99, TX ends at 100
            // Overlap is 100 - 99 = 1ms
            let remaining = tracker.remaining_ms(WINDOW_MS + 99);
            assert_eq!(remaining, MAX_TX_MS - 1);
        }

        // Test 3: 50ms overlap
        {
            let mut tracker: DutyCycleTracker<64> = DutyCycleTracker::new();
            tracker.record_tx(0, 100);

            // At WINDOW_MS + 50, window starts at 50, TX ends at 100
            // Overlap is 100 - 50 = 50ms
            let remaining = tracker.remaining_ms(WINDOW_MS + 50);
            assert_eq!(remaining, MAX_TX_MS - 50);
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
        assert!((DEFAULT_DUTY_CYCLE - 0.01).abs() < 0.0001);
        assert_eq!(MAX_TX_MS, 36000);
    }
}
