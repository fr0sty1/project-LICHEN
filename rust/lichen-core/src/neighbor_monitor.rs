//! Neighbor duty cycle cheat detection.
//!
//! Monitors neighbors for regulatory duty cycle violations by tracking
//! observed transmissions. If we hear too many packets from a neighbor
//! within the rolling window, they are flagged as a cheater.
//!
//! # Heuristic
//!
//! At 1% duty cycle with 1-second airtime per packet, a neighbor can legally
//! transmit at most 36 packets per hour (36 seconds of airtime = 1% of 3600s).
//! Exceeding this threshold suggests the neighbor is violating duty cycle limits.
//!
//! # Example
//!
//! ```
//! use lichen_core::neighbor_monitor::NeighborMonitor;
//! use lichen_core::addr::NodeId;
//!
//! let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
//!
//! let neighbor = NodeId([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
//!
//! // Record packets heard from a neighbor
//! monitor.record_rx(neighbor, 1000);
//! monitor.record_rx(neighbor, 2000);
//!
//! // Check if they exceed duty cycle (they don't yet)
//! assert!(!monitor.check_neighbor_duty(neighbor, 3000));
//! ```

use crate::addr::NodeId;
use crate::duty_cycle::WINDOW_MS;
use heapless::Vec;

/// Default packet threshold: 36 packets per hour (1% duty at ~1s airtime each).
pub const DEFAULT_PACKET_THRESHOLD: u32 = 36;

/// A record of observed packet timestamps for a neighbor.
#[derive(Clone, Debug)]
pub struct NeighborTxLog<const L: usize> {
    /// The neighbor's address.
    pub addr: NodeId,
    /// Timestamps (ms) of observed packets within the rolling window.
    timestamps: Vec<u64, L>,
    /// Whether this neighbor has been flagged as a cheater.
    flagged: bool,
}

impl<const L: usize> NeighborTxLog<L> {
    /// Create a new log for a neighbor.
    pub fn new(addr: NodeId) -> Self {
        Self {
            addr,
            timestamps: Vec::new(),
            flagged: false,
        }
    }

    /// Record an observed packet at the given timestamp.
    ///
    /// Returns `true` if recorded, `false` if the buffer is full.
    pub fn record(&mut self, timestamp_ms: u64) -> bool {
        self.timestamps.push(timestamp_ms).is_ok()
    }

    fn window_start(now_ms: u64) -> u64 {
        now_ms.saturating_sub(WINDOW_MS)
    }

    /// Evict timestamps outside the rolling window.
    pub fn evict_stale(&mut self, now_ms: u64) {
        let window_start = Self::window_start(now_ms);
        self.timestamps.retain(|&ts| ts >= window_start);
    }

    /// Count packets within the current window.
    pub fn packet_count(&self, now_ms: u64) -> usize {
        let window_start = Self::window_start(now_ms);
        self.timestamps
            .iter()
            .filter(|&&ts| ts >= window_start)
            .count()
    }

    /// Check if flagged as a cheater.
    pub fn is_flagged(&self) -> bool {
        self.flagged
    }

    /// Flag this neighbor as a cheater.
    pub fn flag(&mut self) {
        self.flagged = true;
    }

    /// Clear the flagged status.
    pub fn unflag(&mut self) {
        self.flagged = false;
    }
}

/// Monitors multiple neighbors for duty cycle violations.
///
/// # Type Parameters
///
/// - `N`: Maximum number of neighbors to track.
/// - `L`: Maximum number of packet timestamps per neighbor.
#[derive(Debug)]
pub struct NeighborMonitor<const N: usize, const L: usize> {
    /// Logs for each tracked neighbor.
    neighbors: Vec<NeighborTxLog<L>, N>,
    /// Packet threshold for flagging (default: 36 packets/hour).
    threshold: u32,
}

impl<const N: usize, const L: usize> Default for NeighborMonitor<N, L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const L: usize> NeighborMonitor<N, L> {
    /// Create a new monitor with the default packet threshold (36/hour).
    pub const fn new() -> Self {
        Self {
            neighbors: Vec::new(),
            threshold: DEFAULT_PACKET_THRESHOLD,
        }
    }

    /// Create a new monitor with a custom packet threshold.
    ///
    /// # Arguments
    ///
    /// - `threshold`: Maximum packets per hour before flagging.
    pub const fn with_threshold(threshold: u32) -> Self {
        Self {
            neighbors: Vec::new(),
            threshold,
        }
    }

    /// Set the packet threshold.
    pub fn set_threshold(&mut self, threshold: u32) {
        self.threshold = threshold;
    }

    /// Get the current packet threshold.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Find or create a log entry for a neighbor.
    ///
    /// Returns `None` if the neighbor table is full and this is a new neighbor.
    fn get_or_create_log(&mut self, addr: NodeId) -> Option<&mut NeighborTxLog<L>> {
        // Find existing entry
        let idx = self.neighbors.iter().position(|n| n.addr == addr);

        if let Some(i) = idx {
            return Some(&mut self.neighbors[i]);
        }

        // Create new entry if space available
        let new_log = NeighborTxLog::new(addr);
        if self.neighbors.push(new_log).is_ok() {
            Some(self.neighbors.last_mut().unwrap())
        } else {
            None
        }
    }

    /// Find a log entry for a neighbor (immutable).
    fn get_log(&self, addr: NodeId) -> Option<&NeighborTxLog<L>> {
        self.neighbors.iter().find(|n| n.addr == addr)
    }

    /// Find a log entry for a neighbor (mutable).
    fn get_log_mut(&mut self, addr: NodeId) -> Option<&mut NeighborTxLog<L>> {
        self.neighbors.iter_mut().find(|n| n.addr == addr)
    }

    /// Record an observed packet from a neighbor.
    ///
    /// # Arguments
    ///
    /// - `addr`: The neighbor's address.
    /// - `now_ms`: Current timestamp in milliseconds.
    ///
    /// Returns `true` if recorded, `false` if the neighbor table or log is full.
    pub fn record_rx(&mut self, addr: NodeId, now_ms: u64) -> bool {
        if let Some(log) = self.get_or_create_log(addr) {
            log.evict_stale(now_ms);
            log.record(now_ms)
        } else {
            false
        }
    }

    /// Check if a neighbor exceeds the duty cycle threshold.
    ///
    /// # Arguments
    ///
    /// - `addr`: The neighbor's address.
    /// - `now_ms`: Current timestamp in milliseconds.
    ///
    /// Returns `true` if the neighbor has sent more than `threshold` packets
    /// within the rolling window (1 hour), indicating duty cycle violation.
    pub fn check_neighbor_duty(&mut self, addr: NodeId, now_ms: u64) -> bool {
        if let Some(log) = self.get_log_mut(addr) {
            log.evict_stale(now_ms);
            log.packet_count(now_ms) > self.threshold as usize
        } else {
            false
        }
    }

    /// Flag a neighbor as a cheater.
    ///
    /// # Arguments
    ///
    /// - `addr`: The neighbor's address.
    ///
    /// Returns `true` if the neighbor was found and flagged, `false` if unknown.
    pub fn flag_cheater(&mut self, addr: NodeId) -> bool {
        if let Some(log) = self.get_log_mut(addr) {
            log.flag();
            true
        } else {
            false
        }
    }

    /// Unflag a neighbor (give them another chance).
    ///
    /// # Arguments
    ///
    /// - `addr`: The neighbor's address.
    ///
    /// Returns `true` if the neighbor was found and unflagged.
    pub fn unflag_cheater(&mut self, addr: NodeId) -> bool {
        if let Some(log) = self.get_log_mut(addr) {
            log.unflag();
            true
        } else {
            false
        }
    }

    /// Get a list of all flagged cheaters.
    ///
    /// Returns a vector of NodeIds for all neighbors currently flagged.
    pub fn get_cheaters(&self) -> Vec<NodeId, N> {
        let mut cheaters = Vec::new();
        for log in self.neighbors.iter() {
            if log.is_flagged() {
                // Ignore push failure - just return what fits
                let _ = cheaters.push(log.addr);
            }
        }
        cheaters
    }

    /// Check if a specific neighbor is flagged as a cheater.
    pub fn is_cheater(&self, addr: NodeId) -> bool {
        self.get_log(addr).is_some_and(|log| log.is_flagged())
    }

    /// Get the packet count for a neighbor within the current window.
    ///
    /// Returns `None` if the neighbor is not tracked.
    pub fn packet_count(&mut self, addr: NodeId, now_ms: u64) -> Option<usize> {
        if let Some(log) = self.get_log_mut(addr) {
            log.evict_stale(now_ms);
            Some(log.packet_count(now_ms))
        } else {
            None
        }
    }

    /// Remove a neighbor from tracking.
    ///
    /// Returns `true` if the neighbor was found and removed.
    pub fn remove_neighbor(&mut self, addr: NodeId) -> bool {
        if let Some(idx) = self.neighbors.iter().position(|n| n.addr == addr) {
            self.neighbors.swap_remove(idx);
            true
        } else {
            false
        }
    }

    /// Get the number of tracked neighbors.
    pub fn neighbor_count(&self) -> usize {
        self.neighbors.len()
    }

    /// Clear all tracked neighbors.
    pub fn clear(&mut self) {
        self.neighbors.clear();
    }

    /// Automatically check and flag a neighbor if they exceed the threshold.
    ///
    /// This combines `record_rx`, `check_neighbor_duty`, and `flag_cheater`.
    ///
    /// # Arguments
    ///
    /// - `addr`: The neighbor's address.
    /// - `now_ms`: Current timestamp in milliseconds.
    ///
    /// Returns `true` if the neighbor was flagged (newly or already flagged).
    pub fn record_and_check(&mut self, addr: NodeId, now_ms: u64) -> bool {
        self.record_rx(addr, now_ms);
        if self.check_neighbor_duty(addr, now_ms) {
            self.flag_cheater(addr);
            true
        } else {
            self.is_cheater(addr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(id: u8) -> NodeId {
        NodeId([id, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn new_monitor_is_empty() {
        let monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        assert_eq!(monitor.neighbor_count(), 0);
        assert_eq!(monitor.threshold(), DEFAULT_PACKET_THRESHOLD);
    }

    #[test]
    fn record_rx_creates_neighbor() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        let addr = test_addr(1);

        assert!(monitor.record_rx(addr, 1000));
        assert_eq!(monitor.neighbor_count(), 1);
    }

    #[test]
    fn record_rx_increments_count() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        let addr = test_addr(1);

        monitor.record_rx(addr, 1000);
        monitor.record_rx(addr, 2000);
        monitor.record_rx(addr, 3000);

        assert_eq!(monitor.packet_count(addr, 4000), Some(3));
    }

    #[test]
    fn neighbor_below_threshold_is_not_flagged() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        let addr = test_addr(1);

        // Send 36 packets (exactly at threshold)
        for i in 0..36 {
            monitor.record_rx(addr, i as u64 * 100_000); // 100 seconds apart
        }

        // At threshold is OK (not exceeding)
        assert!(!monitor.check_neighbor_duty(addr, 36 * 100_000));
        assert!(!monitor.is_cheater(addr));
    }

    #[test]
    fn neighbor_exceeding_threshold_is_detected() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        let addr = test_addr(1);

        // Send 37 packets within the window (exceeds threshold of 36)
        // Use 90-second intervals so all 37 fit within 1 hour (37 * 90s = 3330s < 3600s)
        for i in 0..37 {
            monitor.record_rx(addr, i as u64 * 90_000);
        }

        // Check at the time of the last packet
        assert!(monitor.check_neighbor_duty(addr, 36 * 90_000));
    }

    #[test]
    fn flag_cheater_marks_neighbor() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        let addr = test_addr(1);

        monitor.record_rx(addr, 1000);
        assert!(!monitor.is_cheater(addr));

        assert!(monitor.flag_cheater(addr));
        assert!(monitor.is_cheater(addr));
    }

    #[test]
    fn flag_unknown_neighbor_returns_false() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        let addr = test_addr(1);

        assert!(!monitor.flag_cheater(addr));
    }

    #[test]
    fn get_cheaters_returns_flagged_only() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        let addr1 = test_addr(1);
        let addr2 = test_addr(2);
        let addr3 = test_addr(3);

        monitor.record_rx(addr1, 1000);
        monitor.record_rx(addr2, 1000);
        monitor.record_rx(addr3, 1000);

        monitor.flag_cheater(addr1);
        monitor.flag_cheater(addr3);

        let cheaters = monitor.get_cheaters();
        assert_eq!(cheaters.len(), 2);
        assert!(cheaters.contains(&addr1));
        assert!(cheaters.contains(&addr3));
        assert!(!cheaters.contains(&addr2));
    }

    #[test]
    fn unflag_cheater_clears_flag() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        let addr = test_addr(1);

        monitor.record_rx(addr, 1000);
        monitor.flag_cheater(addr);
        assert!(monitor.is_cheater(addr));

        assert!(monitor.unflag_cheater(addr));
        assert!(!monitor.is_cheater(addr));
    }

    #[test]
    fn packets_age_out_after_window() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        let addr = test_addr(1);

        // Send packets at time 0
        for i in 0..10 {
            monitor.record_rx(addr, i as u64 * 100);
        }

        assert_eq!(monitor.packet_count(addr, 1000), Some(10));

        // After window, all packets age out
        assert_eq!(monitor.packet_count(addr, WINDOW_MS + 1000), Some(0));
    }

    #[test]
    fn custom_threshold() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::with_threshold(10);
        let addr = test_addr(1);

        for i in 0..11 {
            monitor.record_rx(addr, i as u64 * 1000);
        }

        // 11 packets exceeds threshold of 10
        assert!(monitor.check_neighbor_duty(addr, 11_000));
    }

    #[test]
    fn set_threshold_changes_detection() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        let addr = test_addr(1);

        for i in 0..20 {
            monitor.record_rx(addr, i as u64 * 1000);
        }

        // 20 packets is under default threshold of 36
        assert!(!monitor.check_neighbor_duty(addr, 20_000));

        // Lower threshold to 15
        monitor.set_threshold(15);
        assert!(monitor.check_neighbor_duty(addr, 20_000));
    }

    #[test]
    fn remove_neighbor_clears_tracking() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        let addr = test_addr(1);

        monitor.record_rx(addr, 1000);
        monitor.flag_cheater(addr);

        assert_eq!(monitor.neighbor_count(), 1);
        assert!(monitor.is_cheater(addr));

        assert!(monitor.remove_neighbor(addr));
        assert_eq!(monitor.neighbor_count(), 0);
        assert!(!monitor.is_cheater(addr));
    }

    #[test]
    fn record_and_check_auto_flags() {
        let mut monitor: NeighborMonitor<8, 128> = NeighborMonitor::with_threshold(5);
        let addr = test_addr(1);

        // First 5 packets: not flagged
        for i in 0..5 {
            assert!(!monitor.record_and_check(addr, i as u64 * 1000));
        }

        // 6th packet exceeds threshold, gets flagged
        assert!(monitor.record_and_check(addr, 5000));
        assert!(monitor.is_cheater(addr));
    }

    #[test]
    fn multiple_neighbors_tracked_independently() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::with_threshold(5);
        let addr1 = test_addr(1);
        let addr2 = test_addr(2);

        // addr1: 10 packets (exceeds)
        for i in 0..10 {
            monitor.record_rx(addr1, i as u64 * 1000);
        }

        // addr2: 3 packets (under)
        for i in 0..3 {
            monitor.record_rx(addr2, i as u64 * 1000);
        }

        assert!(monitor.check_neighbor_duty(addr1, 10_000));
        assert!(!monitor.check_neighbor_duty(addr2, 10_000));
    }

    #[test]
    fn neighbor_table_full_rejects_new() {
        let mut monitor: NeighborMonitor<2, 64> = NeighborMonitor::new();

        assert!(monitor.record_rx(test_addr(1), 1000));
        assert!(monitor.record_rx(test_addr(2), 1000));
        // Table full
        assert!(!monitor.record_rx(test_addr(3), 1000));
        assert_eq!(monitor.neighbor_count(), 2);
    }

    #[test]
    fn log_buffer_full_rejects_new_timestamps() {
        let mut monitor: NeighborMonitor<8, 4> = NeighborMonitor::new();
        let addr = test_addr(1);

        assert!(monitor.record_rx(addr, 1000));
        assert!(monitor.record_rx(addr, 2000));
        assert!(monitor.record_rx(addr, 3000));
        assert!(monitor.record_rx(addr, 4000));
        // Log buffer full
        assert!(!monitor.record_rx(addr, 5000));
        assert_eq!(monitor.packet_count(addr, 5000), Some(4));
    }

    #[test]
    fn clear_removes_all_neighbors() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();

        monitor.record_rx(test_addr(1), 1000);
        monitor.record_rx(test_addr(2), 1000);
        monitor.flag_cheater(test_addr(1));

        monitor.clear();

        assert_eq!(monitor.neighbor_count(), 0);
        assert!(monitor.get_cheaters().is_empty());
    }

    #[test]
    fn default_impl() {
        let monitor: NeighborMonitor<8, 64> = NeighborMonitor::default();
        assert_eq!(monitor.neighbor_count(), 0);
        assert_eq!(monitor.threshold(), DEFAULT_PACKET_THRESHOLD);
    }

    #[test]
    fn check_unknown_neighbor_returns_false() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        assert!(!monitor.check_neighbor_duty(test_addr(99), 1000));
    }

    #[test]
    fn packet_count_unknown_neighbor_returns_none() {
        let mut monitor: NeighborMonitor<8, 64> = NeighborMonitor::new();
        assert_eq!(monitor.packet_count(test_addr(99), 1000), None);
    }

    #[test]
    fn realistic_scenario_honest_neighbor() {
        let mut monitor: NeighborMonitor<16, 128> = NeighborMonitor::new();
        let neighbor = test_addr(42);

        // Simulate honest neighbor: 1 packet every 5 minutes for an hour
        // That's 12 packets/hour, well under 36 threshold
        let interval_ms = 5 * 60 * 1000u64;
        for i in 0..12 {
            let is_cheater = monitor.record_and_check(neighbor, i * interval_ms);
            assert!(
                !is_cheater,
                "Honest neighbor wrongly flagged at packet {}",
                i
            );
        }

        assert_eq!(monitor.packet_count(neighbor, 12 * interval_ms), Some(12));
    }

    #[test]
    fn realistic_scenario_cheating_neighbor() {
        let mut monitor: NeighborMonitor<16, 128> = NeighborMonitor::new();
        let neighbor = test_addr(66);

        // Simulate cheater: 1 packet every minute for an hour
        // That's 60 packets/hour, way over 36 threshold
        let interval_ms = 60 * 1000u64;
        let mut flagged_at = None;

        for i in 0..60 {
            let is_cheater = monitor.record_and_check(neighbor, i * interval_ms);
            if is_cheater && flagged_at.is_none() {
                flagged_at = Some(i);
            }
        }

        // Should have been flagged around packet 37
        assert!(flagged_at.is_some());
        assert_eq!(flagged_at, Some(36)); // 37th packet (index 36) exceeds 36
        assert!(monitor.is_cheater(neighbor));
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(DEFAULT_PACKET_THRESHOLD, 36);
    }
}
