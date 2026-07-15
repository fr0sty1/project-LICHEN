//! Forwarding buffer with per-source backpressure (spec appendix-bufferbloat.md).
//!
//! Relay nodes buffer packets for forwarding. Per-source limits prevent one
//! chatty node from monopolizing relay capacity. When a source exceeds its
//! quota, packets are rejected with [`ForwardError::QueueFull`] and a NACK
//! should be sent upstream.
//!
//! ```text
//! MAX_FORWARDING_SOURCES = 8
//! MAX_PACKETS_PER_SOURCE = 2
//! Total forwarding buffer: 16 packets max
//! ```

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Maximum number of distinct sources tracked in forwarding buffer.
pub const MAX_FORWARDING_SOURCES: usize = 8;

/// Maximum packets buffered per source (backpressure limit).
pub const MAX_PACKETS_PER_SOURCE: usize = 2;

/// Error returned when forwarding buffer operations fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForwardError {
    /// Source has reached MAX_PACKETS_PER_SOURCE limit.
    /// A NACK should be sent upstream.
    QueueFull,
    /// No packet found for the given source or criteria.
    NotFound,
}

impl core::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::QueueFull => write!(f, "forwarding queue full for source"),
            Self::NotFound => write!(f, "no packet found"),
        }
    }
}

impl core::error::Error for ForwardError {}

/// A packet queued for forwarding.
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct ForwardEntry {
    /// Raw IPv6 packet data.
    pub packet: Vec<u8>,
    /// Source IID (8-byte Interface Identifier from L2 sender).
    pub source_iid: [u8; 8],
    /// Monotonic timestamp when queued (ms).
    pub queued_at_ms: u32,
    /// Optional deadline (monotonic ms). Packets past deadline are dropped.
    pub deadline_ms: Option<u32>,
    /// Priority (0=highest, 3=lowest per spec).
    pub priority: u8,
}

#[cfg(feature = "std")]
impl ForwardEntry {
    /// Check if this entry has expired.
    ///
    /// Returns `true` if `now_ms` is past the deadline. Packets are valid
    /// at their exact deadline time and expire only afterwards.
    pub fn is_expired(&self, now_ms: u32) -> bool {
        if let Some(deadline) = self.deadline_ms {
            // Handle wraparound: expired if now is strictly past deadline
            // elapsed > 0 means we're past the deadline
            // elapsed < 0x8000_0000 means we haven't wrapped around backwards
            let elapsed = now_ms.wrapping_sub(deadline);
            elapsed > 0 && elapsed < 0x8000_0000
        } else {
            false
        }
    }
}

/// Per-source forwarding buffer with backpressure.
///
/// Tracks packets by source IID and enforces per-source limits to prevent
/// any single node from monopolizing forwarding capacity.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct ForwardBuffer {
    entries: Vec<ForwardEntry>,
}

#[cfg(feature = "std")]
impl ForwardBuffer {
    /// Create an empty forwarding buffer.
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_FORWARDING_SOURCES * MAX_PACKETS_PER_SOURCE),
        }
    }

    /// Queue a packet for forwarding.
    ///
    /// # Errors
    ///
    /// Returns [`ForwardError::QueueFull`] if the source already has
    /// `MAX_PACKETS_PER_SOURCE` packets queued. The caller SHOULD send
    /// a NACK upstream when this occurs.
    pub fn queue(
        &mut self,
        packet: Vec<u8>,
        source_iid: [u8; 8],
        now_ms: u32,
        deadline_ms: Option<u32>,
        priority: u8,
    ) -> Result<(), ForwardError> {
        // Expire old packets first
        self.expire(now_ms);

        // Check per-source limit
        let source_count = self.count_for_source(&source_iid);
        if source_count >= MAX_PACKETS_PER_SOURCE {
            return Err(ForwardError::QueueFull);
        }

        // Check total sources if adding a new one
        if source_count == 0 {
            let distinct_sources = self.distinct_source_count();
            if distinct_sources >= MAX_FORWARDING_SOURCES {
                // Evict oldest packet from the source with the oldest packet overall
                self.evict_oldest_source_packet();
            }
        }

        self.entries.push(ForwardEntry {
            packet,
            source_iid,
            queued_at_ms: now_ms,
            deadline_ms,
            priority,
        });

        Ok(())
    }

    /// Dequeue the highest-priority packet (lowest priority number, then oldest).
    ///
    /// Returns the packet, or `None` if the buffer is empty.
    pub fn dequeue(&mut self, now_ms: u32) -> Option<ForwardEntry> {
        self.expire(now_ms);

        if self.entries.is_empty() {
            return None;
        }

        // Find best entry: lowest priority value, then oldest
        let best_idx = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| (e.priority, e.queued_at_ms))
            .map(|(i, _)| i)?;

        Some(self.entries.swap_remove(best_idx))
    }

    /// Dequeue the next packet for a specific source (oldest first).
    pub fn dequeue_for_source(
        &mut self,
        source_iid: &[u8; 8],
        now_ms: u32,
    ) -> Option<ForwardEntry> {
        self.expire(now_ms);

        let idx = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.source_iid == *source_iid)
            .min_by_key(|(_, e)| e.queued_at_ms)
            .map(|(i, _)| i)?;

        Some(self.entries.swap_remove(idx))
    }

    /// Count packets queued for a specific source.
    pub fn count_for_source(&self, source_iid: &[u8; 8]) -> usize {
        self.entries
            .iter()
            .filter(|e| e.source_iid == *source_iid)
            .count()
    }

    /// Count distinct sources currently in the buffer.
    pub fn distinct_source_count(&self) -> usize {
        let mut seen = [[0u8; 8]; MAX_FORWARDING_SOURCES];
        let mut count = 0;

        for entry in &self.entries {
            if !seen[..count].contains(&entry.source_iid) && count < MAX_FORWARDING_SOURCES {
                seen[count] = entry.source_iid;
                count += 1;
            }
        }

        count
    }

    /// Total number of packets in the buffer.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove all expired packets. Returns count removed.
    pub fn expire(&mut self, now_ms: u32) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| !e.is_expired(now_ms));
        before - self.entries.len()
    }

    /// Clear all packets for a source (e.g., on link failure).
    pub fn clear_source(&mut self, source_iid: &[u8; 8]) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.source_iid != *source_iid);
        before - self.entries.len()
    }

    /// Clear all packets.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get buffer statistics.
    pub fn stats(&self) -> ForwardStats {
        let total_packets = self.entries.len();
        let distinct_sources = self.distinct_source_count();
        let oldest_ms = self.entries.iter().map(|e| e.queued_at_ms).min();

        ForwardStats {
            total_packets,
            distinct_sources,
            oldest_queued_ms: oldest_ms,
        }
    }

    /// Evict the oldest packet overall (used when source limit reached).
    fn evict_oldest_source_packet(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        let oldest_idx = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.queued_at_ms)
            .map(|(i, _)| i)
            .unwrap_or(0);

        self.entries.swap_remove(oldest_idx);
    }
}

#[cfg(feature = "std")]
impl Default for ForwardBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Forwarding buffer statistics for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardStats {
    /// Total packets currently queued.
    pub total_packets: usize,
    /// Number of distinct sources with queued packets.
    pub distinct_sources: usize,
    /// Timestamp of oldest queued packet (if any).
    pub oldest_queued_ms: Option<u32>,
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;
    use std::vec::Vec;

    fn make_iid(v: u8) -> [u8; 8] {
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, v]
    }

    fn make_packet(id: u8) -> Vec<u8> {
        vec![id; 100]
    }

    #[test]
    fn queue_and_dequeue_basic() {
        let mut buf = ForwardBuffer::new();
        let iid = make_iid(1);
        let pkt = make_packet(0xAA);

        buf.queue(pkt.clone(), iid, 1000, None, 3).unwrap();

        assert_eq!(buf.len(), 1);
        assert_eq!(buf.count_for_source(&iid), 1);

        let entry = buf.dequeue(1100).unwrap();
        assert_eq!(entry.packet, pkt);
        assert_eq!(entry.source_iid, iid);
        assert!(buf.is_empty());
    }

    #[test]
    fn per_source_limit_enforced() {
        let mut buf = ForwardBuffer::new();
        let iid = make_iid(1);

        // First two packets succeed
        buf.queue(make_packet(1), iid, 1000, None, 3).unwrap();
        buf.queue(make_packet(2), iid, 1001, None, 3).unwrap();

        // Third packet fails with QueueFull
        let err = buf.queue(make_packet(3), iid, 1002, None, 3).unwrap_err();
        assert_eq!(err, ForwardError::QueueFull);

        assert_eq!(buf.count_for_source(&iid), 2);
    }

    #[test]
    fn multiple_sources_independent_limits() {
        let mut buf = ForwardBuffer::new();
        let iid1 = make_iid(1);
        let iid2 = make_iid(2);

        // Each source can have 2 packets
        buf.queue(make_packet(1), iid1, 1000, None, 3).unwrap();
        buf.queue(make_packet(2), iid1, 1001, None, 3).unwrap();
        buf.queue(make_packet(3), iid2, 1002, None, 3).unwrap();
        buf.queue(make_packet(4), iid2, 1003, None, 3).unwrap();

        assert_eq!(buf.len(), 4);
        assert_eq!(buf.count_for_source(&iid1), 2);
        assert_eq!(buf.count_for_source(&iid2), 2);
        assert_eq!(buf.distinct_source_count(), 2);

        // Both sources are now full
        assert_eq!(
            buf.queue(make_packet(5), iid1, 1004, None, 3).unwrap_err(),
            ForwardError::QueueFull
        );
        assert_eq!(
            buf.queue(make_packet(6), iid2, 1005, None, 3).unwrap_err(),
            ForwardError::QueueFull
        );
    }

    #[test]
    fn max_sources_eviction() {
        let mut buf = ForwardBuffer::new();

        // Fill up MAX_FORWARDING_SOURCES
        for i in 0..MAX_FORWARDING_SOURCES {
            let iid = make_iid(i as u8);
            buf.queue(make_packet(i as u8), iid, 1000 + i as u32, None, 3)
                .unwrap();
        }

        assert_eq!(buf.distinct_source_count(), MAX_FORWARDING_SOURCES);
        assert_eq!(buf.len(), MAX_FORWARDING_SOURCES);

        // Adding a new source should evict the oldest packet
        let new_iid = make_iid(0xFF);
        buf.queue(make_packet(0xFF), new_iid, 2000, None, 3)
            .unwrap();

        // Still at max sources, one was evicted
        assert_eq!(buf.len(), MAX_FORWARDING_SOURCES);
        assert_eq!(buf.count_for_source(&new_iid), 1);
    }

    #[test]
    fn priority_ordering() {
        let mut buf = ForwardBuffer::new();
        let iid1 = make_iid(1);
        let iid2 = make_iid(2);

        // Queue low priority first
        buf.queue(make_packet(3), iid1, 1000, None, 3).unwrap();
        // Queue high priority second
        buf.queue(make_packet(0), iid2, 1001, None, 0).unwrap();

        // Dequeue should return high priority first
        let entry = buf.dequeue(1100).unwrap();
        assert_eq!(entry.priority, 0);
        assert_eq!(entry.packet[0], 0);

        let entry = buf.dequeue(1100).unwrap();
        assert_eq!(entry.priority, 3);
    }

    #[test]
    fn same_priority_oldest_first() {
        let mut buf = ForwardBuffer::new();
        let iid1 = make_iid(1);
        let iid2 = make_iid(2);

        buf.queue(make_packet(1), iid1, 1000, None, 2).unwrap();
        buf.queue(make_packet(2), iid2, 1100, None, 2).unwrap();

        // Oldest should come first
        let entry = buf.dequeue(1200).unwrap();
        assert_eq!(entry.queued_at_ms, 1000);
    }

    #[test]
    fn deadline_expiry() {
        let mut buf = ForwardBuffer::new();
        let iid = make_iid(1);

        // Packet with deadline
        buf.queue(make_packet(1), iid, 1000, Some(1500), 3).unwrap();

        // Before deadline
        assert_eq!(buf.expire(1400), 0);
        assert_eq!(buf.len(), 1);

        // After deadline
        assert_eq!(buf.expire(1600), 1);
        assert!(buf.is_empty());
    }

    #[test]
    fn dequeue_for_source() {
        let mut buf = ForwardBuffer::new();
        let iid1 = make_iid(1);
        let iid2 = make_iid(2);

        buf.queue(make_packet(1), iid1, 1000, None, 3).unwrap();
        buf.queue(make_packet(2), iid2, 1001, None, 3).unwrap();
        buf.queue(make_packet(3), iid1, 1002, None, 3).unwrap();

        // Dequeue for iid1 only
        let entry = buf.dequeue_for_source(&iid1, 1100).unwrap();
        assert_eq!(entry.source_iid, iid1);
        assert_eq!(entry.queued_at_ms, 1000); // Oldest for that source

        assert_eq!(buf.count_for_source(&iid1), 1);
        assert_eq!(buf.count_for_source(&iid2), 1);
    }

    #[test]
    fn clear_source() {
        let mut buf = ForwardBuffer::new();
        let iid1 = make_iid(1);
        let iid2 = make_iid(2);

        buf.queue(make_packet(1), iid1, 1000, None, 3).unwrap();
        buf.queue(make_packet(2), iid1, 1001, None, 3).unwrap();
        buf.queue(make_packet(3), iid2, 1002, None, 3).unwrap();

        let cleared = buf.clear_source(&iid1);
        assert_eq!(cleared, 2);
        assert_eq!(buf.count_for_source(&iid1), 0);
        assert_eq!(buf.count_for_source(&iid2), 1);
    }

    #[test]
    fn stats() {
        let mut buf = ForwardBuffer::new();
        let iid1 = make_iid(1);
        let iid2 = make_iid(2);

        let stats = buf.stats();
        assert_eq!(stats.total_packets, 0);
        assert_eq!(stats.distinct_sources, 0);
        assert_eq!(stats.oldest_queued_ms, None);

        buf.queue(make_packet(1), iid1, 1000, None, 3).unwrap();
        buf.queue(make_packet(2), iid2, 1100, None, 3).unwrap();

        let stats = buf.stats();
        assert_eq!(stats.total_packets, 2);
        assert_eq!(stats.distinct_sources, 2);
        assert_eq!(stats.oldest_queued_ms, Some(1000));
    }

    #[test]
    fn queue_reopens_after_dequeue() {
        let mut buf = ForwardBuffer::new();
        let iid = make_iid(1);

        // Fill quota
        buf.queue(make_packet(1), iid, 1000, None, 3).unwrap();
        buf.queue(make_packet(2), iid, 1001, None, 3).unwrap();

        // Third fails
        assert!(buf.queue(make_packet(3), iid, 1002, None, 3).is_err());

        // Dequeue one
        buf.dequeue(1100).unwrap();

        // Now we can queue again
        buf.queue(make_packet(4), iid, 1003, None, 3).unwrap();
        assert_eq!(buf.count_for_source(&iid), 2);
    }

    #[test]
    fn entry_is_expired() {
        let entry = ForwardEntry {
            packet: vec![],
            source_iid: make_iid(1),
            queued_at_ms: 1000,
            deadline_ms: Some(2000),
            priority: 0,
        };

        assert!(!entry.is_expired(1500));
        assert!(!entry.is_expired(2000)); // Exactly at deadline
        assert!(entry.is_expired(2001));

        // No deadline = never expires
        let no_deadline = ForwardEntry {
            deadline_ms: None,
            ..entry
        };
        assert!(!no_deadline.is_expired(u32::MAX));
    }

    #[test]
    fn entry_expired_handles_wraparound() {
        // Deadline set just before u32 max
        let entry = ForwardEntry {
            packet: vec![],
            source_iid: make_iid(1),
            queued_at_ms: 0xFFFF_FF00,
            deadline_ms: Some(0xFFFF_FFFE),
            priority: 0,
        };

        // Time has wrapped around to small value
        // 0x100 - 0xFFFF_FFFE = 0x102 (small positive in wrapping), not expired yet... wait
        // Actually after wraparound, now_ms(0x100) is "after" deadline(0xFFFF_FFFE)
        // The is_expired check uses now.wrapping_sub(deadline) < 0x8000_0000
        // 0x100.wrapping_sub(0xFFFF_FFFE) = 0x102, which < 0x8000_0000, so expired = true
        assert!(entry.is_expired(0x0000_0100));
    }
}
