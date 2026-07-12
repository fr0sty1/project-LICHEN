//! TX queue observability for LICHEN transmission scheduling.
//!
//! Provides a priority-based transmission queue with statistics and drain time
//! estimation for radio duty cycle planning.

use core::cmp::Ordering;
use core::fmt;
use heapless::binary_heap::{BinaryHeap, Max};

/// Error returned when pushing to the TX queue fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxQueueError {
    /// Queue is at capacity.
    QueueFull,
    /// Payload exceeds maximum size.
    PayloadTooLarge,
}

impl fmt::Display for TxQueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull => write!(f, "TX queue full"),
            Self::PayloadTooLarge => write!(f, "payload exceeds max size"),
        }
    }
}

impl core::error::Error for TxQueueError {}

/// Maximum number of items in the TX queue.
pub const TX_QUEUE_CAPACITY: usize = 32;

/// Maximum payload size for a queued item.
pub const TX_ITEM_MAX_PAYLOAD: usize = 255;

/// Priority levels for TX queue items.
///
/// Lower numeric value = higher priority (processed first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TxPriority {
    /// Control frames (acks, link management). Highest priority.
    Control = 0,
    /// Routing protocol messages (RPL, LOADng, Announce).
    Routing = 1,
    /// User application traffic.
    User = 2,
    /// Bulk transfers (firmware updates, large data). Lowest priority.
    Bulk = 3,
}

impl TxPriority {
    /// Number of distinct priority levels.
    pub const COUNT: usize = 4;

    /// Convert from u8, returning None for invalid values.
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Control),
            1 => Some(Self::Routing),
            2 => Some(Self::User),
            3 => Some(Self::Bulk),
            _ => None,
        }
    }
}

/// A single item in the TX queue.
#[derive(Clone)]
pub struct TxItem {
    /// Priority level for scheduling.
    pub priority: TxPriority,
    /// Sequence number for FIFO ordering within same priority.
    sequence: u32,
    /// Payload data.
    data: heapless::Vec<u8, TX_ITEM_MAX_PAYLOAD>,
}

impl TxItem {
    /// Create a new TX item.
    fn new(priority: TxPriority, sequence: u32, data: &[u8]) -> Option<Self> {
        let mut vec = heapless::Vec::new();
        vec.extend_from_slice(data).ok()?;
        Some(Self {
            priority,
            sequence,
            data: vec,
        })
    }

    /// Get the payload data.
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the payload length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if payload is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// Ordering for BinaryHeap<Max>: higher Ord value = dequeued first.
// We want: lower priority number dequeued first, then lower sequence (older) first.
// So we invert both: higher priority_value in Ord means lower TxPriority enum value.
impl PartialEq for TxItem {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}

impl Eq for TxItem {}

impl PartialOrd for TxItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TxItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // For Max heap: greater = dequeued first.
        // We want lower priority value first, so reverse the comparison.
        match (other.priority as u8).cmp(&(self.priority as u8)) {
            Ordering::Equal => {
                // Same priority: older (lower sequence) should come first.
                // Use wrapping subtraction to handle sequence counter wrap correctly:
                // if other is newer (logically higher seq), the difference is positive,
                // so self (older) compares as "greater" and is dequeued first.
                (other.sequence.wrapping_sub(self.sequence) as i32).cmp(&0)
            }
            ord => ord,
        }
    }
}

/// Statistics snapshot of the TX queue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TxQueueStats {
    /// Number of items currently queued.
    pub depth: usize,
    /// Total bytes pending across all queued items.
    pub bytes_pending: usize,
    /// Count of items at each priority level.
    /// Index corresponds to TxPriority enum value.
    pub by_priority: [usize; TxPriority::COUNT],
}

/// Priority-based transmission queue with observability.
pub struct TxQueue {
    heap: BinaryHeap<TxItem, Max, TX_QUEUE_CAPACITY>,
    /// Monotonic sequence counter for FIFO within priority.
    sequence: u32,
    /// Cached statistics (updated on push/pop).
    bytes_pending: usize,
    by_priority: [usize; TxPriority::COUNT],
}

impl Default for TxQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl TxQueue {
    /// Create a new empty TX queue.
    #[inline]
    pub const fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            sequence: 0,
            bytes_pending: 0,
            by_priority: [0; TxPriority::COUNT],
        }
    }

    /// Push an item onto the queue.
    ///
    /// Returns `Err(data)` if the queue is full or payload exceeds max size.
    pub fn push(&mut self, priority: TxPriority, data: &[u8]) -> Result<(), TxQueueError> {
        let item = TxItem::new(priority, self.sequence, data).ok_or(TxQueueError::PayloadTooLarge)?;

        if self.heap.push(item).is_err() {
            return Err(TxQueueError::QueueFull);
        }

        self.sequence = self.sequence.wrapping_add(1);
        self.bytes_pending += data.len();
        self.by_priority[priority as usize] += 1;
        Ok(())
    }

    /// Pop the highest priority item from the queue.
    ///
    /// Returns `None` if the queue is empty.
    pub fn pop(&mut self) -> Option<TxItem> {
        let item = self.heap.pop()?;
        self.bytes_pending -= item.len();
        self.by_priority[item.priority as usize] -= 1;
        Some(item)
    }

    /// Peek at the highest priority item without removing it.
    #[inline]
    pub fn peek(&self) -> Option<&TxItem> {
        self.heap.peek()
    }

    /// Check if the queue is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Check if the queue is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.heap.len() >= TX_QUEUE_CAPACITY
    }

    /// Get current queue depth.
    #[inline]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Get a snapshot of queue statistics.
    #[inline]
    pub fn stats(&self) -> TxQueueStats {
        TxQueueStats {
            depth: self.heap.len(),
            bytes_pending: self.bytes_pending,
            by_priority: self.by_priority,
        }
    }

    /// Estimate time to drain the queue in milliseconds.
    ///
    /// `airtime_per_byte` is the transmission time per byte in microseconds.
    /// This provides a rough estimate for radio duty cycle planning.
    ///
    /// Returns the estimated drain time in milliseconds.
    #[inline]
    pub fn estimated_drain_time_ms(&self, airtime_per_byte_us: u32) -> u64 {
        let total_us = (self.bytes_pending as u64) * (airtime_per_byte_us as u64);
        // Round up to next millisecond
        (total_us + 999) / 1000
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn empty_queue_stats() {
        let queue = TxQueue::new();
        let stats = queue.stats();

        assert_eq!(stats.depth, 0);
        assert_eq!(stats.bytes_pending, 0);
        assert_eq!(stats.by_priority, [0, 0, 0, 0]);
    }

    #[test]
    fn push_pop_basic() {
        let mut queue = TxQueue::new();

        queue.push(TxPriority::User, b"hello").unwrap();
        assert_eq!(queue.len(), 1);

        let item = queue.pop().unwrap();
        assert_eq!(item.data(), b"hello");
        assert_eq!(item.priority, TxPriority::User);
        assert!(queue.is_empty());
    }

    #[test]
    fn priority_ordering() {
        let mut queue = TxQueue::new();

        // Push in reverse priority order
        queue.push(TxPriority::Bulk, b"bulk").unwrap();
        queue.push(TxPriority::User, b"user").unwrap();
        queue.push(TxPriority::Routing, b"routing").unwrap();
        queue.push(TxPriority::Control, b"control").unwrap();

        // Should pop in priority order (lowest enum value first)
        assert_eq!(queue.pop().unwrap().priority, TxPriority::Control);
        assert_eq!(queue.pop().unwrap().priority, TxPriority::Routing);
        assert_eq!(queue.pop().unwrap().priority, TxPriority::User);
        assert_eq!(queue.pop().unwrap().priority, TxPriority::Bulk);
    }

    #[test]
    fn fifo_within_priority() {
        let mut queue = TxQueue::new();

        queue.push(TxPriority::User, b"first").unwrap();
        queue.push(TxPriority::User, b"second").unwrap();
        queue.push(TxPriority::User, b"third").unwrap();

        assert_eq!(queue.pop().unwrap().data(), b"first");
        assert_eq!(queue.pop().unwrap().data(), b"second");
        assert_eq!(queue.pop().unwrap().data(), b"third");
    }

    #[test]
    fn stats_tracking() {
        let mut queue = TxQueue::new();

        queue.push(TxPriority::Control, b"ack").unwrap();
        queue.push(TxPriority::User, b"hello world").unwrap();
        queue.push(TxPriority::User, b"test").unwrap();
        queue.push(TxPriority::Bulk, b"data").unwrap();

        let stats = queue.stats();
        assert_eq!(stats.depth, 4);
        assert_eq!(stats.bytes_pending, 3 + 11 + 4 + 4); // 22
        assert_eq!(stats.by_priority[TxPriority::Control as usize], 1);
        assert_eq!(stats.by_priority[TxPriority::Routing as usize], 0);
        assert_eq!(stats.by_priority[TxPriority::User as usize], 2);
        assert_eq!(stats.by_priority[TxPriority::Bulk as usize], 1);

        // Pop one and verify stats update
        queue.pop();
        let stats = queue.stats();
        assert_eq!(stats.depth, 3);
        assert_eq!(stats.bytes_pending, 19); // 22 - 3
        assert_eq!(stats.by_priority[TxPriority::Control as usize], 0);
    }

    #[test]
    fn estimated_drain_time() {
        let mut queue = TxQueue::new();

        // 100 bytes total
        queue.push(TxPriority::User, &[0u8; 100]).unwrap();

        // At 1000 us/byte = 1ms/byte, 100 bytes = 100ms
        assert_eq!(queue.estimated_drain_time_ms(1000), 100);

        // At 500 us/byte, 100 bytes = 50ms
        assert_eq!(queue.estimated_drain_time_ms(500), 50);

        // Empty queue should return 0
        queue.pop();
        assert_eq!(queue.estimated_drain_time_ms(1000), 0);
    }

    #[test]
    fn estimated_drain_time_rounds_up() {
        let mut queue = TxQueue::new();

        // 1 byte at 1 us/byte = 1 us, should round up to 1 ms
        queue.push(TxPriority::User, &[0u8; 1]).unwrap();
        assert_eq!(queue.estimated_drain_time_ms(1), 1);
    }

    #[test]
    fn queue_full_error() {
        let mut queue = TxQueue::new();

        for i in 0..TX_QUEUE_CAPACITY {
            queue.push(TxPriority::User, &[i as u8]).unwrap();
        }

        assert!(queue.is_full());
        assert!(queue.push(TxPriority::User, b"overflow").is_err());
    }

    #[test]
    fn priority_from_u8() {
        assert_eq!(TxPriority::from_u8(0), Some(TxPriority::Control));
        assert_eq!(TxPriority::from_u8(1), Some(TxPriority::Routing));
        assert_eq!(TxPriority::from_u8(2), Some(TxPriority::User));
        assert_eq!(TxPriority::from_u8(3), Some(TxPriority::Bulk));
        assert_eq!(TxPriority::from_u8(4), None);
        assert_eq!(TxPriority::from_u8(255), None);
    }

    #[test]
    fn peek_does_not_modify() {
        let mut queue = TxQueue::new();
        queue.push(TxPriority::User, b"data").unwrap();

        assert_eq!(queue.peek().unwrap().data(), b"data");
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.peek().unwrap().data(), b"data");
    }

    #[test]
    fn fifo_across_sequence_wrap() {
        let mut queue = TxQueue::new();

        // Set sequence counter near wrap point
        queue.sequence = u32::MAX - 1;

        // Push items that span the wrap
        queue.push(TxPriority::User, b"before_wrap_1").unwrap(); // seq = MAX-1
        queue.push(TxPriority::User, b"before_wrap_2").unwrap(); // seq = MAX
        queue.push(TxPriority::User, b"after_wrap_1").unwrap(); // seq = 0 (wrapped)
        queue.push(TxPriority::User, b"after_wrap_2").unwrap(); // seq = 1

        // FIFO should be preserved despite wrap
        assert_eq!(queue.pop().unwrap().data(), b"before_wrap_1");
        assert_eq!(queue.pop().unwrap().data(), b"before_wrap_2");
        assert_eq!(queue.pop().unwrap().data(), b"after_wrap_1");
        assert_eq!(queue.pop().unwrap().data(), b"after_wrap_2");
    }
}
