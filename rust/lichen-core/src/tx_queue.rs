//! TX queue observability for LICHEN transmission scheduling.
//!
//! Provides a priority-based transmission queue with statistics and drain time
//! estimation for radio duty cycle planning.
//!
//! Per spec/appendix-bufferbloat.md §3:
//! - Queue capacity: 4 packets max
//! - Deadline expiry: routing 5s, control 10s, user/bulk 60s
//! - Priority preemption: higher priority items evict lower priority when full

use core::cmp::Ordering;
use core::fmt;
use heapless::binary_heap::{BinaryHeap, Max};

/// Error returned when pushing to the TX queue fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxQueueError {
    /// Queue is at capacity and preemption not possible
    /// (new item has same or lower priority than all existing items).
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

/// Maximum number of items in the TX queue (spec: 4 packets).
pub const TX_QUEUE_CAPACITY: usize = 4;

/// Default deadline for routing control messages (5 seconds).
pub const DEADLINE_ROUTING_MS: u64 = 5_000;

/// Default deadline for control/ACK messages (10 seconds).
pub const DEADLINE_CONTROL_MS: u64 = 10_000;

/// Default deadline for user application data (60 seconds).
pub const DEADLINE_USER_MS: u64 = 60_000;

/// Default deadline for bulk data (60 seconds).
pub const DEADLINE_BULK_MS: u64 = 60_000;

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
    /// Deadline timestamp (milliseconds). Item expires when now_ms >= deadline_ms.
    pub deadline_ms: u64,
    /// Enqueue timestamp (milliseconds) for latency tracking.
    enqueue_time_ms: u64,
    /// Payload data.
    data: heapless::Vec<u8, TX_ITEM_MAX_PAYLOAD>,
}

impl TxItem {
    /// Create a new TX item.
    fn new(
        priority: TxPriority,
        sequence: u32,
        deadline_ms: u64,
        enqueue_time_ms: u64,
        data: &[u8],
    ) -> Option<Self> {
        let mut vec = heapless::Vec::new();
        vec.extend_from_slice(data).ok()?;
        Some(Self {
            priority,
            sequence,
            deadline_ms,
            enqueue_time_ms,
            data: vec,
        })
    }

    /// Get the enqueue timestamp.
    #[inline]
    pub fn enqueue_time_ms(&self) -> u64 {
        self.enqueue_time_ms
    }

    /// Check if this item has expired.
    #[inline]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.deadline_ms
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
    /// Cumulative count of packets enqueued (spec: packets_queued).
    pub packets_queued: u32,
    /// Total items dropped due to deadline expiry (spec: packets_dropped_deadline).
    pub packets_dropped_deadline: u32,
    /// Total items dropped because queue was full (spec: packets_dropped_full).
    pub packets_dropped_full: u32,
    /// Total items dropped due to preemption by higher priority.
    pub packets_preempted: u32,
    /// Maximum observed queue latency in milliseconds (spec: max_latency_ms).
    pub max_latency_ms: u32,
    /// Smoothed average queue latency in milliseconds (spec: avg_latency_ms).
    /// Uses EWMA with alpha = 1/8 for low-memory tracking.
    pub avg_latency_ms: u32,
}

/// Priority-based transmission queue with observability.
///
/// Reentrancy: `expire_before`, `try_preempt` (drain+rebuild heap),
/// `push` and `pop` update multiple fields (heap, stats, sequence,
/// bytes_pending) non-atomically. Matches C `pending_drop_tail`
/// requirement (tail-update + memset + count-decrement not atomic;
/// must run in interrupt-disabled context or with protection).
/// No built-in locks (no_std); caller must synchronize. See
/// lichen/subsys/lichen/meshcore/adapter.c:305 and spec for
/// TDMA/pending semantics.
pub struct TxQueue {
    heap: BinaryHeap<TxItem, Max, TX_QUEUE_CAPACITY>,
    /// Monotonic sequence counter for FIFO within priority.
    sequence: u32,
    /// Cached statistics (updated on push/pop).
    bytes_pending: usize,
    by_priority: [usize; TxPriority::COUNT],
    /// Cumulative count of packets enqueued.
    packets_queued: u32,
    /// Cumulative count of packets dropped due to deadline expiry.
    packets_dropped_deadline: u32,
    /// Cumulative count of packets dropped due to queue full.
    packets_dropped_full: u32,
    /// Cumulative count of packets preempted.
    packets_preempted: u32,
    /// Maximum observed queue latency in milliseconds.
    max_latency_ms: u32,
    /// EWMA average latency (scaled by 8 for integer math).
    avg_latency_scaled: u32,
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
            packets_queued: 0,
            packets_dropped_deadline: 0,
            packets_dropped_full: 0,
            packets_preempted: 0,
            max_latency_ms: 0,
            avg_latency_scaled: 0,
        }
    }

    /// Push an item onto the queue.
    ///
    /// Per spec, this method:
    /// 1. First expires any items past their deadline
    /// 2. If queue is full and new item has higher priority, preempts lowest priority
    /// 3. If queue is full and cannot preempt, returns `QueueFull`
    ///
    /// # Arguments
    /// * `priority` - Priority level for this item
    /// * `deadline_ms` - Absolute timestamp when this item expires
    /// * `now_ms` - Current timestamp for expiry checks
    /// * `data` - Payload data
    pub fn push(
        &mut self,
        priority: TxPriority,
        deadline_ms: u64,
        now_ms: u64,
        data: &[u8],
    ) -> Result<(), TxQueueError> {
        let item = TxItem::new(priority, self.sequence, deadline_ms, now_ms, data)
            .ok_or(TxQueueError::PayloadTooLarge)?;

        // Step 1: Expire stale items
        self.expire_before(now_ms);

        // Step 2: If not full, just push
        if !self.is_full() {
            // Safe: we just checked it's not full
            self.heap.push(item).ok();
            self.sequence = self.sequence.wrapping_add(1);
            self.bytes_pending += data.len();
            self.by_priority[priority as usize] += 1;
            self.packets_queued = self.packets_queued.saturating_add(1);
            return Ok(());
        }

        // Step 3: Queue is full, try preemption
        if self.try_preempt(priority) {
            // Preemption succeeded, now there's room
            self.heap.push(item).ok();
            self.sequence = self.sequence.wrapping_add(1);
            self.bytes_pending += data.len();
            self.by_priority[priority as usize] += 1;
            self.packets_queued = self.packets_queued.saturating_add(1);
            return Ok(());
        }

        // Step 4: Cannot preempt, queue is full
        self.packets_dropped_full = self.packets_dropped_full.saturating_add(1);
        Err(TxQueueError::QueueFull)
    }

    /// Expire all items whose deadline has passed.
    ///
    /// Returns the number of items expired.
    pub fn expire_before(&mut self, now_ms: u64) -> usize {
        // For a small queue (4 items), drain and rebuild is efficient
        let mut temp = heapless::Vec::<TxItem, TX_QUEUE_CAPACITY>::new();
        let mut expired_count = 0usize;

        while let Some(item) = self.heap.pop() {
            if item.is_expired(now_ms) {
                // Expired: update stats but don't keep
                self.bytes_pending -= item.len();
                self.by_priority[item.priority as usize] -= 1;
                self.packets_dropped_deadline = self.packets_dropped_deadline.saturating_add(1);
                expired_count += 1;
            } else {
                // Not expired: keep it
                temp.push(item).ok();
            }
        }

        // Put non-expired items back
        for item in temp {
            self.heap.push(item).ok();
        }

        expired_count
    }

    /// Try to preempt a lower-priority item to make room for a higher-priority one.
    ///
    /// Returns true if preemption succeeded (an item was removed).
    fn try_preempt(&mut self, new_priority: TxPriority) -> bool {
        // Find the worst (lowest) priority currently in queue
        let mut worst_priority = 0u8;
        for item in self.heap.iter() {
            worst_priority = worst_priority.max(item.priority as u8);
        }

        // Can only preempt if new item has strictly higher priority (lower number)
        if (new_priority as u8) >= worst_priority {
            return false;
        }

        // Find the oldest item at worst priority (lowest sequence number)
        let mut oldest_seq_at_worst: Option<u32> = None;
        for item in self.heap.iter() {
            if item.priority as u8 == worst_priority {
                match oldest_seq_at_worst {
                    None => oldest_seq_at_worst = Some(item.sequence),
                    Some(seq) => {
                        // Use wrapping comparison: negative difference means item is older
                        if (item.sequence.wrapping_sub(seq) as i32) < 0 {
                            oldest_seq_at_worst = Some(item.sequence);
                        }
                    }
                }
            }
        }

        let target_seq = match oldest_seq_at_worst {
            Some(seq) => seq,
            None => return false, // No items at worst priority (shouldn't happen)
        };

        // Drain and rebuild, removing the target item
        let mut temp = heapless::Vec::<TxItem, TX_QUEUE_CAPACITY>::new();
        let mut removed = false;

        while let Some(item) = self.heap.pop() {
            if !removed && item.priority as u8 == worst_priority && item.sequence == target_seq {
                // This is the item to evict
                self.bytes_pending -= item.len();
                self.by_priority[item.priority as usize] -= 1;
                self.packets_preempted = self.packets_preempted.saturating_add(1);
                removed = true;
            } else {
                temp.push(item).ok();
            }
        }

        // Put remaining items back
        for item in temp {
            self.heap.push(item).ok();
        }

        removed
    }

    /// Pop the highest priority item from the queue.
    ///
    /// Requires current timestamp to compute and track queue latency.
    /// Returns `None` if the queue is empty.
    pub fn pop(&mut self, now_ms: u64) -> Option<TxItem> {
        let item = self.heap.pop()?;
        self.bytes_pending -= item.len();
        self.by_priority[item.priority as usize] -= 1;

        // Compute latency and update statistics
        let latency_ms = now_ms.saturating_sub(item.enqueue_time_ms) as u32;
        if latency_ms > self.max_latency_ms {
            self.max_latency_ms = latency_ms;
        }
        // EWMA: new_avg = (7 * old_avg + new_sample) / 8
        // We store avg * 8 to avoid division until stats() is called
        self.avg_latency_scaled = self
            .avg_latency_scaled
            .saturating_sub(self.avg_latency_scaled / 8)
            .saturating_add(latency_ms);

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
            packets_queued: self.packets_queued,
            packets_dropped_deadline: self.packets_dropped_deadline,
            packets_dropped_full: self.packets_dropped_full,
            packets_preempted: self.packets_preempted,
            max_latency_ms: self.max_latency_ms,
            // Unscale the EWMA (divide by 8)
            avg_latency_ms: self.avg_latency_scaled / 8,
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
        total_us.div_ceil(1000)
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
        assert_eq!(stats.packets_queued, 0);
        assert_eq!(stats.packets_dropped_deadline, 0);
        assert_eq!(stats.packets_dropped_full, 0);
        assert_eq!(stats.packets_preempted, 0);
        assert_eq!(stats.max_latency_ms, 0);
        assert_eq!(stats.avg_latency_ms, 0);
    }

    #[test]
    fn push_pop_basic() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        queue
            .push(TxPriority::User, deadline, now, b"hello")
            .unwrap();
        assert_eq!(queue.len(), 1);

        let pop_time = now + 50; // 50ms later
        let item = queue.pop(pop_time).unwrap();
        assert_eq!(item.data(), b"hello");
        assert_eq!(item.priority, TxPriority::User);
        assert_eq!(item.deadline_ms, deadline);
        assert!(queue.is_empty());
    }

    #[test]
    fn priority_ordering() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        // Push in reverse priority order (all 4 slots)
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk")
            .unwrap();
        queue
            .push(TxPriority::User, deadline, now, b"user")
            .unwrap();
        queue
            .push(TxPriority::Routing, deadline, now, b"routing")
            .unwrap();
        queue
            .push(TxPriority::Control, deadline, now, b"control")
            .unwrap();

        // Should pop in priority order (lowest enum value first)
        assert_eq!(queue.pop(now).unwrap().priority, TxPriority::Control);
        assert_eq!(queue.pop(now).unwrap().priority, TxPriority::Routing);
        assert_eq!(queue.pop(now).unwrap().priority, TxPriority::User);
        assert_eq!(queue.pop(now).unwrap().priority, TxPriority::Bulk);
    }

    #[test]
    fn fifo_within_priority() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        queue
            .push(TxPriority::User, deadline, now, b"first")
            .unwrap();
        queue
            .push(TxPriority::User, deadline, now, b"second")
            .unwrap();
        queue
            .push(TxPriority::User, deadline, now, b"third")
            .unwrap();

        assert_eq!(queue.pop(now).unwrap().data(), b"first");
        assert_eq!(queue.pop(now).unwrap().data(), b"second");
        assert_eq!(queue.pop(now).unwrap().data(), b"third");
    }

    #[test]
    fn stats_tracking() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        queue
            .push(TxPriority::Control, deadline, now, b"ack")
            .unwrap();
        queue
            .push(TxPriority::User, deadline, now, b"hello world")
            .unwrap();
        queue
            .push(TxPriority::User, deadline, now, b"test")
            .unwrap();
        queue
            .push(TxPriority::Bulk, deadline, now, b"data")
            .unwrap();

        let stats = queue.stats();
        assert_eq!(stats.depth, 4);
        assert_eq!(stats.bytes_pending, 3 + 11 + 4 + 4); // 22
        assert_eq!(stats.by_priority[TxPriority::Control as usize], 1);
        assert_eq!(stats.by_priority[TxPriority::Routing as usize], 0);
        assert_eq!(stats.by_priority[TxPriority::User as usize], 2);
        assert_eq!(stats.by_priority[TxPriority::Bulk as usize], 1);
        assert_eq!(stats.packets_queued, 4);

        // Pop one and verify stats update
        queue.pop(now);
        let stats = queue.stats();
        assert_eq!(stats.depth, 3);
        assert_eq!(stats.bytes_pending, 19); // 22 - 3
        assert_eq!(stats.by_priority[TxPriority::Control as usize], 0);
    }

    #[test]
    fn estimated_drain_time() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        // 100 bytes total
        queue
            .push(TxPriority::User, deadline, now, &[0u8; 100])
            .unwrap();

        // At 1000 us/byte = 1ms/byte, 100 bytes = 100ms
        assert_eq!(queue.estimated_drain_time_ms(1000), 100);

        // At 500 us/byte, 100 bytes = 50ms
        assert_eq!(queue.estimated_drain_time_ms(500), 50);

        // Empty queue should return 0
        queue.pop(now);
        assert_eq!(queue.estimated_drain_time_ms(1000), 0);
    }

    #[test]
    fn estimated_drain_time_rounds_up() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        // 1 byte at 1 us/byte = 1 us, should round up to 1 ms
        queue
            .push(TxPriority::User, deadline, now, &[0u8; 1])
            .unwrap();
        assert_eq!(queue.estimated_drain_time_ms(1), 1);
    }

    #[test]
    fn queue_full_error() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        // Fill queue with same priority items
        for i in 0..TX_QUEUE_CAPACITY {
            queue
                .push(TxPriority::User, deadline, now, &[i as u8])
                .unwrap();
        }

        assert!(queue.is_full());
        // Same priority cannot preempt, should fail
        assert!(queue
            .push(TxPriority::User, deadline, now, b"overflow")
            .is_err());
        // Lower priority (Bulk) cannot preempt User, should fail
        assert!(queue
            .push(TxPriority::Bulk, deadline, now, b"bulk")
            .is_err());
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
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        queue
            .push(TxPriority::User, deadline, now, b"data")
            .unwrap();

        assert_eq!(queue.peek().unwrap().data(), b"data");
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.peek().unwrap().data(), b"data");
    }

    #[test]
    fn fifo_across_sequence_wrap() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        // Set sequence counter near wrap point
        queue.sequence = u32::MAX - 1;

        // Push items that span the wrap (fills the queue of 4)
        queue
            .push(TxPriority::User, deadline, now, b"before_wrap_1")
            .unwrap(); // seq = MAX-1
        queue
            .push(TxPriority::User, deadline, now, b"before_wrap_2")
            .unwrap(); // seq = MAX
        queue
            .push(TxPriority::User, deadline, now, b"after_wrap_1")
            .unwrap(); // seq = 0 (wrapped)
        queue
            .push(TxPriority::User, deadline, now, b"after_wrap_2")
            .unwrap(); // seq = 1

        // FIFO should be preserved despite wrap
        assert_eq!(queue.pop(now).unwrap().data(), b"before_wrap_1");
        assert_eq!(queue.pop(now).unwrap().data(), b"before_wrap_2");
        assert_eq!(queue.pop(now).unwrap().data(), b"after_wrap_1");
        assert_eq!(queue.pop(now).unwrap().data(), b"after_wrap_2");
    }

    #[test]
    fn deadline_expiry() {
        let mut queue = TxQueue::new();
        let now = 1000u64;

        // Push item that expires at now + 100
        queue
            .push(TxPriority::User, now + 100, now, b"short_lived")
            .unwrap();
        // Push item that expires at now + 10000
        queue
            .push(TxPriority::User, now + 10000, now, b"long_lived")
            .unwrap();

        assert_eq!(queue.len(), 2);

        // Advance time past first deadline but before second
        let later = now + 500;
        let expired = queue.expire_before(later);

        assert_eq!(expired, 1);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.pop(later).unwrap().data(), b"long_lived");

        // Verify stats tracking
        let stats = queue.stats();
        assert_eq!(stats.packets_dropped_deadline, 1);
    }

    #[test]
    fn deadline_expiry_on_push() {
        let mut queue = TxQueue::new();
        let now = 1000u64;

        // Push item with short deadline
        queue
            .push(TxPriority::User, now + 100, now, b"will_expire")
            .unwrap();
        // Fill rest of queue
        queue
            .push(TxPriority::User, now + 10000, now, b"keeper1")
            .unwrap();
        queue
            .push(TxPriority::User, now + 10000, now, b"keeper2")
            .unwrap();
        queue
            .push(TxPriority::User, now + 10000, now, b"keeper3")
            .unwrap();

        assert!(queue.is_full());

        // Push new item after first one expired - should succeed due to expiry
        let later = now + 500;
        queue
            .push(TxPriority::User, later + 10000, later, b"new_item")
            .unwrap();

        // Queue should still be full (4 items: 3 keepers + new_item)
        assert_eq!(queue.len(), 4);
        let stats = queue.stats();
        assert_eq!(stats.packets_dropped_deadline, 1);
    }

    #[test]
    fn preemption_higher_priority() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        // Fill queue with Bulk priority
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk1")
            .unwrap();
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk2")
            .unwrap();
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk3")
            .unwrap();
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk4")
            .unwrap();

        assert!(queue.is_full());

        // Higher priority (Control) should preempt
        queue
            .push(TxPriority::Control, deadline, now, b"urgent")
            .unwrap();

        // Verify preemption stats
        let stats = queue.stats();
        assert_eq!(stats.packets_preempted, 1);
        assert_eq!(stats.depth, 4); // Still full

        // First item out should be the urgent one (highest priority)
        assert_eq!(queue.pop(now).unwrap().data(), b"urgent");
    }

    #[test]
    fn preemption_evicts_oldest_lowest_priority() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        // Fill with mixed priorities
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk_oldest")
            .unwrap();
        queue
            .push(TxPriority::User, deadline, now, b"user")
            .unwrap();
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk_newer")
            .unwrap();
        queue
            .push(TxPriority::User, deadline, now, b"user2")
            .unwrap();

        assert!(queue.is_full());

        // Push higher priority item
        queue
            .push(TxPriority::Control, deadline, now, b"control")
            .unwrap();

        // Should have preempted oldest Bulk item
        let stats = queue.stats();
        assert_eq!(stats.packets_preempted, 1);

        // Pop all and verify bulk_oldest is gone but bulk_newer remains
        let mut items: std::vec::Vec<_> = std::vec::Vec::new();
        while let Some(item) = queue.pop(now) {
            items.push(item);
        }

        let payloads: std::vec::Vec<_> = items.iter().map(|i| i.data()).collect();
        assert!(payloads.contains(&b"control".as_slice()));
        assert!(payloads.contains(&b"user".as_slice()));
        assert!(payloads.contains(&b"bulk_newer".as_slice()));
        assert!(payloads.contains(&b"user2".as_slice()));
        assert!(!payloads.contains(&b"bulk_oldest".as_slice()));
    }

    #[test]
    fn capacity_is_four() {
        // Verify the spec-mandated capacity
        assert_eq!(TX_QUEUE_CAPACITY, 4);
    }

    #[test]
    fn default_deadline_constants() {
        // Verify spec-mandated deadlines
        assert_eq!(DEADLINE_ROUTING_MS, 5_000);
        assert_eq!(DEADLINE_CONTROL_MS, 10_000);
        assert_eq!(DEADLINE_USER_MS, 60_000);
        assert_eq!(DEADLINE_BULK_MS, 60_000);
    }

    #[test]
    fn packets_queued_counter() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        // Push 3 items
        queue.push(TxPriority::User, deadline, now, b"one").unwrap();
        queue.push(TxPriority::User, deadline, now, b"two").unwrap();
        queue
            .push(TxPriority::User, deadline, now, b"three")
            .unwrap();

        let stats = queue.stats();
        assert_eq!(stats.packets_queued, 3);

        // Pop one and push another - counter should still increment
        queue.pop(now);
        queue
            .push(TxPriority::User, deadline, now, b"four")
            .unwrap();

        let stats = queue.stats();
        assert_eq!(stats.packets_queued, 4); // Cumulative, not current depth
        assert_eq!(stats.depth, 3);
    }

    #[test]
    fn packets_dropped_full_counter() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        // Fill queue with same priority items (4 slots)
        for i in 0..TX_QUEUE_CAPACITY {
            queue
                .push(TxPriority::User, deadline, now, &[i as u8])
                .unwrap();
        }

        // Try to push more - these should fail and increment dropped counter
        assert!(queue
            .push(TxPriority::User, deadline, now, b"drop1")
            .is_err());
        assert!(queue
            .push(TxPriority::Bulk, deadline, now, b"drop2")
            .is_err());
        assert!(queue
            .push(TxPriority::User, deadline, now, b"drop3")
            .is_err());

        let stats = queue.stats();
        assert_eq!(stats.packets_dropped_full, 3);
        assert_eq!(stats.packets_queued, 4); // Only the successful pushes
    }

    #[test]
    fn latency_tracking_basic() {
        let mut queue = TxQueue::new();
        let enqueue_time = 1000u64;
        let deadline = enqueue_time + DEADLINE_USER_MS;

        queue
            .push(TxPriority::User, deadline, enqueue_time, b"test")
            .unwrap();

        // Pop 100ms later
        let pop_time = enqueue_time + 100;
        queue.pop(pop_time);

        let stats = queue.stats();
        assert_eq!(stats.max_latency_ms, 100);
        // After one sample, avg = sample (since EWMA starts at 0 and converges)
        // EWMA: new = old - old/8 + sample = 0 - 0 + 100 = 100
        // Then divided by 8 for display: 100/8 = 12
        assert_eq!(stats.avg_latency_ms, 12);
    }

    #[test]
    fn latency_tracking_max() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        // Push three items
        queue.push(TxPriority::User, deadline, now, b"a").unwrap();
        queue
            .push(TxPriority::User, deadline, now + 50, b"b")
            .unwrap();
        queue
            .push(TxPriority::User, deadline, now + 100, b"c")
            .unwrap();

        // Pop at different times to create varying latencies
        // Item a: enqueued at 1000, popped at 1200 -> 200ms latency
        // Item b: enqueued at 1050, popped at 1200 -> 150ms latency
        // Item c: enqueued at 1100, popped at 1200 -> 100ms latency
        let pop_time = now + 200;
        queue.pop(pop_time); // a: 200ms
        queue.pop(pop_time); // b: 150ms
        queue.pop(pop_time); // c: 100ms

        let stats = queue.stats();
        assert_eq!(stats.max_latency_ms, 200); // Maximum observed
    }

    #[test]
    fn latency_ewma_smoothing() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        // Push and pop multiple items with consistent latency to observe EWMA behavior
        // EWMA formula: scaled = scaled - scaled/8 + sample
        // Display: avg = scaled / 8

        // Sample 1: 80ms -> scaled = 0 - 0 + 80 = 80 -> avg = 10
        queue.push(TxPriority::User, deadline, now, b"1").unwrap();
        queue.pop(now + 80);
        assert_eq!(queue.stats().avg_latency_ms, 10);

        // Sample 2: 80ms -> scaled = 80 - 10 + 80 = 150 -> avg = 18
        queue
            .push(TxPriority::User, deadline, now + 100, b"2")
            .unwrap();
        queue.pop(now + 180);
        assert_eq!(queue.stats().avg_latency_ms, 18);

        // Sample 3: 80ms -> scaled = 150 - 18 + 80 = 212 -> avg = 26
        queue
            .push(TxPriority::User, deadline, now + 200, b"3")
            .unwrap();
        queue.pop(now + 280);
        assert_eq!(queue.stats().avg_latency_ms, 26);
    }

    #[test]
    fn enqueue_time_accessor() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_USER_MS;

        queue
            .push(TxPriority::User, deadline, now, b"test")
            .unwrap();

        let item = queue.pop(now + 50).unwrap();
        assert_eq!(item.enqueue_time_ms(), now);
    }
}
