//! TX queue observability for LICHEN transmission scheduling.
//!
//! Provides a priority-based transmission queue with statistics and drain time
//! estimation for radio duty cycle planning.
//!
//! Per spec/appendix-bufferbloat.md §3:
//! - Queue capacity: 4 packets max
//! - Deadline expiry: routing 5s, control 10s, user/bulk 60s
//! - Priority preemption: higher priority items evict lower priority when full
//!
//! # Duty Cycle Integration
//!
//! The [`TxQueue::pop_if_allowed`] method integrates with congestion levels
//! (spec 07 section 10.2.3) to gate transmission based on duty cycle budget:
//! - NORMAL: all priorities allowed
//! - ELEVATED: only SOS/ROUTING/URGENT (P0-P2)
//! - CRITICAL: only SOS/ROUTING (P0-P1)
//! - EXHAUSTED: no transmission allowed
//!
//! # CSMA/CA Integration
//!
//! [`CsmaState`] consumes CAD observations and produces a [`CsmaAction`]. The
//! caller owns the radio and entropy source; this module only maps a uniformly
//! distributed `u32` draw into the current contention window. A transmit action
//! can be applied directly with [`TxQueue::pop_after_csma`].

use core::cmp::Ordering;
use core::fmt;
use heapless::binary_heap::{BinaryHeap, Max};

use crate::constants::{
    CSMA_BACKOFF_MAX, CSMA_BACKOFF_UNIT_MS, CSMA_CAD_TIMEOUT_SYMBOLS, CSMA_RETRY_LIMIT,
};
use crate::duty_cycle::{check_congestion_allows, CongestionLevel};

/// Result reported by the radio's channel-activity-detection operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CadObservation {
    /// No LoRa preamble was detected; transmission may proceed.
    Idle,
    /// Channel activity was detected; defer and retry.
    Busy,
}

/// Next operation selected by the CSMA/CA state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsmaAction {
    /// The channel is idle and the caller may transmit immediately.
    Transmit,
    /// Wait for the selected number of contention slots, then perform CAD again.
    Backoff {
        /// Randomly selected slot count in the inclusive contention window.
        slots: u8,
        /// Backoff duration in milliseconds.
        delay_ms: u32,
    },
    /// More than [`CSMA_RETRY_LIMIT`] busy CAD results were observed.
    RetryExhausted,
}

impl CsmaAction {
    /// Whether this action permits a queued packet to be transmitted.
    #[inline]
    pub const fn tx_allowed(self) -> bool {
        matches!(self, Self::Transmit)
    }
}

/// Invalid state supplied when restoring a CSMA/CA contention attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsmaStateError {
    /// The backoff exponent exceeds [`CSMA_BACKOFF_MAX`].
    BackoffExponentOutOfRange,
    /// The busy-CAD count exceeds the one terminal value the machine can reach.
    RetryCountOutOfRange,
}

impl fmt::Display for CsmaStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackoffExponentOutOfRange => write!(f, "CSMA backoff exponent out of range"),
            Self::RetryCountOutOfRange => write!(f, "CSMA retry count out of range"),
        }
    }
}

impl core::error::Error for CsmaStateError {}

/// CAD-based CSMA/CA contention state (spec 09 section 14.5).
///
/// The caller performs CAD with a timeout of [`Self::cad_timeout_symbols`] and
/// supplies a uniformly distributed `u32` to [`Self::on_cad`] for busy-channel
/// backoff. Keeping entropy acquisition outside this type makes the state
/// machine deterministic, portable, and `no_std` compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsmaState {
    backoff_exponent: u8,
    retries: u8,
}

impl Default for CsmaState {
    fn default() -> Self {
        Self::new()
    }
}

impl CsmaState {
    /// Start a fresh contention attempt.
    #[inline]
    pub const fn new() -> Self {
        Self {
            backoff_exponent: 0,
            retries: 0,
        }
    }

    /// Restore a validated contention state.
    ///
    /// `CSMA_RETRY_LIMIT + 1` is the terminal exhausted state. Larger values
    /// cannot be produced and are rejected rather than truncated.
    pub const fn from_parts(backoff_exponent: u8, retries: u8) -> Result<Self, CsmaStateError> {
        if backoff_exponent > CSMA_BACKOFF_MAX {
            return Err(CsmaStateError::BackoffExponentOutOfRange);
        }
        if retries > CSMA_RETRY_LIMIT + 1 {
            return Err(CsmaStateError::RetryCountOutOfRange);
        }
        Ok(Self {
            backoff_exponent,
            retries,
        })
    }

    /// CAD timeout required by the LICHEN profile, in LoRa symbols.
    #[inline]
    pub const fn cad_timeout_symbols() -> u8 {
        CSMA_CAD_TIMEOUT_SYMBOLS
    }

    /// Current bounded backoff exponent.
    #[inline]
    pub const fn backoff_exponent(&self) -> u8 {
        self.backoff_exponent
    }

    /// Number of busy CAD results observed in this contention attempt.
    #[inline]
    pub const fn retries(&self) -> u8 {
        self.retries
    }

    /// Whether the retry limit has already been exceeded.
    #[inline]
    pub const fn is_exhausted(&self) -> bool {
        self.retries > CSMA_RETRY_LIMIT
    }

    /// Inclusive maximum slot index for the current contention window.
    #[inline]
    pub const fn contention_window(&self) -> u8 {
        // The exponent is validated at construction and bounded at transition.
        ((1u32 << self.backoff_exponent) - 1) as u8
    }

    /// Reset backoff and retry counters for a new contention attempt.
    #[inline]
    pub fn reset(&mut self) {
        self.backoff_exponent = 0;
        self.retries = 0;
    }

    /// Apply one CAD result and select the next operation.
    ///
    /// `random_draw` must be uniformly distributed across all `u32` values.
    /// Contention-window sizes are powers of two, so masking is an exact,
    /// modulo-bias-free mapping into `0..=CW`. The draw is ignored for an idle
    /// channel and after exhaustion.
    pub fn on_cad(&mut self, observation: CadObservation, random_draw: u32) -> CsmaAction {
        if observation == CadObservation::Idle {
            self.reset();
            return CsmaAction::Transmit;
        }

        if self.is_exhausted() {
            return CsmaAction::RetryExhausted;
        }

        self.retries += 1;
        if self.is_exhausted() {
            return CsmaAction::RetryExhausted;
        }

        self.backoff_exponent = self
            .backoff_exponent
            .saturating_add(1)
            .min(CSMA_BACKOFF_MAX);
        let slots = (random_draw & u32::from(self.contention_window())) as u8;
        let delay_ms = u32::from(slots) * CSMA_BACKOFF_UNIT_MS;
        CsmaAction::Backoff { slots, delay_ms }
    }
}

/// Convert an externally supplied slot count to milliseconds without overflow.
///
/// State-machine-generated slot counts are bounded by the contention window;
/// this checked helper is for persistence and scheduler boundaries that accept
/// a wider integer representation.
#[inline]
pub const fn checked_csma_backoff_ms(slots: u32) -> Option<u32> {
    slots.checked_mul(CSMA_BACKOFF_UNIT_MS)
}

/// Error returned when pushing to the TX queue fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxQueueError {
    /// Queue is at capacity and preemption not possible
    /// (new item has same or lower priority than all existing items).
    QueueFull,
    /// Payload exceeds maximum size.
    PayloadTooLarge,
    /// The supplied absolute deadline has already passed at the queue's
    /// monotonic time watermark.
    DeadlineExpired,
}

impl fmt::Display for TxQueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull => write!(f, "TX queue full"),
            Self::PayloadTooLarge => write!(f, "payload exceeds max size"),
            Self::DeadlineExpired => write!(f, "TX item deadline has expired"),
        }
    }
}

impl core::error::Error for TxQueueError {}

/// Maximum number of items in the TX queue (spec: 4 packets).
pub const TX_QUEUE_CAPACITY: usize = 4;

/// Default deadline for SOS/emergency messages (2 seconds).
pub const DEADLINE_SOS_MS: u64 = 2_000;

/// Default deadline for routing control messages (5 seconds).
pub const DEADLINE_ROUTING_MS: u64 = 5_000;

/// Default deadline for link-layer ACK/NACK (10 seconds).
///
/// spec/appendix-bufferbloat.md B.2.2. `TxPriority::Routing` covers ACK
/// traffic; callers pass this deadline explicitly (same as the Python
/// `Priority.ACK` alias).
pub const DEADLINE_ACK_MS: u64 = 10_000;

/// Default deadline for urgent/time-sensitive messages (30 seconds).
pub const DEADLINE_URGENT_MS: u64 = 30_000;

/// Default deadline for normal application data (60 seconds).
pub const DEADLINE_NORMAL_MS: u64 = 60_000;

/// Default deadline for bulk data (120 seconds).
pub const DEADLINE_BULK_MS: u64 = 120_000;

/// Maximum payload size for a queued item.
pub const TX_ITEM_MAX_PAYLOAD: usize = 255;

/// Priority levels for TX queue items.
///
/// Lower numeric value = higher priority (processed first).
/// Maps 1:1 to the spec's P0-P4 levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TxPriority {
    /// P0: Emergency traffic (SOS beacons). Highest priority.
    Sos = 0,
    /// P1: Routing protocol messages (RPL, LOADng, Announce, ACKs).
    Routing = 1,
    /// P2: Urgent/time-sensitive traffic (CoAP CON, tactical chat).
    Urgent = 2,
    /// P3: Normal application traffic (CoAP NON, telemetry, position).
    Normal = 3,
    /// P4: Bulk transfers (firmware updates, large data). Lowest priority.
    Bulk = 4,
}

impl TxPriority {
    /// Number of distinct priority levels.
    pub const COUNT: usize = 5;

    /// Convert from u8, returning None for invalid values.
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Sos),
            1 => Some(Self::Routing),
            2 => Some(Self::Urgent),
            3 => Some(Self::Normal),
            4 => Some(Self::Bulk),
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
    /// Greatest caller-supplied monotonic timestamp observed by the queue.
    /// Regressing clock samples are clamped to this watermark so expired
    /// entries cannot be admitted again after time has advanced.
    observed_now_ms: u64,
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
            observed_now_ms: 0,
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
        // Step 1: Expire stale items
        self.expire_before(now_ms);
        let effective_now_ms = self.observed_now_ms;
        if deadline_ms <= effective_now_ms {
            return Err(TxQueueError::DeadlineExpired);
        }
        let item = TxItem::new(priority, self.sequence, deadline_ms, effective_now_ms, data)
            .ok_or(TxQueueError::PayloadTooLarge)?;

        // Step 2: If not full, just push
        if self.heap.len() < TX_QUEUE_CAPACITY {
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
        self.observed_now_ms = self.observed_now_ms.max(now_ms);
        let effective_now_ms = self.observed_now_ms;
        // For a small queue (4 items), drain and rebuild is efficient
        let mut temp = heapless::Vec::<TxItem, TX_QUEUE_CAPACITY>::new();
        let mut expired_count = 0usize;

        while let Some(item) = self.heap.pop() {
            if item.is_expired(effective_now_ms) {
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
        self.expire_before(now_ms);
        let item = self.heap.pop()?;
        self.bytes_pending -= item.len();
        self.by_priority[item.priority as usize] -= 1;

        // Compute latency and update statistics
        let latency_ms = self
            .observed_now_ms
            .saturating_sub(item.enqueue_time_ms)
            .min(u64::from(u32::MAX)) as u32;
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

    /// Pop the highest priority item that is allowed at the given congestion level.
    ///
    /// This method integrates TX queue with duty cycle gating per spec 07 section 10.2.3:
    /// - NORMAL: all priorities allowed (P0-P4)
    /// - ELEVATED: only P0-P2 (SOS, ROUTING, URGENT)
    /// - CRITICAL: only P0-P1 (SOS, ROUTING)
    /// - EXHAUSTED: nothing allowed
    ///
    /// Items that are not allowed remain in the queue for later transmission
    /// when congestion eases. Expired items are removed regardless of congestion.
    ///
    /// Returns `None` if the queue is empty or no items are allowed.
    pub fn pop_if_allowed(&mut self, now_ms: u64, level: CongestionLevel) -> Option<TxItem> {
        // First, expire stale items
        self.expire_before(now_ms);

        // If exhausted, nothing is allowed
        if level == CongestionLevel::Exhausted {
            return None;
        }

        // Check if the top item is allowed
        if let Some(top) = self.heap.peek() {
            if check_congestion_allows(level, top.priority) {
                return self.pop(now_ms);
            }
        }

        // Top item not allowed - search for the highest priority item that IS allowed.
        // This requires draining and rebuilding the heap (small queue, so acceptable).
        let mut temp = heapless::Vec::<TxItem, TX_QUEUE_CAPACITY>::new();
        let mut found: Option<TxItem> = None;

        while let Some(item) = self.heap.pop() {
            if found.is_none() && check_congestion_allows(level, item.priority) {
                // Found an allowed item - take it
                self.bytes_pending -= item.len();
                self.by_priority[item.priority as usize] -= 1;

                // Update latency stats
                let latency_ms = self
                    .observed_now_ms
                    .saturating_sub(item.enqueue_time_ms)
                    .min(u64::from(u32::MAX)) as u32;
                if latency_ms > self.max_latency_ms {
                    self.max_latency_ms = latency_ms;
                }
                self.avg_latency_scaled = self
                    .avg_latency_scaled
                    .saturating_sub(self.avg_latency_scaled / 8)
                    .saturating_add(latency_ms);

                found = Some(item);
            } else {
                // Not allowed or already found one - keep for later
                temp.push(item).ok();
            }
        }

        // Put remaining items back
        for item in temp {
            self.heap.push(item).ok();
        }

        found
    }

    /// Pop a packet only when both CSMA/CA and duty-cycle policy allow TX.
    ///
    /// Backoff and exhausted actions leave the queue unchanged. A transmit
    /// action delegates to [`Self::pop_if_allowed`], preserving deadline expiry,
    /// congestion gating, priority ordering, and queue statistics.
    #[inline]
    pub fn pop_after_csma(
        &mut self,
        now_ms: u64,
        level: CongestionLevel,
        action: CsmaAction,
    ) -> Option<TxItem> {
        if !action.tx_allowed() {
            return None;
        }
        self.pop_if_allowed(now_ms, level)
    }

    /// Check if any item in the queue is allowed at the given congestion level.
    ///
    /// Expired items are removed before the congestion policy is evaluated.
    #[inline]
    pub fn has_allowed(&mut self, now_ms: u64, level: CongestionLevel) -> bool {
        self.expire_before(now_ms);
        if level == CongestionLevel::Exhausted {
            return false;
        }
        self.heap
            .iter()
            .any(|item| check_congestion_allows(level, item.priority))
    }

    /// Peek at the highest priority item without removing it.
    #[inline]
    pub fn peek(&mut self, now_ms: u64) -> Option<&TxItem> {
        self.expire_before(now_ms);
        self.heap.peek()
    }

    /// Count unexpired items at `now_ms`.
    #[inline]
    pub fn count(&mut self, now_ms: u64) -> usize {
        self.expire_before(now_ms);
        self.heap.len()
    }

    /// Check if the queue has no unexpired items at `now_ms`.
    #[inline]
    pub fn is_empty(&mut self, now_ms: u64) -> bool {
        self.count(now_ms) == 0
    }

    /// Check if the unexpired queue is full at `now_ms`.
    #[inline]
    pub fn is_full(&mut self, now_ms: u64) -> bool {
        self.expire_before(now_ms);
        self.heap.len() >= TX_QUEUE_CAPACITY
    }

    /// Get physical queue depth without advancing the queue clock.
    ///
    /// Prefer [`Self::count`] when a current timestamp is available. All
    /// time-bearing queue operations prune expiry before returning.
    #[inline]
    #[allow(clippy::len_without_is_empty)]
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
    fn csma_idle_allows_tx_and_resets_contention() {
        let mut state = CsmaState::from_parts(3, 2).unwrap();

        let action = state.on_cad(CadObservation::Idle, u32::MAX);

        assert_eq!(action, CsmaAction::Transmit);
        assert!(action.tx_allowed());
        assert_eq!(state.backoff_exponent(), 0);
        assert_eq!(state.retries(), 0);
        assert!(!state.is_exhausted());
        assert_eq!(CsmaState::cad_timeout_symbols(), 3);
    }

    #[test]
    fn csma_busy_uses_exact_random_window_boundaries() {
        let mut low = CsmaState::new();
        assert_eq!(
            low.on_cad(CadObservation::Busy, 0),
            CsmaAction::Backoff {
                slots: 0,
                delay_ms: 0,
            }
        );
        assert_eq!(low.backoff_exponent(), 1);
        assert_eq!(low.retries(), 1);
        assert_eq!(low.contention_window(), 1);

        let mut high = CsmaState::new();
        assert_eq!(
            high.on_cad(CadObservation::Busy, u32::MAX),
            CsmaAction::Backoff {
                slots: 1,
                delay_ms: 10,
            }
        );
        assert_eq!(
            high.on_cad(CadObservation::Busy, u32::MAX),
            CsmaAction::Backoff {
                slots: 3,
                delay_ms: 30,
            }
        );
        assert_eq!(high.backoff_exponent(), 2);
        assert_eq!(high.retries(), 2);
        assert_eq!(high.contention_window(), 3);
    }

    #[test]
    fn csma_backoff_exponent_saturates_at_profile_maximum() {
        let mut state = CsmaState::from_parts(CSMA_BACKOFF_MAX, 0).unwrap();

        assert_eq!(
            state.on_cad(CadObservation::Busy, u32::MAX),
            CsmaAction::Backoff {
                slots: 31,
                delay_ms: 310,
            }
        );
        assert_eq!(state.backoff_exponent(), CSMA_BACKOFF_MAX);
        assert_eq!(state.contention_window(), 31);
    }

    #[test]
    fn csma_fourth_busy_result_exhausts_and_is_idempotent() {
        let mut state = CsmaState::from_parts(5, CSMA_RETRY_LIMIT).unwrap();

        assert_eq!(
            state.on_cad(CadObservation::Busy, u32::MAX),
            CsmaAction::RetryExhausted
        );
        assert_eq!(state.retries(), CSMA_RETRY_LIMIT + 1);
        assert_eq!(state.backoff_exponent(), 5);
        assert!(state.is_exhausted());

        assert_eq!(
            state.on_cad(CadObservation::Busy, 0),
            CsmaAction::RetryExhausted
        );
        assert_eq!(state.retries(), CSMA_RETRY_LIMIT + 1);

        assert_eq!(state.on_cad(CadObservation::Idle, 0), CsmaAction::Transmit);
        assert_eq!(state, CsmaState::new());
    }

    #[test]
    fn csma_restore_and_delay_math_reject_overflow() {
        assert_eq!(
            CsmaState::from_parts(CSMA_BACKOFF_MAX + 1, 0),
            Err(CsmaStateError::BackoffExponentOutOfRange)
        );
        assert_eq!(
            CsmaState::from_parts(0, CSMA_RETRY_LIMIT + 2),
            Err(CsmaStateError::RetryCountOutOfRange)
        );
        assert_eq!(checked_csma_backoff_ms(31), Some(310));
        assert_eq!(checked_csma_backoff_ms(u32::MAX), None);
    }

    #[test]
    fn csma_action_directly_gates_queue_dequeue() {
        let mut queue = TxQueue::new();
        let now = 1_000;
        queue
            .push(TxPriority::Normal, now + DEADLINE_NORMAL_MS, now, b"data")
            .unwrap();

        assert!(queue
            .pop_after_csma(
                now,
                CongestionLevel::Normal,
                CsmaAction::Backoff {
                    slots: 1,
                    delay_ms: 10,
                },
            )
            .is_none());
        assert_eq!(queue.len(), 1);

        let item = queue
            .pop_after_csma(now, CongestionLevel::Normal, CsmaAction::Transmit)
            .unwrap();
        assert_eq!(item.data(), b"data");
        assert!(queue.is_empty(now));
    }

    #[test]
    fn empty_queue_stats() {
        let queue = TxQueue::new();
        let stats = queue.stats();

        assert_eq!(stats.depth, 0);
        assert_eq!(stats.bytes_pending, 0);
        assert_eq!(stats.by_priority, [0, 0, 0, 0, 0]);
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
        let deadline = now + DEADLINE_NORMAL_MS;

        queue
            .push(TxPriority::Normal, deadline, now, b"hello")
            .unwrap();
        assert_eq!(queue.len(), 1);

        let pop_time = now + 50; // 50ms later
        let item = queue.pop(pop_time).unwrap();
        assert_eq!(item.data(), b"hello");
        assert_eq!(item.priority, TxPriority::Normal);
        assert_eq!(item.deadline_ms, deadline);
        assert!(queue.is_empty(pop_time));
    }

    #[test]
    fn priority_ordering() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        // Push in reverse priority order (all 4 slots)
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk")
            .unwrap();
        queue
            .push(TxPriority::Normal, deadline, now, b"normal")
            .unwrap();
        queue
            .push(TxPriority::Routing, deadline, now, b"routing")
            .unwrap();
        queue.push(TxPriority::Sos, deadline, now, b"sos").unwrap();

        // Should pop in priority order (lowest enum value first)
        assert_eq!(queue.pop(now).unwrap().priority, TxPriority::Sos);
        assert_eq!(queue.pop(now).unwrap().priority, TxPriority::Routing);
        assert_eq!(queue.pop(now).unwrap().priority, TxPriority::Normal);
        assert_eq!(queue.pop(now).unwrap().priority, TxPriority::Bulk);
    }

    #[test]
    fn fifo_within_priority() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        queue
            .push(TxPriority::Normal, deadline, now, b"first")
            .unwrap();
        queue
            .push(TxPriority::Normal, deadline, now, b"second")
            .unwrap();
        queue
            .push(TxPriority::Normal, deadline, now, b"third")
            .unwrap();

        assert_eq!(queue.pop(now).unwrap().data(), b"first");
        assert_eq!(queue.pop(now).unwrap().data(), b"second");
        assert_eq!(queue.pop(now).unwrap().data(), b"third");
    }

    #[test]
    fn stats_tracking() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        queue.push(TxPriority::Sos, deadline, now, b"sos").unwrap();
        queue
            .push(TxPriority::Normal, deadline, now, b"hello world")
            .unwrap();
        queue
            .push(TxPriority::Normal, deadline, now, b"test")
            .unwrap();
        queue
            .push(TxPriority::Bulk, deadline, now, b"data")
            .unwrap();

        let stats = queue.stats();
        assert_eq!(stats.depth, 4);
        assert_eq!(stats.bytes_pending, 3 + 11 + 4 + 4); // 22
        assert_eq!(stats.by_priority[TxPriority::Sos as usize], 1);
        assert_eq!(stats.by_priority[TxPriority::Routing as usize], 0);
        assert_eq!(stats.by_priority[TxPriority::Normal as usize], 2);
        assert_eq!(stats.by_priority[TxPriority::Bulk as usize], 1);
        assert_eq!(stats.packets_queued, 4);

        // Pop one and verify stats update
        queue.pop(now);
        let stats = queue.stats();
        assert_eq!(stats.depth, 3);
        assert_eq!(stats.bytes_pending, 19); // 22 - 3
        assert_eq!(stats.by_priority[TxPriority::Sos as usize], 0);
    }

    #[test]
    fn estimated_drain_time() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        // 100 bytes total
        queue
            .push(TxPriority::Normal, deadline, now, &[0u8; 100])
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
        let deadline = now + DEADLINE_NORMAL_MS;

        // 1 byte at 1 us/byte = 1 us, should round up to 1 ms
        queue
            .push(TxPriority::Normal, deadline, now, &[0u8; 1])
            .unwrap();
        assert_eq!(queue.estimated_drain_time_ms(1), 1);
    }

    #[test]
    fn queue_full_error() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        // Fill queue with same priority items
        for i in 0..TX_QUEUE_CAPACITY {
            queue
                .push(TxPriority::Normal, deadline, now, &[i as u8])
                .unwrap();
        }

        assert!(queue.is_full(now));
        // Same priority cannot preempt, should fail
        assert!(queue
            .push(TxPriority::Normal, deadline, now, b"overflow")
            .is_err());
        // Lower priority (Bulk) cannot preempt Normal, should fail
        assert!(queue
            .push(TxPriority::Bulk, deadline, now, b"bulk")
            .is_err());
    }

    #[test]
    fn priority_from_u8() {
        assert_eq!(TxPriority::from_u8(0), Some(TxPriority::Sos));
        assert_eq!(TxPriority::from_u8(1), Some(TxPriority::Routing));
        assert_eq!(TxPriority::from_u8(2), Some(TxPriority::Urgent));
        assert_eq!(TxPriority::from_u8(3), Some(TxPriority::Normal));
        assert_eq!(TxPriority::from_u8(4), Some(TxPriority::Bulk));
        assert_eq!(TxPriority::from_u8(5), None);
        assert_eq!(TxPriority::from_u8(255), None);
    }

    #[test]
    fn peek_does_not_modify() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        queue
            .push(TxPriority::Normal, deadline, now, b"data")
            .unwrap();

        assert_eq!(queue.peek(now).unwrap().data(), b"data");
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.peek(now).unwrap().data(), b"data");
    }

    #[test]
    fn fifo_across_sequence_wrap() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        // Set sequence counter near wrap point
        queue.sequence = u32::MAX - 1;

        // Push items that span the wrap (fills the queue of 4)
        queue
            .push(TxPriority::Normal, deadline, now, b"before_wrap_1")
            .unwrap(); // seq = MAX-1
        queue
            .push(TxPriority::Normal, deadline, now, b"before_wrap_2")
            .unwrap(); // seq = MAX
        queue
            .push(TxPriority::Normal, deadline, now, b"after_wrap_1")
            .unwrap(); // seq = 0 (wrapped)
        queue
            .push(TxPriority::Normal, deadline, now, b"after_wrap_2")
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
            .push(TxPriority::Normal, now + 100, now, b"short_lived")
            .unwrap();
        // Push item that expires at now + 10000
        queue
            .push(TxPriority::Normal, now + 10000, now, b"long_lived")
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
            .push(TxPriority::Normal, now + 100, now, b"will_expire")
            .unwrap();
        // Fill rest of queue
        queue
            .push(TxPriority::Normal, now + 10000, now, b"keeper1")
            .unwrap();
        queue
            .push(TxPriority::Normal, now + 10000, now, b"keeper2")
            .unwrap();
        queue
            .push(TxPriority::Normal, now + 10000, now, b"keeper3")
            .unwrap();

        assert!(queue.is_full(now));

        // Push new item after first one expired - should succeed due to expiry
        let later = now + 500;
        queue
            .push(TxPriority::Normal, later + 10000, later, b"new_item")
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
        let deadline = now + DEADLINE_NORMAL_MS;

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

        assert!(queue.is_full(now));

        // Higher priority (Sos) should preempt
        queue
            .push(TxPriority::Sos, deadline, now, b"urgent")
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
        let deadline = now + DEADLINE_NORMAL_MS;

        // Fill with mixed priorities
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk_oldest")
            .unwrap();
        queue
            .push(TxPriority::Normal, deadline, now, b"normal")
            .unwrap();
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk_newer")
            .unwrap();
        queue
            .push(TxPriority::Normal, deadline, now, b"normal2")
            .unwrap();

        assert!(queue.is_full(now));

        // Push higher priority item
        queue.push(TxPriority::Sos, deadline, now, b"sos").unwrap();

        // Should have preempted oldest Bulk item
        let stats = queue.stats();
        assert_eq!(stats.packets_preempted, 1);

        // Pop all and verify bulk_oldest is gone but bulk_newer remains
        let mut items: std::vec::Vec<_> = std::vec::Vec::new();
        while let Some(item) = queue.pop(now) {
            items.push(item);
        }

        let payloads: std::vec::Vec<_> = items.iter().map(|i| i.data()).collect();
        assert!(payloads.contains(&b"sos".as_slice()));
        assert!(payloads.contains(&b"normal".as_slice()));
        assert!(payloads.contains(&b"bulk_newer".as_slice()));
        assert!(payloads.contains(&b"normal2".as_slice()));
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
        assert_eq!(DEADLINE_SOS_MS, 2_000);
        assert_eq!(DEADLINE_ROUTING_MS, 5_000);
        assert_eq!(DEADLINE_ACK_MS, 10_000);
        assert_eq!(DEADLINE_URGENT_MS, 30_000);
        assert_eq!(DEADLINE_NORMAL_MS, 60_000);
        assert_eq!(DEADLINE_BULK_MS, 120_000);
    }

    #[test]
    fn packets_queued_counter() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        // Push 3 items
        queue
            .push(TxPriority::Normal, deadline, now, b"one")
            .unwrap();
        queue
            .push(TxPriority::Normal, deadline, now, b"two")
            .unwrap();
        queue
            .push(TxPriority::Normal, deadline, now, b"three")
            .unwrap();

        let stats = queue.stats();
        assert_eq!(stats.packets_queued, 3);

        // Pop one and push another - counter should still increment
        queue.pop(now);
        queue
            .push(TxPriority::Normal, deadline, now, b"four")
            .unwrap();

        let stats = queue.stats();
        assert_eq!(stats.packets_queued, 4); // Cumulative, not current depth
        assert_eq!(stats.depth, 3);
    }

    #[test]
    fn packets_dropped_full_counter() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        // Fill queue with same priority items (4 slots)
        for i in 0..TX_QUEUE_CAPACITY {
            queue
                .push(TxPriority::Normal, deadline, now, &[i as u8])
                .unwrap();
        }

        // Try to push more - these should fail and increment dropped counter
        assert!(queue
            .push(TxPriority::Normal, deadline, now, b"drop1")
            .is_err());
        assert!(queue
            .push(TxPriority::Bulk, deadline, now, b"drop2")
            .is_err());
        assert!(queue
            .push(TxPriority::Normal, deadline, now, b"drop3")
            .is_err());

        let stats = queue.stats();
        assert_eq!(stats.packets_dropped_full, 3);
        assert_eq!(stats.packets_queued, 4); // Only the successful pushes
    }

    #[test]
    fn latency_tracking_basic() {
        let mut queue = TxQueue::new();
        let enqueue_time = 1000u64;
        let deadline = enqueue_time + DEADLINE_NORMAL_MS;

        queue
            .push(TxPriority::Normal, deadline, enqueue_time, b"test")
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
        let deadline = now + DEADLINE_NORMAL_MS;

        // Push three items
        queue.push(TxPriority::Normal, deadline, now, b"a").unwrap();
        queue
            .push(TxPriority::Normal, deadline, now + 50, b"b")
            .unwrap();
        queue
            .push(TxPriority::Normal, deadline, now + 100, b"c")
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
        let deadline = now + DEADLINE_NORMAL_MS;

        // Push and pop multiple items with consistent latency to observe EWMA behavior
        // EWMA formula: scaled = scaled - scaled/8 + sample
        // Display: avg = scaled / 8

        // Sample 1: 80ms -> scaled = 0 - 0 + 80 = 80 -> avg = 10
        queue.push(TxPriority::Normal, deadline, now, b"1").unwrap();
        queue.pop(now + 80);
        assert_eq!(queue.stats().avg_latency_ms, 10);

        // Sample 2: 80ms -> scaled = 80 - 10 + 80 = 150 -> avg = 18
        queue
            .push(TxPriority::Normal, deadline, now + 100, b"2")
            .unwrap();
        queue.pop(now + 180);
        assert_eq!(queue.stats().avg_latency_ms, 18);

        // Sample 3: 80ms -> scaled = 150 - 18 + 80 = 212 -> avg = 26
        queue
            .push(TxPriority::Normal, deadline, now + 200, b"3")
            .unwrap();
        queue.pop(now + 280);
        assert_eq!(queue.stats().avg_latency_ms, 26);
    }

    #[test]
    fn enqueue_time_accessor() {
        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        queue
            .push(TxPriority::Normal, deadline, now, b"test")
            .unwrap();

        let item = queue.pop(now + 50).unwrap();
        assert_eq!(item.enqueue_time_ms(), now);
    }

    // --- Duty cycle integration tests (spec 07 section 10.2.3) ---

    #[test]
    fn pop_if_allowed_normal_allows_all() {
        use crate::duty_cycle::CongestionLevel;

        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk")
            .unwrap();

        // NORMAL level allows all priorities including Bulk
        let item = queue.pop_if_allowed(now, CongestionLevel::Normal).unwrap();
        assert_eq!(item.priority, TxPriority::Bulk);
        assert!(queue.is_empty(now));
    }

    #[test]
    fn pop_if_allowed_elevated_blocks_low_priority() {
        use crate::duty_cycle::CongestionLevel;

        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        // Queue has only low-priority items
        queue
            .push(TxPriority::Normal, deadline, now, b"normal")
            .unwrap();
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk")
            .unwrap();

        // ELEVATED blocks NORMAL and BULK
        assert!(queue
            .pop_if_allowed(now, CongestionLevel::Elevated)
            .is_none());
        // Items should still be in queue
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn pop_if_allowed_elevated_allows_urgent() {
        use crate::duty_cycle::CongestionLevel;

        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk")
            .unwrap();
        queue
            .push(TxPriority::Urgent, deadline, now, b"urgent")
            .unwrap();
        queue
            .push(TxPriority::Normal, deadline, now, b"normal")
            .unwrap();

        // ELEVATED allows Urgent, should skip over Bulk and Normal
        let item = queue
            .pop_if_allowed(now, CongestionLevel::Elevated)
            .unwrap();
        assert_eq!(item.priority, TxPriority::Urgent);
        assert_eq!(queue.len(), 2); // Bulk and Normal remain
    }

    #[test]
    fn pop_if_allowed_critical_only_sos_routing() {
        use crate::duty_cycle::CongestionLevel;

        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        queue
            .push(TxPriority::Urgent, deadline, now, b"urgent")
            .unwrap();
        queue
            .push(TxPriority::Routing, deadline, now, b"routing")
            .unwrap();

        // CRITICAL only allows Routing (and SOS), blocks Urgent
        let item = queue
            .pop_if_allowed(now, CongestionLevel::Critical)
            .unwrap();
        assert_eq!(item.priority, TxPriority::Routing);

        // Urgent should remain
        assert_eq!(queue.len(), 1);
        assert!(queue
            .pop_if_allowed(now, CongestionLevel::Critical)
            .is_none());
    }

    #[test]
    fn pop_if_allowed_exhausted_blocks_all() {
        use crate::duty_cycle::CongestionLevel;

        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        // Even SOS is blocked at EXHAUSTED
        queue.push(TxPriority::Sos, deadline, now, b"sos").unwrap();

        assert!(queue
            .pop_if_allowed(now, CongestionLevel::Exhausted)
            .is_none());
        assert_eq!(queue.len(), 1); // Item remains
    }

    #[test]
    fn pop_if_allowed_finds_allowed_item_behind_blocked() {
        use crate::duty_cycle::CongestionLevel;

        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        // Sos has highest priority, but let's verify we can find routing behind bulk
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk1")
            .unwrap();
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk2")
            .unwrap();
        queue.push(TxPriority::Sos, deadline, now, b"sos").unwrap();

        // At CRITICAL, only SOS/ROUTING allowed
        // Since heap orders by priority, SOS should be at top anyway
        let item = queue
            .pop_if_allowed(now, CongestionLevel::Critical)
            .unwrap();
        assert_eq!(item.priority, TxPriority::Sos);

        // Now only bulk items remain, should return None
        assert!(queue
            .pop_if_allowed(now, CongestionLevel::Critical)
            .is_none());
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn pop_if_allowed_updates_latency_stats() {
        use crate::duty_cycle::CongestionLevel;

        let mut queue = TxQueue::new();
        let enqueue_time = 1000u64;
        let deadline = enqueue_time + DEADLINE_NORMAL_MS;

        queue
            .push(TxPriority::Sos, deadline, enqueue_time, b"sos")
            .unwrap();

        // Pop 200ms later
        let pop_time = enqueue_time + 200;
        let _item = queue
            .pop_if_allowed(pop_time, CongestionLevel::Normal)
            .unwrap();

        let stats = queue.stats();
        assert_eq!(stats.max_latency_ms, 200);
    }

    #[test]
    fn has_allowed_check() {
        use crate::duty_cycle::CongestionLevel;

        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        // Empty queue
        assert!(!queue.has_allowed(now, CongestionLevel::Normal));

        // Add bulk item
        queue
            .push(TxPriority::Bulk, deadline, now, b"bulk")
            .unwrap();

        assert!(queue.has_allowed(now, CongestionLevel::Normal));
        assert!(!queue.has_allowed(now, CongestionLevel::Elevated)); // Bulk not allowed
        assert!(!queue.has_allowed(now, CongestionLevel::Critical));
        assert!(!queue.has_allowed(now, CongestionLevel::Exhausted));

        // Add SOS item
        queue.push(TxPriority::Sos, deadline, now, b"sos").unwrap();

        assert!(queue.has_allowed(now, CongestionLevel::Normal));
        assert!(queue.has_allowed(now, CongestionLevel::Elevated));
        assert!(queue.has_allowed(now, CongestionLevel::Critical));
        assert!(!queue.has_allowed(now, CongestionLevel::Exhausted)); // Nothing allowed
    }

    #[test]
    fn pop_if_allowed_preserves_fifo_within_priority() {
        use crate::duty_cycle::CongestionLevel;

        let mut queue = TxQueue::new();
        let now = 1000u64;
        let deadline = now + DEADLINE_NORMAL_MS;

        // Add multiple SOS items - should preserve FIFO order
        queue
            .push(TxPriority::Sos, deadline, now, b"first")
            .unwrap();
        queue
            .push(TxPriority::Sos, deadline, now, b"second")
            .unwrap();
        queue
            .push(TxPriority::Sos, deadline, now, b"third")
            .unwrap();

        assert_eq!(
            queue
                .pop_if_allowed(now, CongestionLevel::Critical)
                .unwrap()
                .data(),
            b"first"
        );
        assert_eq!(
            queue
                .pop_if_allowed(now, CongestionLevel::Critical)
                .unwrap()
                .data(),
            b"second"
        );
        assert_eq!(
            queue
                .pop_if_allowed(now, CongestionLevel::Critical)
                .unwrap()
                .data(),
            b"third"
        );
    }

    #[test]
    fn pop_if_allowed_empty_queue() {
        use crate::duty_cycle::CongestionLevel;

        let mut queue = TxQueue::new();
        assert!(queue
            .pop_if_allowed(1000, CongestionLevel::Normal)
            .is_none());
    }

    #[test]
    fn pop_discards_all_expired_items() {
        let mut queue = TxQueue::new();
        queue.push(TxPriority::Sos, 100, 0, b"sos").unwrap();
        queue.push(TxPriority::Normal, 200, 0, b"normal").unwrap();

        assert!(queue.pop(200).is_none());
        assert_eq!(queue.count(200), 0);
        assert!(queue.is_empty(200));
        assert_eq!(queue.stats().packets_dropped_deadline, 2);
    }

    #[test]
    fn pop_skips_expired_higher_priority_and_preserves_live_order() {
        let mut queue = TxQueue::new();
        queue.push(TxPriority::Sos, 100, 0, b"expired-sos").unwrap();
        queue
            .push(TxPriority::Normal, 1_000, 0, b"live-first")
            .unwrap();
        queue
            .push(TxPriority::Normal, 1_000, 0, b"live-second")
            .unwrap();

        assert_eq!(queue.pop(100).unwrap().data(), b"live-first");
        assert_eq!(queue.peek(100).unwrap().data(), b"live-second");
        assert_eq!(queue.count(100), 1);
    }

    #[test]
    fn observers_expire_at_exact_deadline_boundary() {
        let mut pop_queue = TxQueue::new();
        pop_queue
            .push(TxPriority::Normal, 200, 100, b"boundary")
            .unwrap();
        assert_eq!(pop_queue.peek(199).unwrap().data(), b"boundary");
        assert!(pop_queue.peek(200).is_none());

        let mut count_queue = TxQueue::new();
        count_queue
            .push(TxPriority::Normal, 200, 100, b"boundary")
            .unwrap();
        assert_eq!(count_queue.count(199), 1);
        assert_eq!(count_queue.count(200), 0);
        assert!(count_queue.is_empty(200));
    }

    #[test]
    fn regressing_clock_cannot_resurrect_or_admit_stale_items() {
        let mut queue = TxQueue::new();
        queue
            .push(TxPriority::Normal, 900, 100, b"expires")
            .unwrap();
        assert_eq!(queue.count(1_000), 0);

        assert_eq!(
            queue.push(TxPriority::Normal, 700, 500, b"already-stale"),
            Err(TxQueueError::DeadlineExpired)
        );
        assert!(queue.peek(500).is_none());
        assert_eq!(queue.stats().packets_queued, 1);
        assert_eq!(queue.stats().packets_dropped_deadline, 1);
    }

    #[test]
    fn expired_capacity_is_reclaimed_by_observers() {
        let mut queue = TxQueue::new();
        for value in 0..TX_QUEUE_CAPACITY {
            queue
                .push(TxPriority::Normal, 100, 0, &[value as u8])
                .unwrap();
        }
        assert_eq!(queue.len(), TX_QUEUE_CAPACITY);

        assert_eq!(queue.count(100), 0);
        assert!(!queue.is_full(100));
        queue
            .push(TxPriority::Normal, 1_000, 100, b"replacement")
            .unwrap();
        assert_eq!(queue.count(100), 1);
        assert_eq!(queue.pop(100).unwrap().data(), b"replacement");
    }
}
