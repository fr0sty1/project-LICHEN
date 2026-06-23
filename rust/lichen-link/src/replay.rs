//! Replay-protection window (spec section 4.4).
//!
//! Tracks seen (epoch, seqnum) pairs using a fixed-size bitmask window.
//! Stub — full implementation is future work.

/// A 64-slot replay window for one peer.
///
/// Accepts a sequence number if it is within the window and has not been seen.
/// The window advances when a newer sequence number is accepted.
#[allow(dead_code)] // fields used by the full implementation (future work)
pub struct ReplayWindow {
    last_seq: u16,
    window: u64, // bit i set => (last_seq - i) was seen
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            last_seq: 0,
            window: 0,
        }
    }

    /// Check and record `seq`. Returns `true` if the packet should be accepted.
    pub fn accept(&mut self, seq: u16) -> bool {
        // Stub: always accept (real implementation tracks the bitmask).
        let _ = seq;
        true
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}
