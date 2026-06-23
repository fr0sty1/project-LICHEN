//! Replay-protection window (spec §5).
//!
//! Tracks seen (epoch, seqnum) pairs for one peer using a 64-slot bitmask
//! window.  A frame is accepted if its sequence number falls within the window
//! and has not been seen before, OR if it advances the window.

/// A 64-slot replay window for one (peer, epoch) context.
///
/// Bit layout: bit 0 of `window` represents `last_seq`; bit `i` represents
/// `last_seq - i`.  A set bit means that sequence number was already accepted.
///
/// `last_seq` is stored as a plain u16; sequence number arithmetic wraps
/// modulo 65536. The caller must handle epoch transitions (discard this
/// window and create a fresh one when the epoch advances).
#[derive(Debug)]
pub struct ReplayWindow {
    /// Highest sequence number accepted so far.
    last_seq: u16,
    /// Bitmask of accepted sequence numbers relative to `last_seq`.
    /// Bit 0 = last_seq, bit 1 = last_seq-1, ..., bit 63 = last_seq-63.
    window: u64,
    /// True once at least one sequence number has been accepted (to
    /// distinguish "last_seq = 0 never seen" from "last_seq = 0 was seen").
    initialised: bool,
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            last_seq: 0,
            window: 0,
            initialised: false,
        }
    }

    /// Check `seq` and record it if accepted.
    ///
    /// Returns `true` if the frame should be processed; `false` if it is a
    /// replay or too old to check (outside the 64-slot window).
    pub fn accept(&mut self, seq: u16) -> bool {
        if !self.initialised {
            self.last_seq = seq;
            self.window = 1;
            self.initialised = true;
            return true;
        }

        // Signed distance: positive means seq is newer than last_seq.
        // Use i32 arithmetic to handle wrapping correctly.
        let diff = (seq as i32) - (self.last_seq as i32);
        // Normalise to [-32768, 32767] range (half the u16 space).
        let diff = if diff > 32767 {
            diff - 65536
        } else if diff < -32768 {
            diff + 65536
        } else {
            diff
        };

        if diff > 0 {
            // Newer than anything we've seen: advance the window.
            let shift = diff as u32;
            self.window = if shift >= 64 {
                // Entire window is beyond what we've seen; reset it.
                1
            } else {
                (self.window << shift) | 1
            };
            self.last_seq = seq;
            true
        } else if diff == 0 {
            // Exact duplicate of last_seq.
            false
        } else {
            // Older than last_seq: check the bitmask.
            let offset = (-diff) as u32;
            if offset >= 64 {
                // Outside the window — too old to verify, reject.
                return false;
            }
            let bit = 1u64 << offset;
            if self.window & bit != 0 {
                // Already seen.
                false
            } else {
                self.window |= bit;
                true
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_always_accepted() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(100));
    }

    #[test]
    fn duplicate_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(5));
        assert!(!w.accept(5));
    }

    #[test]
    fn in_order_sequence() {
        let mut w = ReplayWindow::new();
        for i in 0u16..128 {
            assert!(w.accept(i), "should accept {i}");
        }
    }

    #[test]
    fn out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        // Accept 10, then out-of-order 5, then 10 again (duplicate).
        assert!(w.accept(10));
        assert!(w.accept(5));
        assert!(!w.accept(5)); // replay
        assert!(!w.accept(10)); // replay
        assert!(w.accept(11));
    }

    #[test]
    fn too_old_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(100));
        // Advance window past slot 0.
        assert!(w.accept(164)); // 64 slots ahead
        // seq=100 is now 64 slots behind last_seq=164 — exactly at the edge.
        // offset = 64, which is >= 64, so rejected.
        assert!(!w.accept(100));
        assert!(!w.accept(50)); // way too old
    }

    #[test]
    fn window_boundary_accepted() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(63));
        assert!(w.accept(0)); // 63 slots back — last slot in window
        assert!(!w.accept(0)); // replay
    }

    #[test]
    fn sequence_wraps_u16() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0xFFFE));
        assert!(w.accept(0xFFFF));
        assert!(w.accept(0x0000)); // wraps around
        assert!(w.accept(0x0001));
        assert!(!w.accept(0xFFFF)); // replay in wrapped window
    }

    #[test]
    fn large_gap_resets_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(200)); // gap > 64, resets window
        assert!(!w.accept(0)); // 0 is now 200 slots back — outside window
        assert!(w.accept(199)); // just inside window (offset = 1)
    }
}
