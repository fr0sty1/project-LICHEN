//! Replay-protection window (spec §5).
//!
//! Tracks seen (epoch, seqnum) pairs for one peer using a 32-slot bitmask
//! window. A frame is accepted if its sequence number falls within the window
//! and has not been seen before, OR if it advances the window.

use crate::seqnum::LinkSeqNum;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayWindowState {
    Empty,
    Tracking,
}

impl ReplayWindowState {
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Empty, Self::Tracking) | (Self::Tracking, Self::Tracking)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidReplayWindowTransition {
    pub from: ReplayWindowState,
    pub to: ReplayWindowState,
}

/// A 32-slot replay window for one (peer, epoch) context.
///
/// Bit layout: bit 0 of `window` represents `last_seq`; bit `i` represents
/// `last_seq - i`.  A set bit means that sequence number was already accepted.
///
/// `last_seq` stores the highest accepted sequence number. Sequence numbers do
/// not wrap within an epoch. The caller must discard this window and create a
/// fresh one when the epoch advances.
#[derive(Debug)]
pub struct ReplayWindow {
    /// Highest sequence number accepted so far.
    last_seq: LinkSeqNum,
    /// Bitmask of accepted sequence numbers relative to `last_seq`.
    /// Bit 0 = last_seq, bit 1 = last_seq-1, ..., bit 31 = last_seq-31.
    window: u32,
    /// True once at least one sequence number has been accepted (to
    /// distinguish "last_seq = 0 never seen" from "last_seq = 0 was seen").
    initialised: bool,
    state: ReplayWindowState,
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            last_seq: LinkSeqNum::new(0),
            window: 0,
            initialised: false,
            state: ReplayWindowState::Empty,
        }
    }

    pub fn state(&self) -> ReplayWindowState {
        self.state
    }

    fn transition_to(
        &mut self,
        next: ReplayWindowState,
    ) -> Result<(), InvalidReplayWindowTransition> {
        if self.state.can_transition_to(next) {
            self.state = next;
            Ok(())
        } else {
            Err(InvalidReplayWindowTransition {
                from: self.state,
                to: next,
            })
        }
    }

    /// Check `seq` and record it if accepted.
    ///
    /// Returns `true` if the frame should be processed; `false` if it is a
    /// replay or too old to check (outside the 32-slot window).
    pub fn accept(&mut self, seq: LinkSeqNum) -> bool {
        if !self.initialised {
            self.last_seq = seq;
            self.window = 1;
            self.initialised = true;
            self.transition_to(ReplayWindowState::Tracking)
                .expect("empty replay window can start tracking");
            return true;
        }

        let diff = i32::from(seq.get()) - i32::from(self.last_seq.get());

        if diff > 0 {
            // Newer than anything we've seen: advance the window.
            let shift = diff as u32;
            self.window = if shift >= 32 {
                // Entire window is beyond what we've seen; reset it.
                1
            } else {
                (self.window << shift) | 1
            };
            self.last_seq = seq;
            self.transition_to(ReplayWindowState::Tracking)
                .expect("tracking replay window can keep tracking");
            true
        } else if diff == 0 {
            // Exact duplicate of last_seq.
            false
        } else {
            // Older than last_seq: check the bitmask.
            let offset = (-diff) as u32;
            if offset >= 32 {
                // Outside the window — too old to verify, reject.
                return false;
            }
            let bit = 1u32 << offset;
            if self.window & bit != 0 {
                // Already seen.
                false
            } else {
                self.window |= bit;
                self.transition_to(ReplayWindowState::Tracking)
                    .expect("tracking replay window can keep tracking");
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

    fn seq(n: u16) -> LinkSeqNum {
        LinkSeqNum::new(n)
    }

    #[test]
    fn first_packet_always_accepted() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.state(), ReplayWindowState::Empty);
        assert!(w.accept(seq(0)));
        assert_eq!(w.state(), ReplayWindowState::Tracking);
        assert!(w.accept(seq(100)));
    }

    #[test]
    fn replay_window_transition_table_rejects_return_to_empty() {
        assert!(ReplayWindowState::Empty.can_transition_to(ReplayWindowState::Tracking));
        assert!(ReplayWindowState::Tracking.can_transition_to(ReplayWindowState::Tracking));
        assert!(!ReplayWindowState::Tracking.can_transition_to(ReplayWindowState::Empty));
    }

    #[test]
    fn duplicate_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(seq(5)));
        assert!(!w.accept(seq(5)));
    }

    #[test]
    fn in_order_sequence() {
        let mut w = ReplayWindow::new();
        for i in 0u16..128 {
            assert!(w.accept(seq(i)), "should accept {i}");
        }
    }

    #[test]
    fn out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        // Accept 10, then out-of-order 5, then 10 again (duplicate).
        assert!(w.accept(seq(10)));
        assert!(w.accept(seq(5)));
        assert!(!w.accept(seq(5))); // replay
        assert!(!w.accept(seq(10))); // replay
        assert!(w.accept(seq(11)));
    }

    #[test]
    fn too_old_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(seq(100)));
        // Advance window past slot 0.
        assert!(w.accept(seq(132))); // 32 slots ahead
                                     // seq=100 is now 32 slots behind last_seq=132 — exactly at the edge.
                                     // offset = 32, so rejected.
        assert!(!w.accept(seq(100)));
        assert!(!w.accept(seq(50))); // way too old
    }

    #[test]
    fn window_boundary_accepted() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(seq(31)));
        assert!(w.accept(seq(0))); // 31 slots back — last slot in window
        assert!(!w.accept(seq(0))); // replay
    }

    #[test]
    fn sequence_wrap_rejected_within_epoch() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(seq(0xFFFE)));
        assert!(w.accept(seq(0xFFFF)));
        assert!(!w.accept(seq(0x0000)));
        assert!(!w.accept(seq(0x0001)));
        assert!(!w.accept(seq(0xFFFF)));
    }

    #[test]
    fn large_gap_resets_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(seq(0)));
        assert!(w.accept(seq(200))); // gap > 32, resets window
        assert!(!w.accept(seq(0))); // 0 is now 200 slots back — outside window
        assert!(w.accept(seq(199))); // just inside window (offset = 1)
    }
}
