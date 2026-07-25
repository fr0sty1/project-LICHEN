//! Announce relay protocol.
//!
//! Sequence-based flood routing for peer discovery announcements.

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(feature = "std")]
pub const ANNOUNCE_TYPE: u8 = 0x01;
#[cfg(feature = "std")]
pub const MAX_ANNOUNCE_HOPS: u8 = 15;

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnnounceRelayAction {
    Send { hop_count: u8 },
    Suppress,
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnounceState {
    local_seq: u16,
    last_relay_map: HashMap<[u8; 8], u16>,
}

#[cfg(feature = "std")]
impl AnnounceState {
    pub fn new() -> Self {
        Self {
            local_seq: 0,
            last_relay_map: HashMap::new(),
        }
    }

    pub fn local_seq(&self) -> u16 {
        self.local_seq
    }

    pub fn bump_local_seq(&mut self) -> u16 {
        self.local_seq = self.local_seq.wrapping_add(1);
        self.local_seq
    }

    pub fn should_relay(
        &mut self,
        originator_iid: &[u8; 8],
        seq_num: u16,
        hop_count: u8,
    ) -> AnnounceRelayAction {
        if hop_count >= MAX_ANNOUNCE_HOPS {
            return AnnounceRelayAction::Suppress;
        }
        if let Some(&last_seq) = self.last_relay_map.get(originator_iid) {
            let seq_gt = |a: u16, b: u16| -> bool { a != b && a.wrapping_sub(b) < 1 << 15 };
            if !seq_gt(seq_num, last_seq) {
                return AnnounceRelayAction::Suppress;
            }
        }
        let relay_hop = hop_count + 1;
        self.last_relay_map.insert(*originator_iid, seq_num);
        AnnounceRelayAction::Send {
            hop_count: relay_hop,
        }
    }
}

#[cfg(feature = "std")]
impl Default for AnnounceState {
    fn default() -> Self {
        Self::new()
    }
}
