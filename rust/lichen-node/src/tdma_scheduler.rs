use lichen_core::{
    constants::{TDMA_GUARD_MS, TDMA_SLOT_MS},
    lichen_hash_32,
};

pub const HOP_SCHEDULE_LEN: usize = 8;

pub struct TdmaScheduler {
    pub sfn: u32,
    pub current_channel: u8,
    pub hop_schedule: [u8; HOP_SCHEDULE_LEN],
    eui64: [u8; 8],
}

impl TdmaScheduler {
    pub fn new() -> Self {
        TdmaScheduler {
            sfn: 0,
            current_channel: 0,
            hop_schedule: [0; HOP_SCHEDULE_LEN],
            eui64: [0; 8],
        }
    }

    pub fn with_eui64(eui64: [u8; 8]) -> Self {
        let mut s = Self::new();
        s.eui64 = eui64;
        s.hop_schedule = s.populate_hop_schedule(0);
        s
    }

    pub fn slot_for(eui: &[u8; 8]) -> u16 {
        let h = lichen_hash_32(eui);
        (h % 16) as u16
    }

    pub fn guard_ms() -> u32 {
        TDMA_GUARD_MS
    }

    pub fn slot_ms() -> u32 {
        TDMA_SLOT_MS
    }

    pub fn set_eui64(&mut self, eui64: [u8; 8]) {
        self.eui64 = eui64;
        self.hop_schedule = self.populate_hop_schedule(self.sfn);
    }

    pub fn set_sfn(&mut self, sfn: u32) {
        self.sfn = sfn;
    }

    pub fn advance_sfn(&mut self) {
        self.sfn = self.sfn.wrapping_add(1);
    }

    pub fn set_current_channel(&mut self, channel: u8) {
        self.current_channel = channel;
    }

    pub fn populate_hop_schedule(&self, sfn: u32) -> [u8; HOP_SCHEDULE_LEN] {
        let mut schedule = [0u8; HOP_SCHEDULE_LEN];
        let num_channels = 8u8;
        for i in 0..HOP_SCHEDULE_LEN {
            let sfn_offset = (sfn as u64 + i as u64) & 0xffffffff;
            let sfn_bytes = (sfn_offset as u32).to_le_bytes();
            let mut data = [0u8; 12];
            data[..8].copy_from_slice(&self.eui64);
            data[8..12].copy_from_slice(&sfn_bytes);
            let h = lichen_hash_32(&data);
            let n = num_channels.max(3);
            schedule[i] = 1 + (h % n as u32) as u8;
        }
        schedule
    }

    pub fn synchronized_hop_channel(&self, sfn: Option<u32>) -> u8 {
        self.get_hop_channel(sfn)
    }

    pub fn get_hop_channel(&self, sfn: Option<u32>) -> u8 {
        let sfn = sfn.unwrap_or(self.sfn);
        let has_schedule = self.hop_schedule.iter().any(|&c| c != 0);
        if has_schedule {
            self.hop_schedule[(sfn as usize) % HOP_SCHEDULE_LEN]
        } else {
            self.current_channel
        }
    }
}

impl Default for TdmaScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tdma_slot_guard_drift_independent() {
        assert_eq!(TdmaScheduler::guard_ms(), 100);
        assert_eq!(TdmaScheduler::slot_ms(), 250);

        let eui1 = [0u8, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(TdmaScheduler::slot_for(&eui1), 2);
    }

    #[test]
    fn test_sfn_advance_wrapping() {
        let mut tdma = TdmaScheduler::new();
        assert_eq!(tdma.sfn, 0);
        tdma.advance_sfn();
        assert_eq!(tdma.sfn, 1);
        tdma.sfn = u32::MAX;
        tdma.advance_sfn();
        assert_eq!(tdma.sfn, 0);
    }

    #[test]
    fn test_current_channel_fallback() {
        let mut tdma = TdmaScheduler::new();
        tdma.set_current_channel(3);
        assert_eq!(tdma.get_hop_channel(None), 3);
    }

    #[test]
    fn test_hop_schedule_with_eui64() {
        let eui = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
        let tdma = TdmaScheduler::with_eui64(eui);
        let schedule = tdma.hop_schedule;
        assert!(schedule.iter().all(|&c| c >= 1 && c <= 8));
    }

    #[test]
    fn test_synchronized_hop_channel_sfn0() {
        let eui = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let tdma = TdmaScheduler::with_eui64(eui);
        let ch = tdma.synchronized_hop_channel(Some(0));
        assert!(ch >= 1 && ch <= 8);
    }

    #[test]
    fn test_synchronized_hop_channel_sfn1() {
        let eui = [0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00];
        let tdma = TdmaScheduler::with_eui64(eui);
        let ch = tdma.synchronized_hop_channel(Some(1));
        assert!(ch >= 1 && ch <= 8);
    }

    #[test]
    fn test_sfn_wrap_channel_consistent() {
        let eui = [0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00];
        let tdma = TdmaScheduler::with_eui64(eui);
        let ch_sfn_max = tdma.synchronized_hop_channel(Some(u32::MAX));
        assert!(ch_sfn_max >= 1 && ch_sfn_max <= 8);
        let ch_sfn_0 = tdma.synchronized_hop_channel(Some(0));
        assert!(ch_sfn_0 >= 1 && ch_sfn_0 <= 8);
    }

    #[test]
    fn test_hop_schedule_deterministic_sfn0_seed0() {
        let eui = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let tdma = TdmaScheduler::with_eui64(eui);
        let ch = tdma.synchronized_hop_channel(Some(0));
        assert_eq!(ch, 6);
    }

    #[test]
    fn test_hop_schedule_indexing_matches_python_simnode() {
        let eui = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let tdma = TdmaScheduler::with_eui64(eui);
        assert_eq!(tdma.synchronized_hop_channel(Some(0)), 6);
        assert_eq!(tdma.synchronized_hop_channel(Some(1)), 5);
        assert_eq!(tdma.synchronized_hop_channel(Some(2)), 8);
        assert_eq!(tdma.synchronized_hop_channel(Some(3)), 7);
        assert_eq!(tdma.synchronized_hop_channel(Some(7)), 3);
        assert_eq!(tdma.synchronized_hop_channel(Some(8)), 6);
    }

    #[test]
    fn test_hop_schedule_sfn1_seed42() {
        let eui = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a];
        let tdma = TdmaScheduler::with_eui64(eui);
        let ch = tdma.synchronized_hop_channel(Some(1));
        assert_eq!(ch, 6);
    }

    #[test]
    fn test_hop_schedule_sfn_wrap_seed0() {
        let eui = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let tdma = TdmaScheduler::with_eui64(eui);
        let ch = tdma.synchronized_hop_channel(Some(4294967295));
        assert_eq!(ch, 4);
    }
}
