use lichen_core::{constants::{TDMA_GUARD_MS, TDMA_SLOT_MS}, lichen_hash_32};
pub struct TdmaScheduler;
impl TdmaScheduler {
    pub fn new() -> Self {
        TdmaScheduler
    }
    pub fn slot_for(eui: &[u8; 8], epoch: u32, num_slots: u8) -> u16 {
        let mut data = [0u8; 12];
        data[..8].copy_from_slice(eui);
        data[8..12].copy_from_slice(&epoch.to_le_bytes());
        let h = lichen_hash_32(&data);
        (h % num_slots as u32) as u16
    }
    pub fn guard_ms() -> u32 {
        TDMA_GUARD_MS
    }
    pub fn slot_ms() -> u32 {
        TDMA_SLOT_MS
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
        assert_eq!(TdmaScheduler::slot_for(&eui1, 0, 8), 2);

        let eui2 = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
        assert_eq!(TdmaScheduler::slot_for(&eui2, 0, 16), 13);

        assert_eq!(TdmaScheduler::slot_for(&eui1, 1, 8), 3);
    }
}
