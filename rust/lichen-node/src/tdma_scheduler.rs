use lichen_core::{constants::{TDMA_GUARD_MS, TDMA_SLOT_MS}, lichen_hash_32};
pub struct TdmaScheduler;
impl TdmaScheduler {
    pub fn new() -> Self {
        TdmaScheduler
    }
    pub fn slot_for(eui: &[u8; 8], num_slots: u8, epoch: u32) -> u16 {
        let mut data = *eui;
        let e = epoch;
        for i in 0..4 {
            data[i] ^= (e >> (i * 8)) as u8;
        }
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
        assert_eq!(TdmaScheduler::slot_for(&eui1, 8, 0), 2);
    }
}
