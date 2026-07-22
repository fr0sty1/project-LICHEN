use lichen_core::constants::{TDMA_GUARD_MS, TDMA_SLOT_MS};
pub struct TdmaScheduler;
impl TdmaScheduler {
    pub fn new() -> Self {
        TdmaScheduler
    }
    pub fn slot_for(eui: &[u8; 8]) -> u16 {
        let mut h = 0u32;
        for &b in eui {
            h = h.wrapping_mul(31).wrapping_add(b as u32);
        }
        (h % 16) as u16
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
        assert_eq!(TdmaScheduler::guard_ms(), 50);
        assert_eq!(TdmaScheduler::slot_ms(), 250);

        let eui1 = [0u8, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(TdmaScheduler::slot_for(&eui1), 1);
    }
}
