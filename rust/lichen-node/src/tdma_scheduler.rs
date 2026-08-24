use lichen_core::{
    constants::{TDMA_GUARD_MS, TDMA_SLOT_MS},
    lichen_hash_32,
};
pub struct TdmaScheduler;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TdmaSchedulerError {
    ZeroSlots,
}

impl TdmaScheduler {
    pub fn new() -> Self {
        TdmaScheduler
    }
    /// Compute slot for a given EUI, SFN, and slot count.
    /// Formula: (hash_32(eui64) + sfn) % num_slots (matches Python/spec)
    pub fn slot_for(eui: &[u8; 8], sfn: u32, num_slots: u16) -> Result<u16, TdmaSchedulerError> {
        if num_slots == 0 {
            return Err(TdmaSchedulerError::ZeroSlots);
        }
        let h = lichen_hash_32(eui);
        Ok(((h.wrapping_add(sfn)) % u32::from(num_slots)) as u16)
    }
    /// Legacy slot_for for callers that don't have SFN context (defaults to sfn=0, num_slots=16)
    pub fn slot_for_legacy(eui: &[u8; 8]) -> Result<u16, TdmaSchedulerError> {
        Self::slot_for(eui, 0, 16)
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
        assert_eq!(TdmaScheduler::slot_ms(), 2346);
    }

    #[test]
    fn test_slot_for_incorporates_sfn() {
        let eui = [0u8, 0, 0, 0, 0, 0, 0, 1];
        let slot0 = TdmaScheduler::slot_for(&eui, 0, 16).unwrap();
        let slot1 = TdmaScheduler::slot_for(&eui, 1, 16).unwrap();
        // Slot should change when SFN changes
        assert_ne!(slot0, slot1, "slot_for must incorporate SFN");
    }

    #[test]
    fn test_slot_for_wrapping() {
        let eui = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        // Test u32 wrap: 0xFFFFFFFF + 1 = 0 (wrapping)
        let slot_max = TdmaScheduler::slot_for(&eui, 0xFFFFFFFF, 16).unwrap();
        let slot_zero = TdmaScheduler::slot_for(&eui, 0, 16).unwrap();
        // hash + 0xFFFFFFFF wraps to hash - 1, so slots should differ by 1 mod 16
        let expected_diff = (slot_max as i32 - slot_zero as i32 + 16) % 16;
        assert_eq!(
            expected_diff, 15,
            "SFN wrap should produce slot_max = slot_zero - 1 mod num_slots"
        );
    }

    #[test]
    fn test_slot_for_legacy_matches_sfn_zero() {
        let eui = [0u8, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            TdmaScheduler::slot_for_legacy(&eui).unwrap(),
            TdmaScheduler::slot_for(&eui, 0, 16).unwrap()
        );
    }

    #[test]
    fn zero_slots_is_rejected() {
        assert_eq!(
            TdmaScheduler::slot_for(&[0; 8], 0, 0),
            Err(TdmaSchedulerError::ZeroSlots)
        );
    }
}
