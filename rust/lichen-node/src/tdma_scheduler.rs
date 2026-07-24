use lichen_core::{constants::{TDMA_GUARD_MS, TDMA_SLOT_MS}, lichen_hash_32};

fn xor_epoch(data: &[u8; 8], epoch: u32) -> [u8; 8] {
    let mut buf = *data;
    let e = epoch.to_le_bytes();
    for i in 0..4 {
        buf[i] ^= e[i];
    }
    buf
}

pub struct TdmaScheduler;
impl TdmaScheduler {
    pub fn new() -> Self {
        TdmaScheduler
    }
    pub fn slot_for(eui: &[u8; 8], epoch: u32, num_slots: u8) -> u16 {
        let buf = xor_epoch(eui, epoch);
        let h = lichen_hash_32(&buf);
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
    fn test_tdma_slot_matches_ccp_tdma_vectors() {
        assert_eq!(TdmaScheduler::guard_ms(), 100);
        assert_eq!(TdmaScheduler::slot_ms(), 250);

        let eui1 = [0u8, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(TdmaScheduler::slot_for(&eui1, 0, 8), 2);

        let eui2 = [0xaau8, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
        assert_eq!(TdmaScheduler::slot_for(&eui2, 0, 16), 13);
    }

    #[test]
    fn test_tdma_xor_epoch() {
        let eui = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let epoch = 0x01020304u32;
        let result = xor_epoch(&eui, epoch);
        assert_eq!(result, [0x05, 0x01, 0x01, 0x05, 0x05, 0x06, 0x07, 0x08]);
    }
}
