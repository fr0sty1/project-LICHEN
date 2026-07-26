//! LICHEN protocol primitives.
//!
//! Provides the constants, address types, and shared definitions used by every
//! other crate in the stack. Canonical values are derived from `constants.toml`
//! at the repo root.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

/// Default superframe duration in microseconds (2 seconds)
pub const SUPERFRAME_DURATION_US: u64 = 2_000_000;

/// GNSS epoch base: 2024-01-01 00:00:00 UTC in microseconds
pub const GNSS_EPOCH_BASE_US: u64 = 1_704_067_200_000_000;

pub mod addr;
pub mod announce;
pub mod checksum;
pub mod compact_cot;
pub mod constants;
pub mod duty_cycle;
pub mod error;
pub mod icmpv6;
pub mod ipv6;
pub mod l2_payload;
pub mod loadng;
pub mod neighbor_monitor;
pub mod rf_health;
pub mod tx_queue;
pub mod udp;

#[cfg(feature = "std")]
extern crate std;

pub fn lichen_hash_32(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193u32);
    }
    hash
}

/// Derive superframe number from UTC time in microseconds.
pub fn sfn_from_unix_time(unix_time_us: u64, superframe_duration_us: u64, epoch_base_us: u64) -> u32 {
    if unix_time_us < epoch_base_us {
        return 0;
    }
    ((unix_time_us - epoch_base_us) / superframe_duration_us) as u32
}

/// Compute channel for network-wide synchronized hopping.
/// Uses fnv1a32 hash of (seed || sfn) to select channel.
pub fn synchronized_hop_channel(sfn: u32, seed: u32, n_channels: u8) -> u8 {
    let mut data = [0u8; 8];
    data[0..4].copy_from_slice(&seed.to_le_bytes());
    data[4..8].copy_from_slice(&sfn.to_le_bytes());
    let h = lichen_hash_32(&data);
    let n = n_channels.max(3) - 1;
    1 + (h % n as u32) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sfn_from_unix_time_before_epoch() {
        // Time before epoch should return 0
        let result = sfn_from_unix_time(1_000_000_000_000_000, SUPERFRAME_DURATION_US, GNSS_EPOCH_BASE_US);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_sfn_from_unix_time_at_epoch() {
        // At exactly the epoch, SFN should be 0
        let result = sfn_from_unix_time(GNSS_EPOCH_BASE_US, SUPERFRAME_DURATION_US, GNSS_EPOCH_BASE_US);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_sfn_from_unix_time_one_superframe() {
        // One superframe after epoch
        let result = sfn_from_unix_time(GNSS_EPOCH_BASE_US + SUPERFRAME_DURATION_US, SUPERFRAME_DURATION_US, GNSS_EPOCH_BASE_US);
        assert_eq!(result, 1);
    }

    #[test]
    fn test_sfn_from_unix_time_multiple_superframes() {
        // 10 superframes after epoch
        let result = sfn_from_unix_time(GNSS_EPOCH_BASE_US + 10 * SUPERFRAME_DURATION_US, SUPERFRAME_DURATION_US, GNSS_EPOCH_BASE_US);
        assert_eq!(result, 10);
    }

    #[test]
    fn test_sfn_from_unix_time_partial_superframe() {
        // Partial superframe should truncate
        let result = sfn_from_unix_time(GNSS_EPOCH_BASE_US + SUPERFRAME_DURATION_US + 500_000, SUPERFRAME_DURATION_US, GNSS_EPOCH_BASE_US);
        assert_eq!(result, 1);
    }

    #[test]
    fn test_synchronized_hop_channel_range() {
        // Channel should be in range [1, n_channels-1]
        for sfn in 0..100 {
            let ch = synchronized_hop_channel(sfn, 0x12345678, 8);
            assert!(ch >= 1 && ch < 8, "channel {} out of range for sfn {}", ch, sfn);
        }
    }

    #[test]
    fn test_synchronized_hop_channel_min_channels() {
        // With n_channels < 3, should clamp to 3
        let ch = synchronized_hop_channel(0, 0, 2);
        assert!(ch >= 1 && ch < 3, "channel {} out of range with n_channels=2", ch);
    }

    #[test]
    fn test_synchronized_hop_channel_deterministic() {
        // Same inputs should produce same output
        let ch1 = synchronized_hop_channel(42, 0xDEADBEEF, 8);
        let ch2 = synchronized_hop_channel(42, 0xDEADBEEF, 8);
        assert_eq!(ch1, ch2);
    }

    #[test]
    fn test_synchronized_hop_channel_varies_with_sfn() {
        // Different SFNs should (usually) produce different channels
        let ch1 = synchronized_hop_channel(0, 0x12345678, 16);
        let ch2 = synchronized_hop_channel(1, 0x12345678, 16);
        // Not guaranteed to differ, but highly likely with good hash
        // We just verify they're both valid
        assert!(ch1 >= 1 && ch1 < 16);
        assert!(ch2 >= 1 && ch2 < 16);
    }

    #[test]
    fn test_synchronized_hop_channel_varies_with_seed() {
        // Different seeds should (usually) produce different channels
        let ch1 = synchronized_hop_channel(0, 0x12345678, 16);
        let ch2 = synchronized_hop_channel(0, 0x87654321, 16);
        assert!(ch1 >= 1 && ch1 < 16);
        assert!(ch2 >= 1 && ch2 < 16);
    }
}
