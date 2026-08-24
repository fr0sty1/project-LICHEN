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

/// Configuration for GNSS-synchronized channel hopping.
///
/// When enabled, channel selection uses wall-clock time (from GNSS or RTC)
/// to compute a network-wide synchronized hopping pattern. This allows all
/// nodes with accurate time to rendezvous on the same channel without
/// explicit coordination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GnssHopConfig {
    /// Enable GNSS-synchronized hopping. When false, falls back to
    /// hash-based or CH0 selection.
    pub enabled: bool,
    /// Network-wide seed for the hopping sequence. All nodes in a mesh
    /// must use the same seed to rendezvous correctly.
    pub seed: u32,
    /// Superframe duration in microseconds. Determines how long nodes
    /// stay on each channel before hopping.
    pub superframe_duration_us: u64,
    /// Epoch base time in microseconds (UTC). The hopping sequence is
    /// computed relative to this reference point.
    pub epoch_base_us: u64,
}

impl Default for GnssHopConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            seed: 0,
            superframe_duration_us: SUPERFRAME_DURATION_US,
            epoch_base_us: GNSS_EPOCH_BASE_US,
        }
    }
}

pub mod access_level;
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
pub mod sf_assignment;
pub mod tdma_beacon;
pub mod transport;
pub mod tx_queue;
pub mod udp;

pub use access_level::AccessLevel;

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
///
/// Returns 0 if `superframe_duration_us` is 0 (avoids division by zero).
pub fn sfn_from_unix_time(
    unix_time_us: u64,
    superframe_duration_us: u64,
    epoch_base_us: u64,
) -> u32 {
    if superframe_duration_us == 0 || unix_time_us < epoch_base_us {
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
    // ponytail: spec says N = MAX(NChannels, 3), RETURN 1 + (Hash MOD N)
    let n = n_channels.max(3);
    1 + (h % n as u32) as u8
}

/// Select channel using a priority chain with GNSS-sync support.
///
/// Priority order:
/// 1. **GNSS-synced**: When `gnss_config.enabled` is true and `unix_time_us`
///    is provided, computes the superframe number and uses synchronized hopping.
/// 2. **Hash-based**: When a peer EUI-64 is provided, uses hash-based selection
///    for peer-specific rendezvous (CCP-9 compatible).
/// 3. **Fallback**: Returns CH0 when no other method applies.
///
/// # Arguments
///
/// * `unix_time_us` - UTC time in microseconds from a TimeProvider (or None)
/// * `gnss_config` - GNSS hopping configuration
/// * `peer_eui64` - Optional 8-byte EUI-64 of the peer for hash-based selection
/// * `epoch` - Link-layer epoch for hash-based selection
/// * `n_channels` - Total number of available channels
///
/// # Example
///
/// ```
/// use lichen_core::{GnssHopConfig, select_channel_with_gnss, GNSS_EPOCH_BASE_US};
///
/// // With GNSS time available
/// let config = GnssHopConfig { enabled: true, seed: 0x12345678, ..Default::default() };
/// let unix_us = GNSS_EPOCH_BASE_US + 4_000_000; // 2 superframes in
/// let ch = select_channel_with_gnss(Some(unix_us), &config, None, 0, 8);
/// assert!(ch >= 1 && ch <= 8);
///
/// // Fallback to CH0 when GNSS disabled and no peer
/// let config = GnssHopConfig::default();
/// let ch = select_channel_with_gnss(None, &config, None, 0, 8);
/// assert_eq!(ch, 0);
/// ```
pub fn select_channel_with_gnss(
    unix_time_us: Option<u64>,
    gnss_config: &GnssHopConfig,
    peer_eui64: Option<&[u8; 8]>,
    epoch: u8,
    n_channels: u8,
) -> u8 {
    // Priority 1: GNSS-synced when enabled and time available
    if gnss_config.enabled {
        if let Some(unix_us) = unix_time_us {
            let sfn = sfn_from_unix_time(
                unix_us,
                gnss_config.superframe_duration_us,
                gnss_config.epoch_base_us,
            );
            return synchronized_hop_channel(sfn, gnss_config.seed, n_channels);
        }
    }

    // Priority 2: hash-based for known peers (CCP-9 rendezvous)
    if let Some(eui) = peer_eui64 {
        let mut data = [0u8; 12];
        data[0..8].copy_from_slice(eui);
        data[8..12].copy_from_slice(&(epoch as u32).to_le_bytes());
        let h = lichen_hash_32(&data);
        // ponytail: spec says N = MAX(NChannels, 3), RETURN 1 + (Hash MOD N)
        let n = n_channels.max(3);
        return 1 + (h % n as u32) as u8;
    }

    // Priority 3: fallback to CH0
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sfn_from_unix_time_zero_duration() {
        // Zero superframe duration should return 0 (avoid division by zero)
        let result = sfn_from_unix_time(GNSS_EPOCH_BASE_US + 1_000_000, 0, GNSS_EPOCH_BASE_US);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_sfn_from_unix_time_before_epoch() {
        // Time before epoch should return 0
        let result = sfn_from_unix_time(
            1_000_000_000_000_000,
            SUPERFRAME_DURATION_US,
            GNSS_EPOCH_BASE_US,
        );
        assert_eq!(result, 0);
    }

    #[test]
    fn test_sfn_from_unix_time_at_epoch() {
        // At exactly the epoch, SFN should be 0
        let result = sfn_from_unix_time(
            GNSS_EPOCH_BASE_US,
            SUPERFRAME_DURATION_US,
            GNSS_EPOCH_BASE_US,
        );
        assert_eq!(result, 0);
    }

    #[test]
    fn test_sfn_from_unix_time_one_superframe() {
        // One superframe after epoch
        let result = sfn_from_unix_time(
            GNSS_EPOCH_BASE_US + SUPERFRAME_DURATION_US,
            SUPERFRAME_DURATION_US,
            GNSS_EPOCH_BASE_US,
        );
        assert_eq!(result, 1);
    }

    #[test]
    fn test_sfn_from_unix_time_multiple_superframes() {
        // 10 superframes after epoch
        let result = sfn_from_unix_time(
            GNSS_EPOCH_BASE_US + 10 * SUPERFRAME_DURATION_US,
            SUPERFRAME_DURATION_US,
            GNSS_EPOCH_BASE_US,
        );
        assert_eq!(result, 10);
    }

    #[test]
    fn test_sfn_from_unix_time_partial_superframe() {
        // Partial superframe should truncate
        let result = sfn_from_unix_time(
            GNSS_EPOCH_BASE_US + SUPERFRAME_DURATION_US + 500_000,
            SUPERFRAME_DURATION_US,
            GNSS_EPOCH_BASE_US,
        );
        assert_eq!(result, 1);
    }

    #[test]
    fn test_synchronized_hop_channel_range() {
        // Channel should be in range [1, n_channels] per spec: 1 + (hash % N)
        for sfn in 0..100 {
            let ch = synchronized_hop_channel(sfn, 0x12345678, 8);
            assert!(
                ch >= 1 && ch <= 8,
                "channel {} out of range for sfn {}",
                ch,
                sfn
            );
        }
    }

    #[test]
    fn test_synchronized_hop_channel_min_channels() {
        // With n_channels < 3, should clamp to 3
        let ch = synchronized_hop_channel(0, 0, 2);
        assert!(
            ch >= 1 && ch <= 3,
            "channel {} out of range with n_channels=2",
            ch
        );
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

    // --- select_channel_with_gnss tests ---

    #[test]
    fn test_select_channel_gnss_priority_uses_gnss_when_enabled() {
        // Priority 1: GNSS-synced takes precedence when enabled + time available
        let config = GnssHopConfig {
            enabled: true,
            seed: 0x12345678,
            ..Default::default()
        };
        let unix_us = GNSS_EPOCH_BASE_US + 4_000_000; // SFN = 2
        let peer_eui = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        // Even with peer EUI present, GNSS takes priority
        let ch = select_channel_with_gnss(Some(unix_us), &config, Some(&peer_eui), 0, 8);

        // Should match synchronized_hop_channel result
        let expected = synchronized_hop_channel(2, 0x12345678, 8);
        assert_eq!(ch, expected);
    }

    #[test]
    fn test_select_channel_gnss_falls_back_to_hash_when_no_time() {
        // Priority 2: hash-based when GNSS enabled but no time available
        let config = GnssHopConfig {
            enabled: true,
            seed: 0x12345678,
            ..Default::default()
        };
        let peer_eui = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let ch = select_channel_with_gnss(None, &config, Some(&peer_eui), 0, 8);

        // Should be hash-based, in valid range [1, n_channels]
        assert!(ch >= 1 && ch <= 8, "channel {} out of range", ch);
    }

    #[test]
    fn test_select_channel_gnss_disabled_uses_hash() {
        // Priority 2: hash-based when GNSS disabled, even with time available
        let config = GnssHopConfig {
            enabled: false,
            seed: 0x12345678,
            ..Default::default()
        };
        let unix_us = GNSS_EPOCH_BASE_US + 4_000_000;
        let peer_eui = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let ch_with_time = select_channel_with_gnss(Some(unix_us), &config, Some(&peer_eui), 0, 8);
        let ch_no_time = select_channel_with_gnss(None, &config, Some(&peer_eui), 0, 8);

        // Both should use hash-based (same result)
        assert_eq!(ch_with_time, ch_no_time);
        assert!(ch_with_time >= 1 && ch_with_time < 8);
    }

    #[test]
    fn test_select_channel_gnss_fallback_to_ch0() {
        // Priority 3: CH0 when GNSS disabled and no peer
        let config = GnssHopConfig::default();

        let ch = select_channel_with_gnss(None, &config, None, 0, 8);
        assert_eq!(ch, 0);

        // Also with GNSS enabled but no time and no peer
        let config_enabled = GnssHopConfig {
            enabled: true,
            ..Default::default()
        };
        let ch2 = select_channel_with_gnss(None, &config_enabled, None, 0, 8);
        assert_eq!(ch2, 0);
    }

    #[test]
    fn test_select_channel_gnss_hash_varies_with_epoch() {
        let config = GnssHopConfig::default();
        let peer_eui = [0xAA; 8];

        let ch_epoch0 = select_channel_with_gnss(None, &config, Some(&peer_eui), 0, 16);
        let ch_epoch1 = select_channel_with_gnss(None, &config, Some(&peer_eui), 1, 16);

        // Both valid, and deterministic
        assert!(ch_epoch0 >= 1 && ch_epoch0 < 16);
        assert!(ch_epoch1 >= 1 && ch_epoch1 < 16);

        // Same inputs should be deterministic
        let ch_epoch0_again = select_channel_with_gnss(None, &config, Some(&peer_eui), 0, 16);
        assert_eq!(ch_epoch0, ch_epoch0_again);
    }

    #[test]
    fn test_select_channel_gnss_hash_varies_with_peer() {
        let config = GnssHopConfig::default();
        let peer1 = [0x01; 8];
        let peer2 = [0x02; 8];

        let ch1 = select_channel_with_gnss(None, &config, Some(&peer1), 0, 16);
        let ch2 = select_channel_with_gnss(None, &config, Some(&peer2), 0, 16);

        assert!(ch1 >= 1 && ch1 < 16);
        assert!(ch2 >= 1 && ch2 < 16);
    }

    #[test]
    fn test_gnss_hop_config_default() {
        let config = GnssHopConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.seed, 0);
        assert_eq!(config.superframe_duration_us, SUPERFRAME_DURATION_US);
        assert_eq!(config.epoch_base_us, GNSS_EPOCH_BASE_US);
    }
}
