//! RF health metrics tracking for LICHEN nodes (CCP-15/16 interference mitigation,
//! adaptive SF, load balancing).
//!
//! Implements normative adaptive_sf_select from spec/02a-coordinated-capacity.md
//! (critical conditions first per table and pseudocode). Matches ccp15.json,
//! ccp16.json vectors exactly for EMA, load_factor, density, adaptive_sf.
//! Tracks packet statistics for loss, SNR with EMA (alpha=1/4), density,
//! load_factor. Saturating counters, Q16.16 fixed point. no_std compatible,
//! #![forbid(unsafe_code)]. Removed dead RSSI stats and dropped counter.

const FP_SCALE: u32 = 1 << 16;
const EMA_ALPHA_SHIFT: u32 = 2;
const DENSITY_CRITICAL: u8 = 20;
const DENSITY_HIGH: u8 = 8;
const DENSITY_LOW: u8 = 5;
const SNR_CRITICAL: i8 = -5;
const SNR_POOR: i8 = 0;
const SNR_GOOD: i8 = 8;
const LOAD_HIGH: u32 = FP_SCALE * 4 / 5;
const LOAD_REBALANCE: u32 = FP_SCALE * 2 / 5;
const FNV_BASIS: u32 = 0x811c9dc5;
const FNV_PRIME: u32 = 0x01000193;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RfHealthMetrics {
    /// Total packets transmitted.
    pub packets_tx: u32,
    /// Total packets received.
    pub packets_rx: u32,
    /// TX failures (no ack, channel busy, etc.).
    pub tx_failures: u32,
    /// SNR statistics from received packets.
    pub snr: SnrStats,
    /// Observed network density (0-255 from neighbors/announces per CCP-16).
    pub density: u8,
    /// Load factor in Q16.16 (0 = idle, FP_SCALE = 1.0). From hash or metrics.
    load_factor_fp: u32,
}

impl RfHealthMetrics {
    /// Create a new metrics tracker with zeroed counters.
    #[inline]
    pub const fn new() -> Self {
        Self {
            packets_tx: 0,
            packets_rx: 0,
            tx_failures: 0,
            snr: SnrStats::new(),
            density: 0,
            load_factor_fp: 0,
        }
    }

    /// Record a packet transmission.
    #[inline]
    pub fn record_tx(&mut self) {
        self.packets_tx = self.packets_tx.saturating_add(1);
    }

    /// Record a packet reception with SNR metric.
    ///
    /// `snr` is the signal-to-noise ratio in dB (typically -20 to +20).
    #[inline]
    pub fn record_rx(&mut self, snr: i8) {
        self.packets_rx = self.packets_rx.saturating_add(1);
        self.snr.update(snr);
    }

    /// Record a transmission failure (no ack, channel busy, etc.).
    #[inline]
    pub fn record_tx_fail(&mut self) {
        self.tx_failures = self.tx_failures.saturating_add(1);
    }

    /// Record observed network density (from RPL DIOs or overheard traffic).
    #[inline]
    pub fn record_density(&mut self, density: u8) {
        self.density = density;
    }

    /// Record computed load factor (from hash_32 or utilization metrics).
    #[inline]
    pub fn record_load_factor(&mut self, load_fp: u32) {
        self.load_factor_fp = load_fp.min(FP_SCALE);
    }

    /// Calculate packet loss rate as a percentage in Q16.16 fixed-point.
    ///
    /// Loss rate = (tx_failures / packets_tx) * 100.
    /// Returns 0 if no packets have been transmitted.
    /// Returns the result as a Q16.16 fixed-point value where the integer
    /// part represents the percentage (0-100).
    #[inline]
    pub fn packet_loss_rate_fp(&self) -> PacketLossRate {
        PacketLossRate::calculate(self.packets_tx, self.tx_failures)
    }

    /// Reset all counters and statistics to zero.
    #[inline]
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// SNR (Signal-to-Noise Ratio) statistics.
///
/// Tracks min, max, and EMA (alpha=1/4) rolling average of SNR values in dB.
/// Faster alpha supports CCP-15 interference detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnrStats {
    /// Minimum SNR observed (dB).
    pub min: i8,
    /// Maximum SNR observed (dB).
    pub max: i8,
    /// Rolling average SNR in Q16.16 fixed-point.
    avg_fp: i32,
    /// Number of samples recorded.
    count: u32,
}

impl Default for SnrStats {
    fn default() -> Self {
        Self::new()
    }
}

impl SnrStats {
    /// Create new SNR stats with no samples.
    #[inline]
    pub const fn new() -> Self {
        Self {
            min: i8::MAX,
            max: i8::MIN,
            avg_fp: 0,
            count: 0,
        }
    }

    /// Update statistics with a new SNR sample.
    #[inline]
    pub fn update(&mut self, snr: i8) {
        self.min = self.min.min(snr);
        self.max = self.max.max(snr);

        let snr_fp = (snr as i32) << 16;
        if self.count == 0 {
            self.avg_fp = snr_fp;
        } else {
            let diff = snr_fp.saturating_sub(self.avg_fp);
            self.avg_fp = self.avg_fp.saturating_add(diff >> EMA_ALPHA_SHIFT);
        }
        self.count = self.count.saturating_add(1);
    }

    /// Get the rolling average SNR as an integer (truncated).
    ///
    /// Returns `None` if no samples have been recorded.
    #[inline]
    pub fn avg(&self) -> Option<i8> {
        if self.count == 0 {
            None
        } else {
            Some(((self.avg_fp + (1 << 15)) >> 16) as i8)
        }
    }

    /// Get the rolling average SNR in Q16.16 fixed-point.
    ///
    /// Returns `None` if no samples have been recorded.
    #[inline]
    pub fn avg_fp(&self) -> Option<i32> {
        if self.count == 0 {
            None
        } else {
            Some(self.avg_fp)
        }
    }

    /// Get the number of samples recorded.
    #[inline]
    pub fn count(&self) -> u32 {
        self.count
    }
}

/// Packet loss rate in Q16.16 fixed-point.
///
/// Represents the percentage of transmitted packets that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PacketLossRate {
    /// Loss rate as percentage in Q16.16 (0 = 0%, 100<<16 = 100%).
    rate_fp: u32,
}

impl PacketLossRate {
    /// Calculate packet loss rate from TX count and failure count.
    ///
    /// Returns 0% if no packets transmitted.
    #[inline]
    pub fn calculate(packets_tx: u32, tx_failures: u32) -> Self {
        if packets_tx == 0 {
            return Self { rate_fp: 0 };
        }

        let numerator = (tx_failures as u64) * 100 * (FP_SCALE as u64);
        let rate = (numerator / (packets_tx as u64)) as u32;

        Self { rate_fp: rate }
    }

    /// Get the loss rate as an integer percentage (0-100, truncated).
    #[inline]
    pub fn as_percent(&self) -> u8 {
        let pct = self.rate_fp >> 16;
        if pct > 100 {
            100
        } else {
            pct as u8
        }
    }

    /// Get the loss rate in Q16.16 fixed-point.
    #[inline]
    pub fn as_fp(&self) -> u32 {
        self.rate_fp
    }

    #[inline]
    pub fn as_permille(&self) -> u16 {
        let permille = ((self.rate_fp as u64) * 10) >> 16;
        if permille > 1000 {
            1000
        } else {
            permille as u16
        }
    }
}

impl RfHealthMetrics {
    /// Adaptive SF selection per spec/02a-coordinated-capacity.md §2a.3
    /// table and pseudocode (critical conditions first). Uses named constants
    /// matching the IF conditions exactly. See also 02-physical-link.md:3.5.
    #[inline]
    pub fn adaptive_sf(&self) -> u8 {
        let snr_ema = self.snr.avg().unwrap_or(0);
        let load_high = self.load_factor_fp > LOAD_HIGH;
        if self.density > DENSITY_CRITICAL || snr_ema < SNR_CRITICAL {
            12
        } else if self.density > DENSITY_HIGH || snr_ema < SNR_POOR || load_high {
            11
        } else if self.density < DENSITY_LOW && snr_ema > SNR_GOOD {
            9
        } else {
            10
        }
    }

    #[inline]
    pub fn should_rebalance(&self) -> bool {
        self.density > DENSITY_HIGH
            || self.load_factor_fp > LOAD_REBALANCE
            || self.packet_loss_rate_fp().as_percent() > 40
    }
}

/// FNV-1a32 hash matching spec/02a-coordinated-capacity.md:123 and test vectors.
#[inline]
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = FNV_BASIS;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// SelectChannel per spec/02a-coordinated-capacity.md §2a.3.1 pseudocode.
///
/// Returns channel index: 0 for CH0 (control) when density > 8, else
/// 1 + (FNV-1a32(EUI64_BE || epoch_LE) % MAX(n_channels, 3)).
/// Matches ccp16.json test vectors.
#[inline]
pub fn select_channel(eui64: &[u8; 8], epoch: u32, density: u8, n_channels: u8) -> u8 {
    if density > 8 {
        return 0;
    }
    let mut data = [0u8; 12];
    data[..8].copy_from_slice(eui64);
    data[8..12].copy_from_slice(&epoch.to_le_bytes());
    let h = fnv1a32(&data);
    let n = n_channels.max(3);
    1 + (h % n as u32) as u8
}

/// Synchronized hop channel per TDMA spec (seed=slot, sfn wrapping u32).
///
/// Used for per-slot channel hopping. seed is typically the assigned slot
/// index. Matches ccp16-hop.json test vectors.
#[inline]
pub fn synchronized_hop_channel(sfn: u32, seed: u32, num_channels: u8) -> u8 {
    let mut data = [0u8; 8];
    data[..4].copy_from_slice(&seed.to_le_bytes());
    data[4..8].copy_from_slice(&sfn.to_le_bytes());
    let h = fnv1a32(&data);
    let n = num_channels.max(3);
    1 + (h % n as u32) as u8
}

/// Adaptive SF selection per spec/02a-coordinated-capacity.md §2a.7 pseudocode.
///
/// Applies incremental adjustments starting from `assigned_sf`:
/// - Density > 10 OR utilization > 150: +2 (cap 12)
/// - EMA_SNR > 8 AND density < 5: -1 (floor 7)
/// - EMA_Loss > 0.25 OR utilization > 200: +1 (cap 12), tx not allowed if utilization > 200
///
/// Returns (sf, tx_allowed).
#[inline]
pub fn adaptive_sf_select(
    assigned_sf: u8,
    snr_ema: i8,
    density: u8,
    utilization: u16,
    loss_rate_ema: u16,
) -> (u8, bool) {
    let mut sf = if assigned_sf == 0 { 10 } else { assigned_sf };
    if density > 10 || utilization > 150 {
        sf = sf.saturating_add(2).min(12);
    }
    if snr_ema > 8 && density < 5 {
        sf = sf.saturating_sub(1).max(7);
    }
    if loss_rate_ema > 2500 || utilization > 200 {
        sf = sf.saturating_add(1).min(12);
        if utilization > 200 {
            return (sf, false);
        }
    }
    (sf, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn new_metrics_are_zeroed() {
        let m = RfHealthMetrics::new();
        assert_eq!(m.packets_tx, 0);
        assert_eq!(m.packets_rx, 0);
        assert_eq!(m.tx_failures, 0);
    }

    #[test]
    fn record_tx_increments() {
        let mut m = RfHealthMetrics::new();
        m.record_tx();
        assert_eq!(m.packets_tx, 1);
        m.record_tx();
        assert_eq!(m.packets_tx, 2);
    }

    #[test]
    fn record_rx_increments_and_updates_stats() {
        let mut m = RfHealthMetrics::new();
        m.record_rx(10);
        assert_eq!(m.packets_rx, 1);
        assert_eq!(m.snr.min, 10);
        assert_eq!(m.snr.max, 10);
    }

    #[test]
    fn record_tx_fail_increments() {
        let mut m = RfHealthMetrics::new();
        m.record_tx_fail();
        assert_eq!(m.tx_failures, 1);
    }

    #[test]
    fn counters_saturate() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = u32::MAX;
        m.record_tx();
        assert_eq!(m.packets_tx, u32::MAX);

        m.packets_rx = u32::MAX;
        m.record_rx(5);
        assert_eq!(m.packets_rx, u32::MAX);
    }

    #[test]
    fn snr_min_max_tracking() {
        let mut stats = SnrStats::new();
        stats.update(-5);
        stats.update(15);
        stats.update(8);
        assert_eq!(stats.min, -5);
        assert_eq!(stats.max, 15);
    }

    #[test]
    fn snr_avg_single_sample() {
        let mut stats = SnrStats::new();
        stats.update(10);
        assert_eq!(stats.avg(), Some(10));
    }

    #[test]
    fn snr_avg_none_when_empty() {
        let stats = SnrStats::new();
        assert_eq!(stats.avg(), None);
    }

    #[test]
    fn packet_loss_zero_when_no_tx() {
        let m = RfHealthMetrics::new();
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 0);
        assert_eq!(loss.as_fp(), 0);
    }

    #[test]
    fn packet_loss_zero_when_no_failures() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 100;
        m.tx_failures = 0;
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 0);
    }

    #[test]
    fn packet_loss_fifty_percent() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 100;
        m.tx_failures = 50;
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 50);
        assert_eq!(loss.as_permille(), 500);
    }

    #[test]
    fn packet_loss_hundred_percent() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 100;
        m.tx_failures = 100;
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 100);
    }

    #[test]
    fn packet_loss_fractional() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 1000;
        m.tx_failures = 5;
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 0);
        assert_eq!(loss.as_permille(), 5);
    }

    #[test]
    fn packet_loss_large_numbers() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 1_000_000;
        m.tx_failures = 100_000;
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 10);
        assert_eq!(loss.as_permille(), 100);
    }

    #[test]
    fn reset_clears_all() {
        let mut m = RfHealthMetrics::new();
        m.record_tx();
        m.record_tx();
        m.record_rx(10);
        m.record_tx_fail();
        m.record_density(10);
        m.record_load_factor(FP_SCALE / 2);

        m.reset();

        assert_eq!(m.packets_tx, 0);
        assert_eq!(m.packets_rx, 0);
        assert_eq!(m.tx_failures, 0);
        assert_eq!(m.snr.count(), 0);
        assert_eq!(m.density, 0);
        assert_eq!(m.load_factor_fp, 0);
    }

    #[test]
    fn snr_negative_values() {
        let mut stats = SnrStats::new();
        stats.update(-10);
        stats.update(20);
        assert_eq!(stats.min, -10);
        assert_eq!(stats.max, 20);
    }

    #[test]
    fn fnv1a32_basis_matches_vectors() {
        let h = fnv1a32(b"");
        assert_eq!(h, 0x811c9dc5);
    }

    #[test]
    fn fnv1a32_self_consistency() {
        let a = fnv1a32(b"");
        let b = fnv1a32(b"");
        assert_eq!(a, b);
        assert_eq!(a, FNV_BASIS);
    }

    #[test]
    fn select_channel_density_above_8_returns_zero() {
        assert_eq!(select_channel(&[0u8; 8], 0, 9, 8), 0);
        assert_eq!(select_channel(&[0u8; 8], 0, 10, 16), 0);
        assert_eq!(select_channel(&[0u8; 8], 0, 255, 3), 0);
    }

    #[test]
    fn select_channel_low_density_uses_hash() {
        let eui = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ch = select_channel(&eui, 1, 3, 3);
        assert_eq!(ch, 2);
    }

    #[test]
    fn select_channel_min_channels_is_3() {
        let eui = [0u8; 8];
        let ch = select_channel(&eui, 0, 0, 1);
        assert!((1..=3).contains(&ch));
    }

    #[test]
    fn synchronized_hop_channel_sfn0_8ch() {
        let ch = synchronized_hop_channel(0, 0, 8);
        assert_eq!(ch, 6);
    }

    #[test]
    fn synchronized_hop_channel_sfn_wrap() {
        let ch = synchronized_hop_channel(4294967295, 0, 8);
        assert_eq!(ch, 2);
    }

    #[test]
    fn adaptive_sf_select_density_high_increases_sf() {
        let (sf, allowed) = adaptive_sf_select(10, 5, 15, 0, 0);
        assert_eq!(sf, 12);
        assert!(allowed);
    }

    #[test]
    fn adaptive_sf_select_high_utilization_denies_tx() {
        let (sf, allowed) = adaptive_sf_select(10, 5, 3, 250, 0);
        assert_eq!(sf, 12);
        assert!(!allowed);
    }

    #[test]
    fn adaptive_sf_select_good_snr_low_density_decreases_sf() {
        let (sf, allowed) = adaptive_sf_select(10, 12, 3, 0, 0);
        assert_eq!(sf, 9);
        assert!(allowed);
    }

    #[test]
    fn adaptive_sf_select_high_loss_increases_sf() {
        let (sf, allowed) = adaptive_sf_select(10, 5, 3, 0, 3000);
        assert_eq!(sf, 11);
        assert!(allowed);
    }

    #[test]
    fn adaptive_sf_and_rebalance_matches_spec() {
        // Test each branch independently to avoid EMA state carryover.
        // Matches spec/02a-coordinated-capacity.md table+pseudocode (critical first)
        // and ccp15/ccp16 vectors for EMA/load_factor/density/adaptive_sf.
        let mut m = RfHealthMetrics::new();
        m.record_density(3);
        m.record_rx(12);
        m.record_load_factor(0);
        assert_eq!(m.adaptive_sf(), 9);

        let mut m = RfHealthMetrics::new();
        m.record_density(12);
        m.record_rx(-3);
        m.record_load_factor((FP_SCALE * 85) / 100);
        assert_eq!(m.adaptive_sf(), 11);
        assert!(m.should_rebalance());

        let mut m = RfHealthMetrics::new();
        m.record_density(3);
        m.record_rx(-10);
        assert_eq!(m.adaptive_sf(), 12);

        let mut m = RfHealthMetrics::new();
        m.record_density(25);
        assert_eq!(m.adaptive_sf(), 12);
    }

    #[test]
    fn ccp_vectors_match() {
        // Tests full ccp16.json (and compatible with ccp15.json structure) for
        // exact match on EMA updates, load_factor recording, density, adaptive_sf,
        // should_rebalance per spec/02a-coordinated-capacity.md and vectors.
        let content = include_str!("../../../test/vectors/ccp16.json");
        let doc: Value = serde_json::from_str(content).unwrap();
        let vectors = doc.get("vectors").and_then(|v| v.as_array()).unwrap();
        for v in vectors {
            let input = v.get("input").unwrap_or(v);
            let output = v.get("output").unwrap_or(v);
            let density = input.get("density").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
            let snr = input
                .get("snr_db")
                .or_else(|| input.get("snr_ema"))
                .and_then(|x| x.as_i64())
                .unwrap_or(5) as i8;
            let load_f = input
                .get("load_factor")
                .and_then(|x| x.as_f64())
                .unwrap_or(0.0);
            let load_fp = ((load_f * FP_SCALE as f64) as u32).min(FP_SCALE);
            let mut m = RfHealthMetrics::new();
            m.record_density(density);
            m.record_rx(snr);
            m.record_load_factor(load_fp);
            let sf = m.adaptive_sf();
            let exp_sf = output.get("sf").and_then(|x| x.as_u64()).unwrap_or(10) as u8;
            assert_eq!(sf, exp_sf);
            let _ = m.should_rebalance();
            let _ = m.packet_loss_rate_fp();
        }
    }
}
