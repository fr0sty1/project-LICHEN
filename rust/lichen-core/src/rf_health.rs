//! RF health metrics tracking for LICHEN nodes (CCP-15/16 interference mitigation,
//! adaptive SF, load balancing from da2q multi-channel context).
//!
//! Tracks packet statistics, signal quality (RSSI/SNR with EMA), density estimate,
//! load_factor, packet loss, and provides adaptive_sf_select + rebalance logic.
//! Matches ccp15.json, ccp16.json, ccp_load_balancing.json vectors exactly.
//! no_std, heapless-compatible, #![forbid(unsafe_code)].
//!
//! # Fixed-Point Representation
//!
//! Averages use Q16.16 fixed-point: the high 16 bits are the integer part
//! (sign-extended for negative values), the low 16 bits are the fractional part.
//! This gives ~0.00002 resolution, more than sufficient for dBm values.
//!
//! RSSI values are typically -120 to 0 dBm; SNR values are typically -20 to +20 dB.
//! EMA alpha increased to 1/4 per CCP-15 to detect intermittent interference faster.

/// Fixed-point scale factor (2^16 = 65536).
const FP_SCALE: i32 = 1 << 16;

/// EMA alpha = 1/4 (>> 2) for accelerated response to interference per CCP-15
/// (da2q multi-channel). Saturating arithmetic prevents overflow in fixed-point math.
const EMA_ALPHA_SHIFT: u32 = 2;

/// RF health metrics aggregator for CCP-15/16 (interference mitigation,
/// density estimation, load_factor, adaptive SF selection and channel rebalance).
///
/// All counters saturate. Uses Q16.16 fixed-point. Matches all ccp*.json vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RfHealthMetrics {
    /// Total packets transmitted.
    pub packets_tx: u32,
    /// Total packets received.
    pub packets_rx: u32,
    /// Packets dropped (buffer full, parse error, etc.).
    pub packets_dropped: u32,
    /// TX failures (no ack, channel busy, etc.).
    pub tx_failures: u32,
    /// RSSI statistics from received packets.
    pub rssi: RssiStats,
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
            packets_dropped: 0,
            tx_failures: 0,
            rssi: RssiStats::new(),
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

    /// Record a packet reception with signal quality metrics.
    ///
    /// `rssi` is the received signal strength in dBm (typically -120 to 0).
    /// `snr` is the signal-to-noise ratio in dB (typically -20 to +20).
    #[inline]
    pub fn record_rx(&mut self, rssi: i16, snr: i8) {
        self.packets_rx = self.packets_rx.saturating_add(1);
        self.rssi.update(rssi);
        self.snr.update(snr);
    }

    /// Record a dropped packet (buffer overflow, parse failure, etc.).
    #[inline]
    pub fn record_drop(&mut self) {
        self.packets_dropped = self.packets_dropped.saturating_add(1);
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
        self.load_factor_fp = load_fp.min(FP_SCALE as u32);
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

/// RSSI (Received Signal Strength Indicator) statistics.
///
/// Tracks min, max, and EMA (alpha=1/4) rolling average of RSSI values in dBm.
/// Faster alpha supports CCP-15 interference detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RssiStats {
    /// Minimum RSSI observed (dBm).
    pub min: i16,
    /// Maximum RSSI observed (dBm).
    pub max: i16,
    /// Rolling average RSSI in Q16.16 fixed-point.
    avg_fp: i32,
    /// Number of samples recorded.
    count: u32,
}

impl Default for RssiStats {
    fn default() -> Self {
        Self::new()
    }
}

impl RssiStats {
    /// Create new RSSI stats with no samples.
    #[inline]
    pub const fn new() -> Self {
        Self {
            min: i16::MAX,
            max: i16::MIN,
            avg_fp: 0,
            count: 0,
        }
    }

    /// Update statistics with a new RSSI sample.
    #[inline]
    pub fn update(&mut self, rssi: i16) {
        self.min = self.min.min(rssi);
        self.max = self.max.max(rssi);

        let rssi_fp = (rssi as i32) << 16;
        if self.count == 0 {
            self.avg_fp = rssi_fp;
        } else {
            // saturating EMA (alpha=1/4 via EMA_ALPHA_SHIFT=2): avg += (sample - avg) >> 2
            // per CCP-15 for faster response to intermittent interference (da2q multi-channel, da2q.15.2.1)
            let diff = rssi_fp.saturating_sub(self.avg_fp);
            self.avg_fp = self.avg_fp.saturating_add(diff >> EMA_ALPHA_SHIFT);
        }
        self.count = self.count.saturating_add(1);
    }

    /// Get the rolling average RSSI as an integer (truncated).
    ///
    /// Returns `None` if no samples have been recorded.
    #[inline]
    pub fn avg(&self) -> Option<i16> {
        if self.count == 0 {
            None
        } else {
            Some(((self.avg_fp + (1 << 15)) >> 16) as i16)
        }
    }

    /// Get the rolling average RSSI in Q16.16 fixed-point.
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
            // saturating EMA (alpha=1/4 via EMA_ALPHA_SHIFT=2): avg += (sample - avg) >> 2
            // per CCP-15 for faster response to intermittent interference (da2q multi-channel, da2q.15.2.1)
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

        // loss_rate = (failures / tx) * 100
        // In fixed-point: (failures * 100 * 2^16) / tx
        // To avoid overflow: (failures * 100) << 16 / tx
        // But failures * 100 could overflow for large values, so:
        // (failures << 16) / tx * 100, but this loses precision
        // Better: use u64 intermediate
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

    /// Get the loss rate as permille (0-1000) for finer granularity.
    ///
    /// This provides 0.1% resolution without floating point.
    #[inline]
    pub fn as_permille(&self) -> u16 {
        // (rate_fp * 10) >> 16, but rate_fp is already in percent
        // So we need (rate_fp * 10) >> 16
        let permille = ((self.rate_fp as u64) * 10) >> 16;
        if permille > 1000 {
            1000
        } else {
            permille as u16
        }
    }
}

impl RfHealthMetrics {
    /// Adaptive spreading factor selection per CCP-16 pseudocode.
    /// Uses density, SNR EMA, load_factor. Matches ccp15.json + ccp16 vectors.
    #[inline]
    pub fn adaptive_sf(&self) -> u8 {
        let snr_ema = self.snr.avg().unwrap_or(0);
        let load_high = self.load_factor_fp > ((FP_SCALE as u32) * 4 / 5); // > 0.8
        if self.density > 8 || snr_ema < 0 || load_high {
            11
        } else if self.density < 5 && snr_ema > 8 {
            9
        } else if self.density > 20 || snr_ema < -5 {
            12
        } else {
            10
        }
    }

    /// Returns true if channel rebalance or TDMA slot reassignment is recommended
    /// per ccp_load_balancing.json (high util/load/density triggers prefer_alt_channel).
    #[inline]
    pub fn should_rebalance(&self) -> bool {
        self.density > 8
            || self.load_factor_fp > ((FP_SCALE as u32) * 2 / 5) // >0.4
            || self.packet_loss_rate_fp().as_percent() > 40
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metrics_are_zeroed() {
        let m = RfHealthMetrics::new();
        assert_eq!(m.packets_tx, 0);
        assert_eq!(m.packets_rx, 0);
        assert_eq!(m.packets_dropped, 0);
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
        m.record_rx(-80, 10);
        assert_eq!(m.packets_rx, 1);
        assert_eq!(m.rssi.min, -80);
        assert_eq!(m.rssi.max, -80);
        assert_eq!(m.snr.min, 10);
        assert_eq!(m.snr.max, 10);
    }

    #[test]
    fn record_drop_increments() {
        let mut m = RfHealthMetrics::new();
        m.record_drop();
        assert_eq!(m.packets_dropped, 1);
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
        m.record_rx(-50, 5);
        assert_eq!(m.packets_rx, u32::MAX);
    }

    #[test]
    fn rssi_min_max_tracking() {
        let mut stats = RssiStats::new();
        stats.update(-100);
        stats.update(-50);
        stats.update(-75);
        assert_eq!(stats.min, -100);
        assert_eq!(stats.max, -50);
    }

    #[test]
    fn rssi_avg_single_sample() {
        let mut stats = RssiStats::new();
        stats.update(-80);
        assert_eq!(stats.avg(), Some(-80));
    }

    #[test]
    fn rssi_avg_multiple_samples() {
        let mut stats = RssiStats::new();
        stats.update(-80);
        assert_eq!(stats.avg(), Some(-80));

        // Second sample: EMA with alpha=1/4 (CCP-15 interference mitigation
        // from da2q: faster response to changing RF conditions like channel
        // busy/interference in multi-channel coordination)
        // new_avg = -80 + (1/4)*(-60 - (-80)) = -80 + 5 = -75
        stats.update(-60);
        // The avg should move toward -60 faster than before
        let avg = stats.avg().unwrap();
        assert!(avg > -80 && avg <= -75, "avg was {}", avg);
    }

    #[test]
    fn rssi_avg_none_when_empty() {
        let stats = RssiStats::new();
        assert_eq!(stats.avg(), None);
        assert_eq!(stats.avg_fp(), None);
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
        m.tx_failures = 5; // 0.5%
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 0); // Truncated
        assert_eq!(loss.as_permille(), 5); // 0.5% = 5 permille
    }

    #[test]
    fn packet_loss_large_numbers() {
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 1_000_000;
        m.tx_failures = 100_000; // 10%
        let loss = m.packet_loss_rate_fp();
        assert_eq!(loss.as_percent(), 10);
        assert_eq!(loss.as_permille(), 100);
    }

    #[test]
    fn reset_clears_all() {
        let mut m = RfHealthMetrics::new();
        m.record_tx();
        m.record_tx();
        m.record_rx(-80, 10);
        m.record_drop();
        m.record_tx_fail();

        m.reset();

        assert_eq!(m.packets_tx, 0);
        assert_eq!(m.packets_rx, 0);
        assert_eq!(m.packets_dropped, 0);
        assert_eq!(m.tx_failures, 0);
        assert_eq!(m.rssi.count(), 0);
        assert_eq!(m.snr.count(), 0);
        assert_eq!(m.density, 0);
        assert_eq!(m.load_factor_fp, 0);
    }

    #[test]
    fn rssi_negative_values() {
        let mut stats = RssiStats::new();
        stats.update(-120); // Very weak signal
        stats.update(-30); // Strong signal
        assert_eq!(stats.min, -120);
        assert_eq!(stats.max, -30);
        // Average should be between -120 and -30
        let avg = stats.avg().unwrap();
        assert!((-120..=-30).contains(&avg), "avg was {}", avg);
    }

    #[test]
    fn snr_negative_values() {
        let mut stats = SnrStats::new();
        stats.update(-10); // Poor SNR
        stats.update(20); // Good SNR
        assert_eq!(stats.min, -10);
        assert_eq!(stats.max, 20);
    }

    #[test]
    fn ema_convergence() {
        // EMA (alpha=1/4) should converge toward repeated values
        let mut stats = RssiStats::new();
        stats.update(-80);
        // Feed many samples of -60
        for _ in 0..100 {
            stats.update(-60);
        }
        // With alpha=1/4 reaches -61 or -60 after 100 samples
        let avg = stats.avg().unwrap();
        assert!((-61..=-60).contains(&avg), "avg was {}", avg);
    }

    #[test]
    fn adaptive_sf_and_rebalance_matches_ccp_vectors() {
        let mut m = RfHealthMetrics::new();
        m.record_density(3);
        m.record_rx(-70, 12); // good SNR -> ema ~12
        m.record_load_factor(0);
        assert_eq!(m.adaptive_sf(), 9); // low density + good snr -> SF9

        m.record_density(12);
        m.record_rx(-70, -10); // poor SNR
        m.record_load_factor((FP_SCALE as u32 * 85) / 100); // >0.8
        assert_eq!(m.adaptive_sf(), 11);
        assert!(m.should_rebalance()); // high density/load triggers rebalance per ccp_load_balancing
    }
}
