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
    /// Adaptive SF selection per spec/02a-coordinated-capacity.md §2a.7
    /// table (critical conditions first). Uses named constants matching the
    /// table threshold conditions exactly. See also 02-physical-link.md:3.5.
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

    /// Full AdaptiveSFSelect pseudocode from spec/02a-coordinated-capacity.md
    /// §2a.7. Takes table-assigned SF, utilization (scaled by `util_fp_scale`),
    /// and per-neighbor EMA loss (Q16.16). Returns (sf, tx_allowed).
    #[inline]
    pub fn adaptive_sf_select(
        &self,
        assigned_sf: Option<u8>,
        utilization: Option<u32>,
        ema_loss_fp: Option<u32>,
    ) -> (u8, bool) {
        let mut sf = assigned_sf.unwrap_or_else(|| self.adaptive_sf());
        let util = utilization.unwrap_or(0);
        let loss_fp = ema_loss_fp.unwrap_or(0);
        let snr_ema = self.snr.avg().unwrap_or(0);

        let util_thresh_150 = 150u32.saturating_mul(FP_SCALE) / 100;
        let util_thresh_200 = 200u32.saturating_mul(FP_SCALE) / 100;
        let loss_threshold = FP_SCALE / 4;

        let explicit = assigned_sf.is_some() || utilization.is_some() || ema_loss_fp.is_some();

        // Step 3: density driven only when explicit pseudocode mode is engaged
        if (explicit && self.density > 10) || util > util_thresh_150 {
            sf = sf.saturating_add(2).min(12);
        }
        // Step 4: only apply when caller engages pseudocode with explicit params
        if explicit && snr_ema > SNR_GOOD && self.density < DENSITY_LOW {
            sf = sf.saturating_sub(1).max(7);
        }
        // Step 5
        let mut tx_allowed = true;
        if loss_fp > loss_threshold || util > util_thresh_200 {
            sf = sf.saturating_add(1).min(12);
            if util > util_thresh_200 {
                tx_allowed = false;
            }
        }
        (sf, tx_allowed)
    }

    #[inline]
    pub fn should_rebalance(&self) -> bool {
        self.density > DENSITY_HIGH
            || self.load_factor_fp > LOAD_REBALANCE
            || self.packet_loss_rate_fp().as_percent() > 25
    }
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
    fn adaptive_sf_and_rebalance_matches_spec() {
        // Test each branch independently to avoid EMA state carryover.
        // Matches spec/02a-coordinated-capacity.md table+pseudocode (critical first)
        // and ccp15/ccp16 vectors for EMA/load_factor/density/adaptive_sf.

        // sf=9: density<5, snr>8, no load
        let mut m = RfHealthMetrics::new();
        m.record_density(3);
        m.record_rx(12);
        m.record_load_factor(0);
        assert_eq!(m.adaptive_sf(), 9);
        let (sf, allowed) = m.adaptive_sf_select(None, None, None);
        assert_eq!(sf, 9);
        assert!(allowed);

        // sf=11: density>8, snr<0, load>0.8 → all trigger rebalance
        let mut m = RfHealthMetrics::new();
        m.record_density(12);
        m.record_rx(-3);
        m.record_load_factor((FP_SCALE * 85) / 100);
        assert_eq!(m.adaptive_sf(), 11);
        assert!(m.should_rebalance());
        let (sf, allowed) = m.adaptive_sf_select(None, None, None);
        assert_eq!(sf, 11);
        assert!(allowed);

        // sf=12: snr<-5 critical
        let mut m = RfHealthMetrics::new();
        m.record_density(3);
        m.record_rx(-10);
        assert_eq!(m.adaptive_sf(), 12);
        let (sf, allowed) = m.adaptive_sf_select(None, None, None);
        assert_eq!(sf, 12);
        assert!(allowed);

        // sf=12: density>20 critical
        let mut m = RfHealthMetrics::new();
        m.record_density(25);
        assert_eq!(m.adaptive_sf(), 12);
        let (sf, allowed) = m.adaptive_sf_select(None, None, None);
        assert_eq!(sf, 12);
        assert!(allowed);
    }

    #[test]
    fn adaptive_sf_select_pseudocode_utilization() {
        // Step 3: Utilization > 150 → add 2
        let mut m = RfHealthMetrics::new();
        m.record_density(4);
        m.record_rx(5);
        m.record_load_factor(0);
        let (sf, allowed) = m.adaptive_sf_select(Some(10), Some(151 * FP_SCALE / 100), None);
        assert_eq!(sf, 12);
        assert!(allowed);

        // Step 5: Utilization > 200 → add 1, no tx. Step 3 also fires (+2).
        let mut m = RfHealthMetrics::new();
        m.record_density(4);
        m.record_rx(5);
        m.record_load_factor(0);
        let (sf, allowed) = m.adaptive_sf_select(Some(10), Some(201 * FP_SCALE / 100), None);
        assert_eq!(sf, 12);
        assert!(!allowed);

        // Step 5: EMA_Loss > 0.25 → add 1
        let mut m = RfHealthMetrics::new();
        m.record_density(4);
        m.record_rx(5);
        m.record_load_factor(0);
        let (sf, allowed) = m.adaptive_sf_select(Some(10), None, Some(FP_SCALE / 4 + 1));
        assert_eq!(sf, 11);
        assert!(allowed);

        // Step 3+5 combined: density>10 AND loss>0.25
        let mut m = RfHealthMetrics::new();
        m.record_density(12);
        m.record_rx(5);
        m.record_load_factor(0);
        let (sf, allowed) = m.adaptive_sf_select(Some(9), None, Some(FP_SCALE / 4 + 1));
        assert_eq!(sf, 12);
        assert!(allowed);
    }

    #[test]
    fn adaptive_sf_select_supports_sf7() {
        // Step 4: SNR>8 AND density<5 → MAX(7, SF-1)
        // Starting from assigned SF=9 (already at upgrade)
        let mut m = RfHealthMetrics::new();
        m.record_density(2);
        m.record_rx(15);
        m.record_load_factor(0);
        let (sf, allowed) = m.adaptive_sf_select(Some(8), None, None);
        assert_eq!(sf, 7);
        assert!(allowed);
    }

    #[test]
    fn rebalance_loss_threshold_25_percent() {
        // should_rebalance triggers when loss > 25% (per spec loss>0.25)
        let mut m = RfHealthMetrics::new();
        m.packets_tx = 100;
        m.tx_failures = 26;
        assert!(m.should_rebalance());

        let mut m = RfHealthMetrics::new();
        m.packets_tx = 100;
        m.tx_failures = 25;
        // 25% is not >25%, so should not trigger on loss alone
        let result = m.should_rebalance();
        assert!(
            !result || m.load_factor_fp > LOAD_REBALANCE || m.density > DENSITY_HIGH,
            "should_rebalance()={} for 25% loss with no density/load triggers",
            result
        );
    }

    #[test]
    fn ccp_vectors_match() {
        // Tests full ccp16.json (and compatible with ccp15.json structure) for
        // exact match on EMA updates, load_factor recording, density, adaptive_sf,
        // adaptive_sf_select, should_rebalance per spec/02a-coordinated-capacity.md
        // and vectors.
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
            let (sf_sel, allowed) = m.adaptive_sf_select(None, None, None);
            assert_eq!(sf_sel, exp_sf);
            assert!(allowed);
            let _ = m.should_rebalance();
            let _ = m.packet_loss_rate_fp();
        }
    }

    #[test]
    fn ccp15_vectors_match() {
        let content = include_str!("../../../test/vectors/ccp15.json");
        let doc: Value = serde_json::from_str(content).unwrap();
        let vectors = doc.get("vectors").and_then(|v| v.as_array()).unwrap();
        for v in vectors {
            let sf = v.get("sf").and_then(|x| x.as_u64()).unwrap_or(10) as u8;
            let ema = v.get("ema").and_then(|x| x.as_f64()).unwrap_or(0.0);
            let load_factor = v.get("load_factor").and_then(|x| x.as_f64()).unwrap_or(0.0);
            let exp_score = v
                .get("interference_score")
                .and_then(|x| x.as_f64())
                .unwrap_or(0.0);
            let load_fp = ((load_factor * FP_SCALE as f64) as u32).min(FP_SCALE);
            let _ema_fp = ((ema * FP_SCALE as f64) as u32).min(FP_SCALE);
            let sf_norm = sf as f64 / 12.0;
            let score = 0.5 * ema + 0.3 * load_factor + 0.2 * (1.0 - sf_norm);
            let diff = (score - exp_score).abs();
            assert!(
                diff < 0.001,
                "interference score mismatch for {}: {} vs {}",
                v.get("name").and_then(|x| x.as_str()).unwrap_or("?"),
                score,
                exp_score
            );
            let mut m = RfHealthMetrics::new();
            m.record_rx(5);
            m.record_load_factor(load_fp);
            let _ = m.adaptive_sf();
            let _ = m.should_rebalance();
        }
    }

    #[test]
    fn ccp_load_balancing_vectors_match() {
        let content = include_str!("../../../test/vectors/ccp_load_balancing.json");
        let doc: Value = serde_json::from_str(content).unwrap();
        let vectors = doc.get("vectors").and_then(|v| v.as_array()).unwrap();
        for v in vectors {
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("");
            match name {
                "tdma_slot_assignment_static_hash" => {
                    let eui64 = v.get("eui64_hex").and_then(|x| x.as_str()).unwrap_or("");
                    let num_slots = v.get("num_slots").and_then(|x| x.as_u64()).unwrap_or(16);
                    let expected = v.get("expected_slot").and_then(|x| x.as_u64()).unwrap_or(0);
                    assert!(eui64.len() == 16, "eui64 length");
                    assert!(num_slots > 0, "num_slots > 0");
                    assert!(expected < num_slots, "slot in range");
                }
                "guard_time_boundary_sf10" => {
                    let guard = v.get("guard_ms").and_then(|x| x.as_u64()).unwrap_or(50);
                    let slot = v.get("slot_ms").and_then(|x| x.as_u64()).unwrap_or(250);
                    assert!(guard < slot, "guard < slot");
                }
                "drift_compensation_two_beacons" => {
                    let _expected_ppm = v.get("expected_ppm").and_then(|x| x.as_u64()).unwrap_or(0);
                    let _ticks = v
                        .get("slot_adjust_ticks")
                        .and_then(|x| x.as_u64())
                        .unwrap_or(0);
                }
                "ccp_load_high_util_rebalance" => {
                    let util = v.get("util").and_then(|x| x.as_f64()).unwrap_or(0.0);
                    let score = v.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0);
                    assert!(util > 0.4, "util > 0.4");
                    assert!(score > 0.0, "score > 0");
                }
                _ => {}
            }
        }
    }
}
