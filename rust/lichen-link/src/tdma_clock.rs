//! TDMA slot-clock helpers (spec 02a drift, guard, CCP-7 holdover).
//!
//! Formulas:
//! - `delta_ms = local_rx_ms - expected_beacon_ms`
//! - `drift_ppm = (delta_ms * 1_000_000) / beacon_interval_ms`
//! - `correction_ms = drift_ppm * future_delta_ms / 1_000_000`
//! - `B(h) = B(0) + rho * h`
//! - `G >= B_i + B_j + J_i + J_j + P + M`
//! - Drift beyond `guard_ppm` (5000 in ccp16-desync) ends holdover.

/// Beacon arrival offset (local minus expected), milliseconds.
pub const fn beacon_delta_ms(local_rx_ms: i64, expected_beacon_ms: i64) -> i64 {
    local_rx_ms.saturating_sub(expected_beacon_ms)
}

/// Oscillator drift in ppm from a beacon delta and interval.
pub const fn drift_ppm(delta_ms: i64, beacon_interval_ms: u64) -> Option<i64> {
    if beacon_interval_ms == 0 {
        return None;
    }
    Some(((delta_ms as i128) * 1_000_000 / (beacon_interval_ms as i128)) as i64)
}

/// Linear correction to apply at `future_delta_ms` given a ppm estimate.
pub const fn correction_ms(drift_ppm: i64, future_delta_ms: i64) -> i64 {
    ((drift_ppm as i128) * (future_delta_ms as i128) / 1_000_000) as i64
}

/// Drift bound `B(h) = B(0) + rho * h`.
pub const fn drift_bound(b0: u64, rho: u64, h: u64) -> u64 {
    b0.saturating_add(rho.saturating_mul(h))
}

/// True when the 50 ms-class guard covers both nodes' bounds and jitter.
pub const fn guard_sufficient(
    guard: u64,
    b_i: u64,
    b_j: u64,
    j_i: u64,
    j_j: u64,
    p: u64,
    m: u64,
) -> bool {
    let need = b_i
        .saturating_add(b_j)
        .saturating_add(j_i)
        .saturating_add(j_j)
        .saturating_add(p)
        .saturating_add(m);
    guard >= need
}

/// Trailing-guard check for a TDMA slot.
pub const fn in_guard(
    slot_start_ms: u64,
    current_ms: u64,
    slot_duration_ms: u64,
    guard_ms: u64,
) -> bool {
    if slot_duration_ms < guard_ms {
        return false;
    }
    let guard_start = slot_start_ms.saturating_add(slot_duration_ms.saturating_sub(guard_ms));
    let slot_end = slot_start_ms.saturating_add(slot_duration_ms);
    current_ms >= guard_start && current_ms < slot_end
}

/// TX is allowed in the data window, not in the trailing guard.
pub const fn tx_allowed(
    slot_start_ms: u64,
    current_ms: u64,
    slot_duration_ms: u64,
    guard_ms: u64,
) -> bool {
    if current_ms < slot_start_ms {
        return false;
    }
    !in_guard(slot_start_ms, current_ms, slot_duration_ms, guard_ms)
        && current_ms < slot_start_ms.saturating_add(slot_duration_ms)
}

/// Holdover ends when measured |drift_ppm| exceeds the configured guard.
pub const fn holdover_expired(measured_drift_ppm: i64, guard_ppm: u64) -> bool {
    measured_drift_ppm.unsigned_abs() > guard_ppm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ccp_tdma_drift_compensation_delta_is_correction() {
        assert_eq!(beacon_delta_ms(123_456, 123_400), 56);
        assert_eq!(correction_ms(10, 5_600_000), 56);
        assert_eq!(drift_ppm(56, 5_600_000), Some(10));
    }

    #[test]
    fn guard_window_matches_sf10_vectors() {
        assert!(!in_guard(1000, 3295, 2346, 50));
        assert!(tx_allowed(1000, 3295, 2346, 50));
        assert!(in_guard(1000, 3296, 2346, 50));
        assert!(!tx_allowed(1000, 3296, 2346, 50));
    }

    #[test]
    fn holdover_expires_above_guard_ppm() {
        assert!(!holdover_expired(5000, 5000));
        assert!(holdover_expired(12_000, 5000));
        assert_eq!(drift_bound(10, 2, 5), 20);
        assert!(guard_sufficient(50, 10, 10, 5, 5, 5, 5));
        assert!(!guard_sufficient(50, 20, 20, 5, 5, 5, 5));
    }

    #[test]
    fn zero_interval_has_no_ppm() {
        assert_eq!(drift_ppm(10, 0), None);
    }
}
