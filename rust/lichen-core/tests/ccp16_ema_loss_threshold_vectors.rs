//! CCP-16 EMA packet loss threshold test vectors per spec section 3.5 and 2a.7.
//!
//! Tests the EMA loss threshold boundary behavior:
//! - ema_loss <= 0.25: no SF bump (threshold is strictly >)
//! - ema_loss > 0.25: SF += 1
//!
//! Validates both the reference pseudocode AND the actual RfHealthMetrics::adaptive_sf_select
//! implementation against the test vectors.
//!
//! Cross-language oracle: Python reference implementation.

use lichen_core::rf_health::RfHealthMetrics;
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/ccp16_ema_loss_threshold.json");
const FP_SCALE: u32 = 1 << 16;

#[derive(Deserialize)]
struct Document {
    format_version: u8,
    vector_type: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    input: Input,
    output: Output,
}

#[derive(Deserialize)]
struct Input {
    assigned_sf: u8,
    density: u8,
    utilization: u8,
    ema_snr: f32,
    ema_loss: f32,
}

#[derive(Deserialize)]
struct Output {
    sf: u8,
    sf_bumped: bool,
}

/// Simulate select_tx_sf logic from spec pseudocode for loss threshold.
fn select_tx_sf_loss_check(
    assigned_sf: u8,
    density: u8,
    utilization: u8,
    ema_snr: f32,
    ema_loss: f32,
) -> (u8, bool) {
    let mut sf = assigned_sf;
    let mut bumped = false;

    // Step 3: density/utilization > 150 check
    if density > 10 || utilization > 150 {
        sf = sf.saturating_add(2).min(12);
    }

    // Step 4: SNR upgrade (good link quality, low density)
    if ema_snr > 8.0 && density < 5 {
        sf = sf.saturating_sub(1).max(7);
    }

    // Step 5a: loss check
    if ema_loss > 0.25 {
        sf = sf.saturating_add(1).min(12);
        bumped = true;
    }

    // Step 5b: utilization > 200 - force SF=12
    if utilization > 200 {
        return (12, bumped);
    }

    (sf, bumped)
}

#[test]
fn ccp16_ema_loss_threshold_vectors() {
    let doc: Document = serde_json::from_str(VECTORS_JSON).expect("valid JSON");
    assert_eq!(doc.format_version, 2);
    assert_eq!(doc.vector_type, "ccp16_ema_loss_threshold");

    for vector in &doc.vectors {
        let (computed_sf, computed_bumped) = select_tx_sf_loss_check(
            vector.input.assigned_sf,
            vector.input.density,
            vector.input.utilization,
            vector.input.ema_snr,
            vector.input.ema_loss,
        );

        assert_eq!(
            computed_sf, vector.output.sf,
            "{}: SF mismatch (expected {}, got {})",
            vector.name, vector.output.sf, computed_sf
        );
        assert_eq!(
            computed_bumped, vector.output.sf_bumped,
            "{}: sf_bumped mismatch",
            vector.name
        );
    }
}

/// Tests the actual RfHealthMetrics::adaptive_sf_select implementation against vectors.
#[test]
fn rf_health_adaptive_sf_select_ema_loss_matches_vectors() {
    let doc: Document = serde_json::from_str(VECTORS_JSON).expect("valid JSON");

    for vector in &doc.vectors {
        let mut metrics = RfHealthMetrics::new();
        metrics.record_density(vector.input.density);
        // Record SNR to set up EMA state (single sample sets avg directly)
        metrics.record_rx(vector.input.ema_snr as i8);

        // Convert utilization from u8 raw value to Q16.16 fixed-point
        let util_fp = (vector.input.utilization as u32).saturating_mul(FP_SCALE) / 100;

        // Convert ema_loss from float 0.0-1.0 to Q16.16
        let loss_fp = ((vector.input.ema_loss * FP_SCALE as f32) as u32).min(FP_SCALE);

        let (computed_sf, _tx_allowed) = metrics.adaptive_sf_select(
            Some(vector.input.assigned_sf),
            Some(util_fp),
            Some(loss_fp),
        );

        assert_eq!(
            computed_sf, vector.output.sf,
            "{}: RfHealthMetrics SF mismatch (expected {}, got {})",
            vector.name, vector.output.sf, computed_sf
        );
    }
}

#[test]
fn ema_loss_threshold_coverage() {
    let doc: Document = serde_json::from_str(VECTORS_JSON).expect("valid JSON");

    let names: Vec<&str> = doc.vectors.iter().map(|v| v.name.as_str()).collect();

    // Required boundary coverage
    assert!(names
        .iter()
        .any(|n| n.contains("0.24") || n.contains("below_threshold")));
    assert!(names
        .iter()
        .any(|n| n.contains("0.25") || n.contains("at_threshold")));
    assert!(names
        .iter()
        .any(|n| n.contains("0.26") || n.contains("above_threshold")));
    assert!(names
        .iter()
        .any(|n| n.contains("sf12") || n.contains("capped")));
}

#[test]
fn loss_threshold_exact_boundary_fp() {
    // Verify that Q16.16 representation of 0.25 is handled correctly
    // FP_SCALE / 4 = 16384 = 0.25 in Q16.16
    let threshold = FP_SCALE / 4;

    // At threshold: loss_fp = 16384 should NOT trigger bump (> not >=)
    let mut metrics = RfHealthMetrics::new();
    metrics.record_density(5);
    metrics.record_rx(5);
    let (sf_at, _) = metrics.adaptive_sf_select(Some(10), None, Some(threshold));
    assert_eq!(sf_at, 10, "0.25 exactly should not bump SF");

    // Just above: loss_fp = 16385 should trigger bump
    let (sf_above, _) = metrics.adaptive_sf_select(Some(10), None, Some(threshold + 1));
    assert_eq!(sf_above, 11, "0.25 + epsilon should bump SF");

    // Just below: loss_fp = 16383 should not trigger bump
    let (sf_below, _) = metrics.adaptive_sf_select(Some(10), None, Some(threshold - 1));
    assert_eq!(sf_below, 10, "0.25 - epsilon should not bump SF");
}
