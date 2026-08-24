//! CCP-16 channel utilization test vectors per spec section 3.5 and 2a.7.
//!
//! Tests utilization thresholds and tx_allowed behavior:
//! - utilization 0-150: no SF adjustment from utilization
//! - utilization > 150: SF += 2
//! - utilization > 200: returns (12, false) - tx blocked
//!
//! Validates both the reference pseudocode AND the actual RfHealthMetrics::adaptive_sf_select
//! implementation against the test vectors.
//!
//! Cross-language oracle: Python reference implementation.

use lichen_core::rf_health::RfHealthMetrics;
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/ccp16_utilization.json");
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
    tx_allowed: bool,
}

/// Simulate select_tx_sf logic from spec pseudocode.
fn select_tx_sf(assigned_sf: u8, density: u8, utilization: u8, ema_loss: f32) -> (u8, bool) {
    let mut sf = assigned_sf;

    // Step 3: density/utilization > 150 check
    if density > 10 || utilization > 150 {
        sf = sf.saturating_add(2).min(12);
    }

    // Step 5: loss check
    if ema_loss > 0.25 {
        sf = sf.saturating_add(1).min(12);
    }

    // Step 6: utilization > 200 - force SF=12, tx_allowed=false
    if utilization > 200 {
        return (12, false);
    }

    (sf, true)
}

#[test]
fn ccp16_utilization_vectors() {
    let doc: Document = serde_json::from_str(VECTORS_JSON).expect("valid JSON");
    assert_eq!(doc.format_version, 2);
    assert_eq!(doc.vector_type, "ccp16_utilization");

    for vector in &doc.vectors {
        let (computed_sf, computed_tx_allowed) = select_tx_sf(
            vector.input.assigned_sf,
            vector.input.density,
            vector.input.utilization,
            vector.input.ema_loss,
        );

        assert_eq!(
            computed_sf, vector.output.sf,
            "{}: SF mismatch",
            vector.name
        );
        assert_eq!(
            computed_tx_allowed, vector.output.tx_allowed,
            "{}: tx_allowed mismatch",
            vector.name
        );
    }
}

#[test]
fn utilization_coverage() {
    let doc: Document = serde_json::from_str(VECTORS_JSON).expect("valid JSON");

    let names: Vec<&str> = doc.vectors.iter().map(|v| v.name.as_str()).collect();

    // Required threshold coverage
    assert!(names.iter().any(|n| n.contains("utilization_0")));
    assert!(names.iter().any(|n| n.contains("utilization_150")));
    assert!(names.iter().any(|n| n.contains("utilization_200")));
    assert!(names
        .iter()
        .any(|n| n.contains("utilization_201") || n.contains("tx_blocked")));
    assert!(names
        .iter()
        .any(|n| n.contains("utilization_255") || n.contains("saturated")));
}

/// Tests the actual RfHealthMetrics::adaptive_sf_select implementation against vectors.
/// This validates that the real implementation matches the spec pseudocode.
#[test]
fn rf_health_adaptive_sf_select_matches_vectors() {
    let doc: Document = serde_json::from_str(VECTORS_JSON).expect("valid JSON");

    for vector in &doc.vectors {
        let mut metrics = RfHealthMetrics::new();
        metrics.record_density(vector.input.density);
        // Record SNR to set up EMA state (single sample sets avg directly)
        metrics.record_rx(vector.input.ema_snr as i8);

        // Convert utilization from u8 raw value to Q16.16 fixed-point
        // Per spec, utilization is 0-255 where 255 = 100% (1.0)
        // But the threshold checks are against >150 and >200 as raw values
        // So we pass utilization as-is (scaled to FP: util * FP_SCALE / 100)
        let util_fp = (vector.input.utilization as u32).saturating_mul(FP_SCALE) / 100;

        // Convert ema_loss from float 0.0-1.0 to Q16.16
        let loss_fp = ((vector.input.ema_loss * FP_SCALE as f32) as u32).min(FP_SCALE);

        let (computed_sf, computed_tx_allowed) = metrics.adaptive_sf_select(
            Some(vector.input.assigned_sf),
            Some(util_fp),
            Some(loss_fp),
        );

        assert_eq!(
            computed_sf, vector.output.sf,
            "{}: RfHealthMetrics SF mismatch (expected {}, got {})",
            vector.name, vector.output.sf, computed_sf
        );
        assert_eq!(
            computed_tx_allowed, vector.output.tx_allowed,
            "{}: RfHealthMetrics tx_allowed mismatch",
            vector.name
        );
    }
}
