//! EMA (Exponential Moving Average) test vectors for CCP adaptive SF.
//!
//! Validates the Q16.16 fixed-point EMA implementation in `rf_health::SnrStats`
//! against cross-language test vectors. The EMA formula is:
//! new_avg = avg + ((sample - avg) >> 2) with alpha=1/4.
//!
//! Cross-language oracle: Python uses float arithmetic (diff * 0.25) while
//! Rust uses Q16.16 fixed-point with arithmetic right shift (diff >> 2).
//! For integer inputs, both produce identical EMA update results.

use serde::Deserialize;
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/ccp_ema_update_integer.json");

const FP_SCALE: i32 = 1 << 16;
const EMA_ALPHA_SHIFT: u32 = 2;

/// Q16.16 fixed-point EMA update matching SnrStats::update implementation.
fn ema_update_fp(avg_fp: i32, sample: i8) -> i32 {
    let sample_fp = (sample as i32) << 16;
    let diff = sample_fp.saturating_sub(avg_fp);
    avg_fp.saturating_add(diff >> EMA_ALPHA_SHIFT)
}

/// Convert Q16.16 to integer with round-half-up (matching SnrStats::avg).
fn fp_to_int_round_half_up(avg_fp: i32) -> i8 {
    ((avg_fp + (1 << 15)) >> 16) as i8
}

#[derive(Deserialize)]
struct Document {
    format_version: u8,
    vector_type: String,
    #[allow(dead_code)]
    description: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    #[allow(dead_code)]
    description: String,
    #[serde(rename = "type")]
    vec_type: Option<String>,
    input: Value,
    output: Value,
}

#[test]
fn ema_single_update_vectors() {
    let doc: Document = serde_json::from_str(VECTORS_JSON).expect("valid JSON");
    assert_eq!(doc.format_version, 2);
    assert_eq!(doc.vector_type, "ccp_ema_update");

    for vector in doc.vectors.iter().filter(|v| v.vec_type.is_none()) {
        let name = &vector.name;
        let inp = &vector.input;
        let out = &vector.output;

        let avg = inp["avg"].as_i64().unwrap() as i32;
        let sample = inp["sample"].as_i64().unwrap() as i8;
        let avg_fp = avg * FP_SCALE;

        // Compute EMA update
        let new_avg_fp = ema_update_fp(avg_fp, sample);

        // Verify Q16.16 result matches expected
        let expected_fp = out["new_avg_fp"].as_i64().unwrap() as i32;
        assert_eq!(new_avg_fp, expected_fp, "{}: new_avg_fp mismatch", name);

        // Verify integer conversion with round-half-up
        let new_avg_int = fp_to_int_round_half_up(new_avg_fp);
        let expected_int = out["new_avg_int_round_half_up"].as_i64().unwrap() as i8;
        assert_eq!(
            new_avg_int, expected_int,
            "{}: new_avg_int_round_half_up mismatch",
            name
        );

        // Verify diff computation
        let diff = sample as i32 - avg;
        let expected_diff = out["diff"].as_i64().unwrap() as i32;
        assert_eq!(diff, expected_diff, "{}: diff mismatch", name);
    }
}

#[test]
fn ema_sequence_vectors() {
    let doc: Document = serde_json::from_str(VECTORS_JSON).expect("valid JSON");

    for vector in doc
        .vectors
        .iter()
        .filter(|v| v.vec_type.as_deref() == Some("sequence"))
    {
        let name = &vector.name;
        let inp = &vector.input;
        let out = &vector.output;

        let initial_avg = inp["initial_avg"].as_i64().unwrap() as i32;
        let samples: Vec<i8> = inp["samples"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap() as i8)
            .collect();

        let expected_intermediate: Vec<i32> = out["intermediate_avg_fp"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap() as i32)
            .collect();

        // Apply sequence and verify intermediate values
        let mut avg_fp = initial_avg * FP_SCALE;
        for (i, &sample) in samples.iter().enumerate() {
            avg_fp = ema_update_fp(avg_fp, sample);
            assert_eq!(
                avg_fp, expected_intermediate[i],
                "{}: intermediate[{}] mismatch",
                name, i
            );
        }

        // Verify final value
        let expected_final_fp = out["final_avg_fp"].as_i64().unwrap() as i32;
        assert_eq!(avg_fp, expected_final_fp, "{}: final_avg_fp mismatch", name);

        // Verify final integer conversion
        let final_int = fp_to_int_round_half_up(avg_fp);
        let expected_final_int = out["final_avg_int_round_half_up"].as_i64().unwrap() as i8;
        assert_eq!(
            final_int, expected_final_int,
            "{}: final_avg_int mismatch",
            name
        );
    }
}

#[test]
fn ema_vector_coverage() {
    let doc: Document = serde_json::from_str(VECTORS_JSON).expect("valid JSON");

    let names: Vec<&str> = doc.vectors.iter().map(|v| v.name.as_str()).collect();

    // Verify required coverage
    assert!(names.contains(&"basic_positive_diff_divisible_by_4"));
    assert!(names.contains(&"negative_diff_divisible_by_4"));
    assert!(names.contains(&"small_diff_not_divisible_by_4"));
    assert!(names.contains(&"negative_diff_not_divisible_by_4"));
    assert!(names.contains(&"diff_minus_7_shows_rounding_divergence"));
    assert!(names.contains(&"boundary_sf12_snr_critical"));
    assert!(names.contains(&"boundary_sf11_snr_poor"));
    assert!(names.contains(&"boundary_sf9_snr_good"));
    assert!(names.contains(&"i8_boundary_max"));
    assert!(names.contains(&"i8_boundary_min"));
    assert!(names.contains(&"convergence_sequence_positive"));
    assert!(names.contains(&"convergence_sequence_negative"));
    assert!(names.contains(&"alternating_sequence"));

    // Verify minimum vector count
    assert!(doc.vectors.len() >= 15, "insufficient vector coverage");
}

#[test]
fn ema_matches_snr_stats_implementation() {
    use lichen_core::rf_health::SnrStats;

    let doc: Document = serde_json::from_str(VECTORS_JSON).expect("valid JSON");

    // Test single sample updates (starting from count=0)
    // Note: SnrStats::update sets first sample directly (no EMA), then uses EMA
    // for subsequent samples. The vectors test pure EMA formula.
    for vector in doc.vectors.iter().filter(|v| v.vec_type.is_none()) {
        let name = &vector.name;
        let inp = &vector.input;

        // Only test cases starting from avg=0 since SnrStats::new() starts at 0
        let avg = inp["avg"].as_i64().unwrap();
        if avg != 0 {
            continue;
        }

        let sample = inp["sample"].as_i64().unwrap() as i8;
        let mut stats = SnrStats::new();
        stats.update(sample);

        // For first sample, avg_fp should be sample * FP_SCALE
        // (no EMA, just initialization)
        let expected_direct = (sample as i32) << 16;

        // SnrStats sets first sample directly, not via EMA
        assert_eq!(
            stats.avg_fp().unwrap(),
            expected_direct,
            "{}: first sample should set avg directly",
            name
        );
    }

    // Test that SnrStats EMA blending matches vectors when we have 2+ samples
    // We feed two samples: first sets avg directly, second uses EMA
    let mut stats = SnrStats::new();
    stats.update(20); // First sample: sets avg to 20 directly
    stats.update(12); // Second sample: EMA from avg=20, sample=12

    // This should match the "basic_positive_diff_divisible_by_4" vector
    // new_avg = 20 + (12 - 20) / 4 = 20 - 2 = 18
    assert_eq!(stats.avg().unwrap(), 18, "SnrStats EMA update mismatch");

    // Verify EMA formula applied correctly for second sample
    // avg_fp after first sample: 20 * 65536 = 1310720
    // diff = 12 * 65536 - 1310720 = -524288
    // new_avg_fp = 1310720 + (-524288 >> 2) = 1310720 - 131072 = 1179648
    assert_eq!(stats.avg_fp().unwrap(), 1179648);
}

#[test]
fn arithmetic_right_shift_behavior() {
    // Verify that Rust's >> on signed integers is arithmetic (sign-extending)
    // This is required for correct EMA computation with negative values

    // Positive values: >> fills with 0
    assert_eq!(8i32 >> 2, 2);
    assert_eq!(7i32 >> 2, 1);
    assert_eq!(3i32 >> 2, 0);

    // Negative values: >> fills with 1 (sign extension)
    assert_eq!((-8i32) >> 2, -2);
    assert_eq!((-7i32) >> 2, -2); // -7 >> 2 = -2 (rounds towards -inf)
    assert_eq!((-3i32) >> 2, -1); // -3 >> 2 = -1 (rounds towards -inf)
    assert_eq!((-1i32) >> 2, -1); // -1 >> 2 = -1 (all 1s remains all 1s)

    // This is the critical behavior for EMA with negative SNR values
    // Python's >> also does arithmetic shift on signed integers
}
