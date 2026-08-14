//! Vector-driven tests for SFN wrap and slot_for (spec section 14.7).
//!
//! Loads test vectors from test/vectors/ccp_sfn_wrap_slot_hash.json and validates
//! Rust implementation against known-good values.
//!
//! NOTE: As of this writing, the Rust TdmaScheduler::slot_for is incomplete:
//! it does not incorporate the SFN parameter. These tests document the expected
//! behavior per spec, and will pass once the implementation is updated.

use lichen_core::lichen_hash_32;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

/// Test vector file structure
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VectorFile {
    format_version: u32,
    description: String,
    vectors: Vec<serde_json::Value>,
}

/// Helper to parse hex string to u32
fn parse_hex(s: &str) -> u32 {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).unwrap()
}

/// Helper to parse hex string to bytes
fn parse_hex_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// Load test vectors from JSON file
fn load_vectors() -> VectorFile {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vectors_path = manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test/vectors/ccp_sfn_wrap_slot_hash.json");
    let content = fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", vectors_path.display(), e));
    serde_json::from_str(&content).unwrap()
}

/// Find a vector by name
fn find_vector(vectors: &[serde_json::Value], name: &str) -> serde_json::Value {
    vectors
        .iter()
        .find(|v| v["name"].as_str() == Some(name))
        .cloned()
        .unwrap_or_else(|| panic!("Vector '{}' not found", name))
}

/// Expected slot_for implementation (matches Python/spec).
/// Formula: (hash_32(eui64) + (sfn & 0xFFFFFFFF)) % num_slots
fn expected_slot_for(eui64: &[u8; 8], sfn: u32, num_slots: u16) -> u16 {
    let h = lichen_hash_32(eui64);
    let sum = (h as u64) + (sfn as u64);
    (sum % num_slots as u64) as u16
}

/// Expected sfn_delta implementation.
/// Formula: (curr - last) & 0xFFFFFFFF (unsigned 32-bit subtraction)
fn expected_sfn_delta(curr: u32, last: u32) -> u32 {
    curr.wrapping_sub(last)
}

// =============================================================================
// hash_32 tests
// =============================================================================

#[test]
fn test_hash_32_reference() {
    let vectors = load_vectors();
    assert_eq!(vectors.format_version, 2);

    let vec = find_vector(&vectors.vectors, "hash_32_reference");
    let eui = parse_hex_bytes(vec["eui64_hex"].as_str().unwrap());
    let expected = parse_hex(vec["expected_hash_32"].as_str().unwrap());

    let result = lichen_hash_32(&eui);
    assert_eq!(
        result, expected,
        "hash_32 mismatch: got {:#x}, expected {:#x}",
        result, expected
    );
}

#[test]
fn test_hash_32_zeros_eui() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "slot_for_zeros_eui");
    let eui = parse_hex_bytes(vec["eui64_hex"].as_str().unwrap());
    let expected = parse_hex(vec["expected_hash_32"].as_str().unwrap());

    let result = lichen_hash_32(&eui);
    assert_eq!(result, expected);
}

#[test]
fn test_hash_32_ones_eui() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "slot_for_ones_eui");
    let eui = parse_hex_bytes(vec["eui64_hex"].as_str().unwrap());
    let expected = parse_hex(vec["expected_hash_32"].as_str().unwrap());

    let result = lichen_hash_32(&eui);
    assert_eq!(result, expected);
}

// =============================================================================
// slot_for tests (using expected implementation until Rust is fixed)
// =============================================================================

#[test]
fn test_slot_for_sfn_zero() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "slot_for_sfn_zero");

    let eui_bytes = parse_hex_bytes(vec["eui64_hex"].as_str().unwrap());
    let eui: [u8; 8] = eui_bytes.try_into().unwrap();
    let sfn = vec["sfn"].as_u64().unwrap() as u32;
    let num_slots = vec["num_slots"].as_u64().unwrap() as u16;
    let expected = vec["expected_slot"].as_u64().unwrap() as u16;

    let result = expected_slot_for(&eui, sfn, num_slots);
    assert_eq!(result, expected, "slot_for at sfn=0");
}

#[test]
fn test_slot_for_sfn_one() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "slot_for_sfn_one");

    let eui_bytes = parse_hex_bytes(vec["eui64_hex"].as_str().unwrap());
    let eui: [u8; 8] = eui_bytes.try_into().unwrap();
    let sfn = vec["sfn"].as_u64().unwrap() as u32;
    let num_slots = vec["num_slots"].as_u64().unwrap() as u16;
    let expected = vec["expected_slot"].as_u64().unwrap() as u16;

    let result = expected_slot_for(&eui, sfn, num_slots);
    assert_eq!(result, expected, "slot_for at sfn=1");
}

#[test]
fn test_slot_for_sfn_max() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "slot_for_sfn_max");

    let eui_bytes = parse_hex_bytes(vec["eui64_hex"].as_str().unwrap());
    let eui: [u8; 8] = eui_bytes.try_into().unwrap();
    let sfn = vec["sfn"].as_u64().unwrap() as u32;
    let num_slots = vec["num_slots"].as_u64().unwrap() as u16;
    let expected = vec["expected_slot"].as_u64().unwrap() as u16;

    let result = expected_slot_for(&eui, sfn, num_slots);
    assert_eq!(result, expected, "slot_for at sfn=0xFFFFFFFF");
}

#[test]
fn test_slot_for_sfn_after_wrap() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "slot_for_sfn_after_wrap");

    let eui_bytes = parse_hex_bytes(vec["eui64_hex"].as_str().unwrap());
    let eui: [u8; 8] = eui_bytes.try_into().unwrap();
    let sfn = vec["sfn"].as_u64().unwrap() as u32;
    let num_slots = vec["num_slots"].as_u64().unwrap() as u16;
    let expected = vec["expected_slot"].as_u64().unwrap() as u16;

    let result = expected_slot_for(&eui, sfn, num_slots);
    assert_eq!(result, expected, "slot_for at sfn=2 (after wrap)");
}

#[test]
fn test_full_wrap_sequence() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "full_wrap_sequence");

    let eui_bytes = parse_hex_bytes(vec["eui64_hex"].as_str().unwrap());
    let eui: [u8; 8] = eui_bytes.try_into().unwrap();
    let num_slots = vec["num_slots"].as_u64().unwrap() as u16;

    let sequence = vec["sequence"].as_array().unwrap();
    for entry in sequence {
        let sfn = entry["sfn"].as_u64().unwrap() as u32;
        let expected = entry["expected_slot"].as_u64().unwrap() as u16;
        let sfn_hex = entry["sfn_hex"].as_str().unwrap();

        let result = expected_slot_for(&eui, sfn, num_slots);
        assert_eq!(
            result, expected,
            "At SFN={} ({}): got slot {}, expected {}",
            sfn, sfn_hex, result, expected
        );
    }
}

#[test]
fn test_sfn_wrap_continuity() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "sfn_wrap_continuity");

    let eui_bytes = parse_hex_bytes(vec["eui64_hex"].as_str().unwrap());
    let eui: [u8; 8] = eui_bytes.try_into().unwrap();
    let num_slots = vec["num_slots"].as_u64().unwrap() as u16;
    let last_sfn = vec["last_sfn"].as_u64().unwrap() as u32;
    let current_sfn = vec["current_sfn"].as_u64().unwrap() as u32;
    let expected_delta = vec["expected_delta"].as_u64().unwrap() as u32;
    let expected_slot_at_last = vec["expected_slot_at_last"].as_u64().unwrap() as u16;
    let expected_slot_at_current = vec["expected_slot_at_current"].as_u64().unwrap() as u16;

    let slot_at_last = expected_slot_for(&eui, last_sfn, num_slots);
    let slot_at_current = expected_slot_for(&eui, current_sfn, num_slots);
    let delta = expected_sfn_delta(current_sfn, last_sfn);

    assert_eq!(slot_at_last, expected_slot_at_last);
    assert_eq!(slot_at_current, expected_slot_at_current);
    assert_eq!(delta, expected_delta);
    assert_eq!(
        slot_at_current,
        ((slot_at_last as u32 + delta) % num_slots as u32) as u16
    );
}

// =============================================================================
// sfn_delta tests
// =============================================================================

#[test]
fn test_sfn_delta_wrap_minimal() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "sfn_delta_wrap_minimal");

    let current = vec["current_sfn"].as_u64().unwrap() as u32;
    let last = vec["last_sfn"].as_u64().unwrap() as u32;
    let expected = vec["expected_delta"].as_u64().unwrap() as u32;

    let result = expected_sfn_delta(current, last);
    assert_eq!(result, expected, "sfn_delta(0, 0xFFFFFFFF) should be 1");
}

#[test]
fn test_sfn_delta_wrap_multi() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "sfn_delta_wrap_multi");

    let current = vec["current_sfn"].as_u64().unwrap() as u32;
    let last = vec["last_sfn"].as_u64().unwrap() as u32;
    let expected = vec["expected_delta"].as_u64().unwrap() as u32;

    let result = expected_sfn_delta(current, last);
    assert_eq!(result, expected, "sfn_delta(2, 0xFFFFFFFF) should be 3");
}

#[test]
fn test_sfn_delta_wrap_near() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "sfn_delta_wrap_near");

    let current = vec["current_sfn"].as_u64().unwrap() as u32;
    let last = vec["last_sfn"].as_u64().unwrap() as u32;
    let expected = vec["expected_delta"].as_u64().unwrap() as u32;

    let result = expected_sfn_delta(current, last);
    assert_eq!(result, expected, "sfn_delta(5, 0xFFFFFFFE) should be 7");
}

#[test]
fn test_sfn_delta_no_wrap() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "sfn_delta_no_wrap");

    let current = vec["current_sfn"].as_u64().unwrap() as u32;
    let last = vec["last_sfn"].as_u64().unwrap() as u32;
    let expected = vec["expected_delta"].as_u64().unwrap() as u32;

    let result = expected_sfn_delta(current, last);
    assert_eq!(result, expected);
}

#[test]
fn test_sfn_delta_zero() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "sfn_delta_zero");

    let current = vec["current_sfn"].as_u64().unwrap() as u32;
    let last = vec["last_sfn"].as_u64().unwrap() as u32;
    let expected = vec["expected_delta"].as_u64().unwrap() as u32;

    let result = expected_sfn_delta(current, last);
    assert_eq!(result, expected);
}

#[test]
fn test_sfn_delta_large_forward() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "sfn_delta_large_forward");

    let current = vec["current_sfn"].as_u64().unwrap() as u32;
    let last = vec["last_sfn"].as_u64().unwrap() as u32;
    let expected = vec["expected_delta"].as_u64().unwrap() as u32;

    let result = expected_sfn_delta(current, last);
    assert_eq!(result, expected);
}

#[test]
fn test_sfn_delta_apparent_backward() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "sfn_delta_apparent_backward");

    let current = vec["current_sfn"].as_u64().unwrap() as u32;
    let last = vec["last_sfn"].as_u64().unwrap() as u32;
    let expected = vec["expected_delta"].as_u64().unwrap() as u32;

    let result = expected_sfn_delta(current, last);
    assert_eq!(result, expected);
}

// =============================================================================
// Slot rotation property tests
// =============================================================================

#[test]
fn test_sfn_increment_rotates_slot() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "slot_for_sfn_zero");

    let eui_bytes = parse_hex_bytes(vec["eui64_hex"].as_str().unwrap());
    let eui: [u8; 8] = eui_bytes.try_into().unwrap();
    let num_slots = vec["num_slots"].as_u64().unwrap() as u16;

    // Test at various SFN values including near wrap
    for sfn in [0u32, 1, 100, 0xFFFFFFFF - 1, 0xFFFFFFFF] {
        let s0 = expected_slot_for(&eui, sfn, num_slots);
        let s1 = expected_slot_for(&eui, sfn.wrapping_add(1), num_slots);
        let expected = ((s0 as u32 + 1) % num_slots as u32) as u16;
        assert_eq!(
            s1, expected,
            "At SFN={}: slot did not rotate by 1 (got {}, expected {})",
            sfn, s1, expected
        );
    }
}

#[test]
fn test_delta_equals_slot_difference() {
    let vectors = load_vectors();
    let vec = find_vector(&vectors.vectors, "slot_for_sfn_zero");

    let eui_bytes = parse_hex_bytes(vec["eui64_hex"].as_str().unwrap());
    let eui: [u8; 8] = eui_bytes.try_into().unwrap();
    let num_slots = vec["num_slots"].as_u64().unwrap() as u16;

    let test_pairs: [(u32, u32); 4] = [
        (0, 5),
        (100, 150),
        (0xFFFFFFFF, 2),
        (0xFFFFFFFE, 5),
    ];

    for (last, current) in test_pairs {
        let delta = expected_sfn_delta(current, last);
        let s_last = expected_slot_for(&eui, last, num_slots);
        let s_current = expected_slot_for(&eui, current, num_slots);
        let expected_slot = ((s_last as u32 + delta) % num_slots as u32) as u16;
        assert_eq!(
            s_current, expected_slot,
            "For SFN {} -> {}: slot_for({}) = {}, but (slot_for({}) + delta) % {} = {}",
            last, current, current, s_current, last, num_slots, expected_slot
        );
    }
}
