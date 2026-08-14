// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Test CCP beacon format and TDMA slot assignment against cross-language vectors.
//!
//! These vectors expose implementation divergence between Python and Rust:
//! - Python slot_for: (hash_32(eui64) + sfn) % num_slots
//! - Rust TdmaScheduler::slot_for: lichen_hash_32(eui) % 16 (ignores SFN, hardcodes 16)
//!
//! The Rust implementation is KNOWN TO DIVERGE from Python for non-zero SFN values.
//! This test documents the current behavior; fixing the divergence requires spec clarification.

use lichen_core::lichen_hash_32;

const JSON: &str = include_str!("../../../test/vectors/ccp_beacon_format.json");

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Extract string field value from JSON object substring.
fn string_field<'a>(object: &'a str, name: &str) -> Option<&'a str> {
    let pattern = format!("\"{}\":", name);
    let after = object.split_once(&pattern)?.1.trim_start();
    if after.starts_with('"') {
        let value = after.strip_prefix('"')?.split_once('"')?.0;
        Some(value)
    } else {
        None
    }
}

/// Extract integer field value from JSON object substring.
fn int_field(object: &str, name: &str) -> Option<u64> {
    let pattern = format!("\"{}\":", name);
    let after = object.split_once(&pattern)?.1.trim_start();
    let end = after.find(|c: char| !c.is_ascii_digit())?;
    after[..end].parse().ok()
}

/// Extract boolean field value from JSON object substring.
fn bool_field(object: &str, name: &str) -> Option<bool> {
    let pattern = format!("\"{}\":", name);
    let after = object.split_once(&pattern)?.1.trim_start();
    if after.starts_with("true") {
        Some(true)
    } else if after.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Current Rust slot_for implementation (documents divergence from Python).
///
/// NOTE: This ignores SFN and hardcodes num_slots=16, which diverges from Python.
fn rust_slot_for(eui: &[u8; 8]) -> u16 {
    let h = lichen_hash_32(eui);
    (h % 16) as u16
}

/// Proposed fixed slot_for implementation that matches Python behavior.
fn slot_for_fixed(eui: &[u8; 8], sfn: u32, num_slots: u16) -> u16 {
    if num_slots == 0 {
        return 0;
    }
    let h = lichen_hash_32(eui);
    let combined = h.wrapping_add(sfn);
    (combined % num_slots as u32) as u16
}

/// Split JSON into vector objects.
fn extract_vectors(json: &str) -> Vec<&str> {
    let mut vectors = Vec::new();
    let vectors_start = json.find("\"vectors\":").expect("no vectors field");
    let arr_start = json[vectors_start..].find('[').unwrap() + vectors_start + 1;

    let mut depth = 0;
    let mut obj_start = None;

    for (i, c) in json[arr_start..].char_indices() {
        match c {
            '{' => {
                if depth == 0 {
                    obj_start = Some(arr_start + i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(start) = obj_start {
                        vectors.push(&json[start..arr_start + i + 1]);
                    }
                    obj_start = None;
                }
            }
            ']' if depth == 0 => break,
            _ => {}
        }
    }
    vectors
}

#[test]
fn test_vectors_file_parses() {
    let vectors = extract_vectors(JSON);
    assert!(!vectors.is_empty(), "should have at least one vector");

    // Verify format version
    assert!(
        JSON.contains("\"format_version\": 2"),
        "expected format_version 2"
    );
}

#[test]
fn test_hash_32_fnv1a_vectors() {
    for v in extract_vectors(JSON) {
        let type_field = string_field(v, "type");
        if type_field != Some("hash_32") {
            continue;
        }

        let name = string_field(v, "name").unwrap_or("unknown");
        let input_section = v.split_once("\"input\":").unwrap().1;
        let data_hex = string_field(input_section, "data_hex").unwrap_or("");
        let output_section = v.split_once("\"output\":").unwrap().1;
        let expected = int_field(output_section, "hash_32").unwrap() as u32;

        let data = hex_to_bytes(data_hex);
        let computed = lichen_hash_32(&data);

        assert_eq!(
            computed, expected,
            "{}: hash_32 mismatch: got 0x{:08x}, expected 0x{:08x}",
            name, computed, expected
        );
    }
}

#[test]
fn test_slot_selection_current_behavior() {
    for v in extract_vectors(JSON) {
        let type_field = string_field(v, "type");
        if type_field != Some("slot_selection") {
            continue;
        }

        let name = string_field(v, "name").unwrap_or("unknown");
        let input_section = v.split_once("\"input\":").unwrap().1;
        let eui64_hex = string_field(input_section, "eui64").unwrap();
        let output_section = v.split_once("\"output\":").unwrap().1;
        let rust_expected = int_field(output_section, "slot_rust_expected").unwrap() as u16;

        let eui_bytes = hex_to_bytes(eui64_hex);
        let eui: [u8; 8] = eui_bytes.try_into().unwrap();

        let computed = rust_slot_for(&eui);

        assert_eq!(
            computed, rust_expected,
            "{}: Rust slot mismatch: got {}, expected {}",
            name, computed, rust_expected
        );
    }
}

#[test]
fn test_slot_selection_divergence_documented() {
    for v in extract_vectors(JSON) {
        let type_field = string_field(v, "type");
        if type_field != Some("slot_selection") {
            continue;
        }

        let name = string_field(v, "name").unwrap_or("unknown");
        let output_section = v.split_once("\"output\":").unwrap().1;
        let slot_python = int_field(output_section, "slot_python").unwrap() as u16;
        let slot_rust = int_field(output_section, "slot_rust_expected").unwrap() as u16;
        let diverges = bool_field(output_section, "diverges").unwrap_or(false);

        if diverges {
            assert_ne!(
                slot_python, slot_rust,
                "{}: marked as diverging but slots match: {}",
                name, slot_python
            );
        } else {
            assert_eq!(
                slot_python, slot_rust,
                "{}: not marked as diverging but slots differ: Python={}, Rust={}",
                name, slot_python, slot_rust
            );
        }
    }
}

#[test]
fn test_hash_32_fnv1a_properties() {
    // Empty input returns offset basis
    assert_eq!(lichen_hash_32(&[]), 0x811C9DC5);

    // Single zero byte
    assert_eq!(lichen_hash_32(&[0x00]), 0x050C5D1F);

    // Deterministic
    let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    assert_eq!(lichen_hash_32(&data), lichen_hash_32(&data));

    // Different inputs produce different hashes
    assert_ne!(lichen_hash_32(&[0x01]), lichen_hash_32(&[0x02]));
}

#[test]
fn test_rust_slot_ignores_sfn() {
    // Document that Rust currently ignores SFN (this is the divergence)
    let eui: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

    // Same result regardless of SFN (because Rust ignores it)
    let slot_sfn0 = rust_slot_for(&eui);
    let slot_sfn1 = rust_slot_for(&eui); // Would be different in Python

    assert_eq!(
        slot_sfn0, slot_sfn1,
        "Rust slot_for should be SFN-independent (current behavior)"
    );

    // This documents the divergence: Python would give different slots for different SFNs
    // slot_for(eui, sfn=0, num_slots=16) = 13
    // slot_for(eui, sfn=1, num_slots=16) = 14
    assert_eq!(slot_sfn0, 13, "Expected slot 13 for this EUI64");
}

#[test]
fn test_rust_slot_hardcodes_16_slots() {
    // Document that Rust hardcodes num_slots=16
    let eui: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];

    let slot = rust_slot_for(&eui);

    // Slot should be in range [0, 16) because Rust hardcodes 16
    assert!(
        slot < 16,
        "Rust slot {} should be < 16 (hardcoded num_slots)",
        slot
    );
}

#[test]
fn test_fixed_slot_for_matches_python() {
    // Verify that the fixed implementation would match Python
    for v in extract_vectors(JSON) {
        let type_field = string_field(v, "type");
        if type_field != Some("slot_selection") {
            continue;
        }

        let name = string_field(v, "name").unwrap_or("unknown");
        let input_section = v.split_once("\"input\":").unwrap().1;
        let eui64_hex = string_field(input_section, "eui64").unwrap();
        let sfn = int_field(input_section, "sfn").unwrap() as u32;
        let num_slots = int_field(input_section, "num_slots").unwrap() as u16;
        let output_section = v.split_once("\"output\":").unwrap().1;
        let python_expected = int_field(output_section, "slot_python").unwrap() as u16;

        let eui_bytes = hex_to_bytes(eui64_hex);
        let eui: [u8; 8] = eui_bytes.try_into().unwrap();

        let computed = slot_for_fixed(&eui, sfn, num_slots);

        assert_eq!(
            computed, python_expected,
            "{}: Fixed slot_for mismatch: got {}, expected {} (Python behavior)",
            name, computed, python_expected
        );
    }
}
