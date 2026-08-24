// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Test CCP slot_map validation against test vectors.
//!
//! Validates slot_map CBOR array per spec/02a-coordinated-capacity.md:80:
//! - Each entry must be < num_slots
//! - Array must be sorted ascending
//! - Duplicates are rejected (sorted-unique invariant)
//! - Empty array is valid (no TX slots)

const JSON: &str = include_str!("../../../test/vectors/ccp_slot_map_validation.json");

#[derive(Debug, PartialEq, Eq)]
enum SlotMapError {
    SlotOutOfBounds,
    Unsorted,
    Duplicate,
}

/// Validate a slot_map array per CCP spec.
///
/// # Arguments
/// * `slot_map` - Slice of u8 slot indices
/// * `num_slots` - Maximum number of slots (entries must be < num_slots)
///
/// # Returns
/// Ok(()) if valid, Err with error type otherwise
fn validate_slot_map(slot_map: &[u8], num_slots: u16) -> Result<(), SlotMapError> {
    if slot_map.is_empty() {
        return Ok(());
    }

    let mut prev: Option<u8> = None;

    for &slot in slot_map {
        // Each slot must be < num_slots
        if u16::from(slot) >= num_slots {
            return Err(SlotMapError::SlotOutOfBounds);
        }

        if let Some(p) = prev {
            // Must be strictly ascending (sorted and no duplicates)
            if slot < p {
                return Err(SlotMapError::Unsorted);
            }
            if slot == p {
                return Err(SlotMapError::Duplicate);
            }
        }

        prev = Some(slot);
    }

    Ok(())
}

fn error_to_string(err: &SlotMapError) -> &'static str {
    match err {
        SlotMapError::SlotOutOfBounds => "slot_out_of_bounds",
        SlotMapError::Unsorted => "unsorted",
        SlotMapError::Duplicate => "duplicate",
    }
}

/// Extract string field value from JSON object text
fn string_field<'a>(object: &'a str, name: &str) -> Option<&'a str> {
    object
        .split_once(&format!("\"{name}\": \""))
        .map(|(_, rest)| rest.split_once('"').unwrap().0)
}

/// Extract integer field value from JSON object text
fn int_field(object: &str, name: &str) -> Option<u16> {
    object
        .split_once(&format!("\"{name}\": "))
        .map(|(_, rest)| {
            let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            num_str.parse().unwrap()
        })
}

/// Extract boolean field value from JSON object text
fn bool_field(object: &str, name: &str) -> Option<bool> {
    object
        .split_once(&format!("\"{name}\": "))
        .map(|(_, rest)| rest.starts_with("true"))
}

/// Parse slot_map array from JSON: "slot_map": [0, 1, 7]
fn slot_map_field(object: &str) -> Vec<u8> {
    let Some((_, rest)) = object.split_once("\"slot_map\": [") else {
        return Vec::new();
    };
    let Some((array_content, _)) = rest.split_once(']') else {
        return Vec::new();
    };
    array_content
        .split(',')
        .filter_map(|s| s.trim().parse::<u8>().ok())
        .collect()
}

/// Iterator over vector objects in the JSON file
fn vectors() -> impl Iterator<Item = &'static str> {
    JSON.split("    {\n      \"name\": \"").skip(1).map(|tail| {
        tail.split_once("\n    }")
            .map_or(tail, |(vector, _)| vector)
    })
}

#[test]
fn test_vectors_file_parses() {
    let count = vectors().count();
    assert!(count >= 10, "expected at least 10 vectors, got {}", count);
}

#[test]
fn test_slot_map_validation_all_vectors() {
    let mut count = 0;
    let mut failures = Vec::new();

    for vector in vectors() {
        count += 1;
        let name = vector.split_once('"').unwrap().0;
        let num_slots = int_field(vector, "num_slots").expect("missing num_slots");
        let slot_map = slot_map_field(vector);
        let expected_valid = bool_field(vector, "expected_valid").expect("missing expected_valid");
        let expected_error = string_field(vector, "expected_error");

        let result = validate_slot_map(&slot_map, num_slots);

        match result {
            Ok(()) => {
                if !expected_valid {
                    failures.push(format!("{}: expected invalid but got valid", name));
                }
            }
            Err(ref err) => {
                if expected_valid {
                    failures.push(format!("{}: expected valid but got error {:?}", name, err));
                } else if let Some(expected) = expected_error {
                    let actual = error_to_string(err);
                    if actual != expected {
                        failures.push(format!(
                            "{}: expected error '{}' but got '{}'",
                            name, expected, actual
                        ));
                    }
                }
            }
        }
    }

    assert!(count >= 10, "expected at least 10 vectors, got {}", count);

    if !failures.is_empty() {
        panic!(
            "{} of {} vectors failed:\n{}",
            failures.len(),
            count,
            failures.join("\n")
        );
    }
}

#[test]
fn test_slot_out_of_bounds_specific() {
    let result = validate_slot_map(&[0, 3, 8, 12], 8);
    assert_eq!(result, Err(SlotMapError::SlotOutOfBounds));
}

#[test]
fn test_slot_unsorted_specific() {
    let result = validate_slot_map(&[3, 1, 5, 2], 16);
    assert_eq!(result, Err(SlotMapError::Unsorted));
}

#[test]
fn test_slot_duplicate_specific() {
    let result = validate_slot_map(&[1, 1, 3], 8);
    assert_eq!(result, Err(SlotMapError::Duplicate));
}

#[test]
fn test_slot_empty_valid() {
    let result = validate_slot_map(&[], 8);
    assert_eq!(result, Ok(()));
}

#[test]
fn test_slot_boundary_max() {
    // Slot at num_slots-1 is valid
    let result = validate_slot_map(&[7], 8);
    assert_eq!(result, Ok(()));

    // Slot at num_slots is not
    let result = validate_slot_map(&[8], 8);
    assert_eq!(result, Err(SlotMapError::SlotOutOfBounds));
}

#[test]
fn test_all_slots_valid() {
    // All slots 0-7 valid for num_slots=8
    let result = validate_slot_map(&[0, 1, 2, 3, 4, 5, 6, 7], 8);
    assert_eq!(result, Ok(()));
}

#[test]
fn test_zero_num_slots() {
    // With num_slots=0, any slot is out of bounds
    let result = validate_slot_map(&[0], 0);
    assert_eq!(result, Err(SlotMapError::SlotOutOfBounds));
}

#[test]
fn test_descending_order() {
    // Descending order should fail with unsorted
    let result = validate_slot_map(&[7, 5, 3, 1], 8);
    assert_eq!(result, Err(SlotMapError::Unsorted));
}
