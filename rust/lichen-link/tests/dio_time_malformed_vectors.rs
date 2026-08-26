// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Malformed DIO Time Option vectors: decode errors, no panic.

use lichen_link::DioTimeOption;
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/dio_time_option_malformed.json");

fn hex_decode(s: &str) -> Vec<u8> {
    if s.is_empty() {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn malformed_dio_time_options_are_rejected() {
    let document: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    for case in document["vectors"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let bytes = hex_decode(case["hex"].as_str().unwrap());
        let expected = case["expected"].as_str().unwrap();
        let err = DioTimeOption::decode(&bytes).expect_err(name);
        assert_eq!(err.as_str(), expected, "{name}");
    }
}
