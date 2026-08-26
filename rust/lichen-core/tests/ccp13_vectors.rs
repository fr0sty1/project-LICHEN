// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_core::duty_cycle::adaptive_duty_permille;
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/ccp13.json");

#[derive(Deserialize)]
struct Document {
    format_version: u8,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    density: Option<u8>,
    region: Option<u8>,
    expected_duty_permille: Option<u16>,
}

#[test]
fn adaptive_regional_limits_match_ccp13_vectors() {
    let document: Document = serde_json::from_str(VECTORS_JSON).expect("valid CCP-13 vectors");
    assert_eq!(document.format_version, 2);

    let mut checked = 0;
    for vector in document.vectors {
        let (Some(density), Some(region), Some(expected)) =
            (vector.density, vector.region, vector.expected_duty_permille)
        else {
            continue;
        };

        assert_eq!(
            adaptive_duty_permille(density, region),
            expected,
            "{}",
            vector.name
        );
        checked += 1;
    }

    assert_eq!(
        checked, 10,
        "all canonical adaptive vectors must be consumed"
    );
}
