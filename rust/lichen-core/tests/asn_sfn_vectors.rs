// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_core::sfn_from_unix_time;
use serde::Deserialize;

const VECTORS: &str = include_str!("../../../test/vectors/asn_sfn_derivation.json");

#[derive(Debug, Deserialize)]
struct Document {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    input: Input,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Input {
    unix_time_us: u64,
    epoch_base_us: u64,
    interval_duration_us: u64,
}

#[derive(Debug, Deserialize)]
struct Expected {
    asn_u64: u64,
    sfn_u32: u32,
    clamped: bool,
}

#[test]
fn production_sfn_derivation_matches_all_shared_vectors() {
    let document: Document = serde_json::from_str(VECTORS).expect("valid ASN/SFN vectors");

    for vector in document.vectors {
        let actual = sfn_from_unix_time(
            vector.input.unix_time_us,
            vector.input.interval_duration_us,
            vector.input.epoch_base_us,
        );
        assert_eq!(actual, vector.expected.sfn_u32, "{}", vector.name);
        assert_eq!(
            vector.expected.asn_u64 as u32, vector.expected.sfn_u32,
            "{} has inconsistent ASN/SFN projections",
            vector.name
        );
        assert_eq!(
            vector.expected.clamped,
            vector.input.interval_duration_us == 0
                || vector.input.unix_time_us < vector.input.epoch_base_us,
            "{} has inconsistent clamp metadata",
            vector.name
        );
    }
}
