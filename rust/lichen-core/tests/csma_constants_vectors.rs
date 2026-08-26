// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_core::constants::{
    CSMA_BACKOFF_MAX, CSMA_BACKOFF_UNIT_MS, CSMA_CAD_TIMEOUT_SYMBOLS, CSMA_RETRY_LIMIT,
};
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/packets-timing.json");

#[test]
fn csma_constants_match_canonical_timing_vector() {
    let document: Value =
        serde_json::from_str(VECTORS_JSON).expect("packets-timing vectors must parse");
    let vector = document["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .find(|vector| vector["category"] == "csma_params")
        .expect("CSMA parameter vector");

    assert_eq!(
        u64::from(CSMA_CAD_TIMEOUT_SYMBOLS),
        vector["cad_timeout_symbols"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(CSMA_BACKOFF_UNIT_MS),
        vector["backoff_unit_ms"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(CSMA_BACKOFF_MAX),
        vector["backoff_max"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(CSMA_RETRY_LIMIT),
        vector["retry_limit"].as_u64().unwrap()
    );
}
