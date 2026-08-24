// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_core::lichen_hash_32;
use lichen_core::sf_assignment::{assigned_sf_hash_based, SfAssignmentState};
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    format_version: u8,
    vectors: Vec<SfVector>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SfVector {
    name: String,
    iid_hex: String,
    hash_32: String,
    hash_sf: Option<u8>,
    assigned_sf: Option<u8>,
    assigned_sf_dio: Option<u8>,
    joined: Option<bool>,
    effective_sf: Option<u8>,
    #[serde(rename = "description")]
    _description: String,
    #[serde(rename = "formula")]
    _formula: String,
}

fn decode_iid(value: &str) -> [u8; 8] {
    assert_eq!(value.len(), 16, "IID vector must contain exactly 8 bytes");
    let mut iid = [0u8; 8];
    for (index, byte) in iid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .expect("IID vector must be hexadecimal");
    }
    iid
}

#[test]
fn canonical_sf_assignment_vectors() {
    let vectors: VectorFile =
        serde_json::from_str(include_str!("../../../test/vectors/sf_assignment.json"))
            .expect("canonical SF assignment vectors must parse");
    assert_eq!(vectors.format_version, 2);
    assert!(!vectors.vectors.is_empty());

    for vector in vectors.vectors {
        let iid = decode_iid(&vector.iid_hex);
        let expected_hash = u32::from_str_radix(
            vector
                .hash_32
                .strip_prefix("0x")
                .expect("hash vector must use a 0x prefix"),
            16,
        )
        .expect("hash vector must be hexadecimal");
        assert_eq!(lichen_hash_32(&iid), expected_hash, "{}", vector.name);

        if let Some(expected_sf) = vector.assigned_sf {
            assert_eq!(assigned_sf_hash_based(&iid), expected_sf, "{}", vector.name);
        }
        if let Some(expected_sf) = vector.hash_sf {
            assert_eq!(assigned_sf_hash_based(&iid), expected_sf, "{}", vector.name);
        }

        if vector.assigned_sf_dio.is_some() || vector.effective_sf.is_some() {
            let mut state = SfAssignmentState::new();
            if vector.joined.unwrap_or(vector.assigned_sf_dio.is_some()) {
                state.set_joined();
            }
            if let Some(sf) = vector.assigned_sf_dio {
                state
                    .set_assigned_sf(sf)
                    .expect("canonical DIO assignment must be valid");
            }
            assert_eq!(
                Some(state.effective_sf(&iid)),
                vector.effective_sf,
                "{}",
                vector.name
            );
        }
    }
}
