// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Shared-vector tests for RFC 1055 SLIP framing.

use lichen_kiss::slip::{decode, encode, Error, LCI_MAX_DATA_SIZE, LCI_MAX_FRAME_SIZE};
use serde_json::Value;

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("hex must be ASCII"), 16)
                .expect("vector must contain valid hex")
        })
        .collect()
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../test/vectors/slip_framing.json"))
        .expect("SLIP vectors must be valid JSON")
}

#[test]
fn shared_encode_vectors_match_exact_bytes() {
    let document = vectors();
    assert_eq!(document["format_version"], 2);

    for vector in document["vectors"].as_array().unwrap() {
        let (Some(data), Some(framed)) = (
            vector["data"].as_str(),
            vector["expected"]["framed"].as_str(),
        ) else {
            continue;
        };

        let data = hex(data);
        let expected = hex(framed);
        let mut output = vec![0xA5; expected.len()];
        let length = encode(&data, &mut output).unwrap();
        assert_eq!(&output[..length], expected, "{}", vector["name"]);
    }
}

#[test]
fn shared_decode_vectors_match_or_reject() {
    let document = vectors();

    for vector in document["vectors"].as_array().unwrap() {
        let Some(framed) = vector["framed"].as_str() else {
            continue;
        };
        let Some(valid) = vector["expected"]["valid"].as_bool() else {
            continue;
        };

        let frame = hex(framed);
        let mut output = vec![0xA5; frame.len()];
        let result = decode(&frame, &mut output);
        if valid {
            let expected = hex(vector["expected"]["data"].as_str().unwrap_or(""));
            let length = result.unwrap();
            assert_eq!(&output[..length], expected, "{}", vector["name"]);
        } else {
            let error = result.expect_err("invalid vector must be rejected");
            match vector["expected"]["reason"].as_str().unwrap() {
                "invalid_escape_sequence" => {
                    assert!(matches!(error, Error::InvalidEscape(_)), "{error:?}")
                }
                "truncated_escape" => assert_eq!(error, Error::TruncatedEscape),
                reason => panic!("unhandled invalid-vector reason {reason}"),
            }
        }
    }
}

#[test]
fn shared_maximum_size_vector_matches_constants_and_encoding() {
    let document = vectors();
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == "slip_max_frame_size")
        .unwrap();

    assert_eq!(vector["max_data_size"], LCI_MAX_DATA_SIZE);
    assert_eq!(vector["expected"]["max_framed_size"], LCI_MAX_FRAME_SIZE);

    let data = vec![0xC0; LCI_MAX_DATA_SIZE];
    let mut frame = vec![0; LCI_MAX_FRAME_SIZE];
    assert_eq!(encode(&data, &mut frame), Ok(LCI_MAX_FRAME_SIZE));

    let mut decoded = vec![0; LCI_MAX_DATA_SIZE];
    assert_eq!(decode(&frame, &mut decoded), Ok(LCI_MAX_DATA_SIZE));
    assert_eq!(decoded, data);
}

#[test]
fn output_buffers_are_not_modified_on_error() {
    let mut output = [0xA5; 2];
    assert_eq!(
        encode(b"x", &mut output),
        Err(Error::BufferTooSmall { needed: 3 })
    );
    assert_eq!(output, [0xA5; 2]);

    let mut output = [0xA5; 4];
    assert_eq!(
        decode(&[0xC0, 0x01, 0xDB, 0x01, 0xC0], &mut output),
        Err(Error::InvalidEscape(0x01))
    );
    assert_eq!(output, [0xA5; 4]);
}
