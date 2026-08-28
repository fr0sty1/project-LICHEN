// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Shared transport vectors: RFC 7252 messages and RFC 7959 Block options.

use lichen_coap::block::BlockOption;
use lichen_coap::codec::CoapPacket;
use lichen_coap::option::content_format;
use lichen_coap::option::OptionNumber;
use lichen_coap::CoapError;
use serde_json::Value;

const COAP_MESSAGES: &str = include_str!("../../../test/vectors/coap_messages.json");
const COAP_BLOCK: &str = include_str!("../../../test/vectors/coap_block.json");

fn hex_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd-length hex {}", hex);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

fn mtype_u8(pkt: &CoapPacket<'_>) -> u8 {
    match pkt.msg_type() {
        lichen_coap::MessageType::Confirmable => 0,
        lichen_coap::MessageType::NonConfirmable => 1,
        lichen_coap::MessageType::Acknowledgement => 2,
        lichen_coap::MessageType::Reset => 3,
    }
}

#[test]
fn coap_messages_wire_vectors_parse() {
    let document: Value = serde_json::from_str(COAP_MESSAGES).unwrap();
    assert_eq!(document["format_version"].as_u64(), Some(2));
    let mut parsed = 0u8;
    for vector in document["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        if name == "content_format_table" {
            for format in vector["formats"].as_array().unwrap() {
                let value = format["value"].as_u64().unwrap() as u16;
                let media = format["media_type"].as_str().unwrap();
                let expected = match value {
                    0 => content_format::TEXT_PLAIN,
                    60 => content_format::CBOR,
                    110 => content_format::APPLICATION_SENML_JSON,
                    112 => content_format::SENML_CBOR,
                    11542 => content_format::OCF_CBOR,
                    other => panic!("unexpected content-format {other}"),
                };
                assert_eq!(expected, value, "{media}");
            }
            continue;
        }
        let Some(encoded_hex) = vector["encoded"].as_str() else {
            continue;
        };
        let encoded = hex_bytes(encoded_hex);
        let pkt = CoapPacket::from_bytes(&encoded).unwrap_or_else(|e| {
            panic!("{name}: parse {e}");
        });
        if let Some(mtype) = vector["mtype"].as_u64() {
            assert_eq!(mtype_u8(&pkt) as u64, mtype, "{name} mtype");
        }
        if let Some(decoded_code) = vector["decoded_code"].as_u64() {
            assert_eq!(pkt.code().0 as u64, decoded_code, "{name} decoded_code");
        }
        if let Some(mid) = vector["mid"].as_u64() {
            assert_eq!(pkt.message_id() as u64, mid, "{name} mid");
        }
        if let Some(token) = vector["token"].as_str() {
            assert_eq!(pkt.token(), hex_bytes(token), "{name} token");
        }
        parsed += 1;
    }
    assert!(parsed >= 4, "expected the four wire messages, got {parsed}");
}

#[test]
fn coap_block_option_values_match_shared_vectors() {
    let document: Value = serde_json::from_str(COAP_BLOCK).unwrap();
    assert_eq!(document["format_version"].as_u64(), Some(2));
    let mut accepted = 0u8;
    let mut rejected = 0u8;
    for vector in document["vectors"].as_array().unwrap() {
        if vector["kind"].as_str() != Some("option_value") {
            continue;
        }
        let name = vector["name"].as_str().unwrap();
        let encoded = hex_bytes(vector["encoded_hex"].as_str().unwrap());
        let expected = vector["expected"].as_str().unwrap();
        match expected {
            "accept" => {
                let parsed =
                    BlockOption::from_bytes(&encoded).unwrap_or_else(|e| panic!("{name}: {e:?}"));
                assert_eq!(parsed.num, vector["num"].as_u64().unwrap() as u32, "{name}");
                assert_eq!(parsed.more, vector["more"].as_bool().unwrap(), "{name}");
                assert_eq!(parsed.szx, vector["szx"].as_u64().unwrap() as u8, "{name}");
                assert_eq!(
                    parsed.size(),
                    vector["size"].as_u64().unwrap() as usize,
                    "{name}"
                );
                let mut buf = [0u8; 3];
                let len = parsed.write_to(&mut buf).unwrap();
                assert_eq!(&buf[..len], encoded.as_slice(), "{name} encode");
                accepted += 1;
            }
            "reject" => {
                assert_eq!(
                    BlockOption::from_bytes(&encoded),
                    Err(CoapError::InvalidBlockOption),
                    "{name}"
                );
                rejected += 1;
            }
            other => panic!("{name}: bad expected {other}"),
        }
    }
    assert!(accepted >= 10, "accepted={accepted}");
    assert_eq!(rejected, 3, "rejected={rejected}");
}

#[test]
fn coap_block_messages_parse_block_options() {
    let document: Value = serde_json::from_str(COAP_BLOCK).unwrap();
    let mut seen = 0u8;
    for vector in document["vectors"].as_array().unwrap() {
        if vector["kind"].as_str() != Some("coap_message") {
            continue;
        }
        let name = vector["name"].as_str().unwrap();
        let encoded = hex_bytes(vector["encoded"].as_str().unwrap());
        let pkt = CoapPacket::from_bytes(&encoded).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            mtype_u8(&pkt) as u64,
            vector["mtype"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            pkt.code().0 as u64,
            vector["code"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            pkt.message_id() as u64,
            vector["mid"].as_u64().unwrap(),
            "{name}"
        );
        if let Some(payload_hex) = vector["payload_hex"].as_str() {
            assert_eq!(pkt.payload(), hex_bytes(payload_hex), "{name} payload");
        }
        let mut paths: Vec<Vec<u8>> = Vec::new();
        let mut block1 = None;
        let mut block2 = None;
        for option in pkt.options() {
            let option = option.unwrap_or_else(|e| panic!("{name} option: {e}"));
            if option.number == OptionNumber::UriPath as u16 {
                paths.push(option.value.to_vec());
            } else if option.is_block1() {
                block1 = Some(option.as_block().unwrap());
            } else if option.is_block2() {
                block2 = Some(option.as_block().unwrap());
            }
        }
        if let Some(expected_paths) = vector["uri_path"].as_array() {
            let got: Vec<String> = paths
                .iter()
                .map(|p| String::from_utf8(p.clone()).unwrap())
                .collect();
            let want: Vec<String> = expected_paths
                .iter()
                .map(|p| p.as_str().unwrap().to_string())
                .collect();
            assert_eq!(got, want, "{name} uri-path");
        }
        if let Some(expected) = vector.get("block1") {
            let block = block1.unwrap_or_else(|| panic!("{name} missing Block1"));
            assert_eq!(block.num, expected["num"].as_u64().unwrap() as u32);
            assert_eq!(block.more, expected["more"].as_bool().unwrap());
            assert_eq!(block.szx, expected["szx"].as_u64().unwrap() as u8);
        }
        if let Some(expected) = vector.get("block2") {
            let block = block2.unwrap_or_else(|| panic!("{name} missing Block2"));
            assert_eq!(block.num, expected["num"].as_u64().unwrap() as u32);
            assert_eq!(block.more, expected["more"].as_bool().unwrap());
            assert_eq!(block.szx, expected["szx"].as_u64().unwrap() as u8);
        }
        seen += 1;
    }
    assert_eq!(seen, 3);
}
