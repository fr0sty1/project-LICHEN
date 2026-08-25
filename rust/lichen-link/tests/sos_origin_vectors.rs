//! Drive `test/vectors/sos_signature.json` origin-signature type pins.

use lichen_link::{SosOriginSignature, SOS_ORIGIN_DOMAIN, SOS_ORIGIN_SIGNATURE_LENGTH};
use serde_json::Value;

const JSON: &str = include_str!("../../../test/vectors/sos_signature.json");

fn doc() -> Value {
    serde_json::from_str(JSON).expect("sos_signature.json")
}

fn vector<'a>(doc: &'a Value, name: &str) -> &'a Value {
    doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("missing vector {name}"))
}

#[test]
fn origin_domain_separation() {
    let doc = doc();
    let v = vector(&doc, "origin_domain_separation");
    assert_eq!(SOS_ORIGIN_DOMAIN, v["domain"].as_str().unwrap().as_bytes());
    assert_eq!(
        SOS_ORIGIN_DOMAIN.len(),
        v["domain_length"].as_u64().unwrap() as usize
    );
    let hex = v["domain_hex"].as_str().unwrap();
    let decoded: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(SOS_ORIGIN_DOMAIN, decoded.as_slice());
    assert_ne!(
        v["domain"].as_str().unwrap(),
        v["different_from"].as_str().unwrap()
    );
}

#[test]
fn origin_wire_format() {
    let doc = doc();
    let v = vector(&doc, "origin_wire_format");
    let seq = v["origin_sequence"].as_u64().unwrap();
    let sig = SosOriginSignature::new(seq, [0x11; 48]);
    let bytes = sig.to_bytes();
    assert_eq!(bytes.len(), v["total_length"].as_u64().unwrap() as usize);
    assert_eq!(bytes.len(), SOS_ORIGIN_SIGNATURE_LENGTH);
    let seq_hex = v["sequence_hex"].as_str().unwrap();
    let expected_seq: Vec<u8> = (0..seq_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&seq_hex[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(&bytes[..8], expected_seq.as_slice());
    assert_eq!(
        sig.signature().len(),
        v["signature_length"].as_u64().unwrap() as usize
    );
    assert_eq!(
        SosOriginSignature::from_bytes(&bytes)
            .unwrap()
            .origin_sequence(),
        seq
    );
}
