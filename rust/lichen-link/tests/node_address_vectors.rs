//! Tests against shared test vectors from test/vectors/node_address.json
//!
//! These vectors are the source of truth for cross-implementation compatibility.
//! If this test fails, the Rust implementation doesn't match the Python reference.

#![cfg(feature = "schnorr")]

use std::fs;
use std::path::Path;

use serde::Deserialize;

use lichen_link::identity::{human_address_from_pubkey, iid_from_pubkey};
use lichen_link::PublicKey;

#[derive(Deserialize)]
struct VectorFile {
    #[allow(dead_code)]
    description: String,
    vectors: Vec<NodeAddressVector>,
}

#[derive(Deserialize)]
struct NodeAddressVector {
    name: String,
    #[allow(dead_code)]
    seed: String,
    pubkey: String,
    iid: String,
    human_address: String,
    #[allow(dead_code)]
    description: String,
}

fn hex_decode_32(s: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    bytes
}

fn hex_decode_8(s: &str) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    for i in 0..8 {
        bytes[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    bytes
}

#[test]
fn test_node_address_vectors() {
    let vectors_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/node_address.json");

    assert!(
        vectors_path.exists(),
        "Vectors file not found at {:?}",
        vectors_path
    );

    let content = fs::read_to_string(&vectors_path).expect("Failed to read vectors file");
    let vf: VectorFile =
        serde_json::from_str(&content).expect("Failed to parse node_address.json");

    let mut failures = Vec::new();

    for vector in &vf.vectors {
        let pubkey = PublicKey::new(hex_decode_32(&vector.pubkey));
        let expected_iid = hex_decode_8(&vector.iid);

        let got_iid = iid_from_pubkey(&pubkey);
        let got_human = human_address_from_pubkey(&pubkey);

        let human_str = core::str::from_utf8(&got_human).unwrap();

        if got_iid != expected_iid {
            failures.push(format!(
                "{}: IID mismatch: got {:02x?}, expected {:02x?}",
                vector.name, got_iid, expected_iid
            ));
        }
        if human_str != vector.human_address {
            failures.push(format!(
                "{}: human_address mismatch: got {}, expected {}",
                vector.name, human_str, vector.human_address
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "Node address vector failures:\n{}",
        failures.join("\n")
    );
}
