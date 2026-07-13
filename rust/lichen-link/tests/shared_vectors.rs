//! Tests against shared test vectors from test/vectors/link_frame.json
//!
//! These vectors are the source of truth for cross-implementation compatibility.
//! If this test fails, the Rust implementation doesn't match the Python reference.

use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<LinkFrameVector>,
}

#[derive(Deserialize)]
struct LinkFrameVector {
    name: String,
    encoded: String,  // hex-encoded frame
    fields: LinkFrameFields,
}

#[derive(Deserialize)]
struct LinkFrameFields {
    length: u8,
    llsec: u8,
    epoch: u8,
    seqnum: u16,
    addr_mode: u8,
    dest_addr: Option<String>,
    payload: String,
    mic: String,
}

fn hex_decode(s: &str) -> Vec<u8> {
    if s.is_empty() {
        return vec![];
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_link_frame_vectors() {
    let vectors_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/vectors/link_frame.json");

    if !vectors_path.exists() {
        eprintln!("Vectors file not found at {:?}, skipping", vectors_path);
        return;
    }

    let content = fs::read_to_string(&vectors_path)
        .expect("Failed to read vectors file");
    let vectors: VectorFile = serde_json::from_str(&content)
        .expect("Failed to parse vectors JSON");

    for vector in &vectors.vectors {
        let encoded = hex_decode(&vector.encoded);
        let fields = &vector.fields;

        // Verify wire format structure
        assert!(encoded.len() >= 5, "Vector '{}': frame too short", vector.name);

        // Check header fields match
        assert_eq!(encoded[0], fields.length, "Vector '{}': length mismatch", vector.name);
        assert_eq!(encoded[1], fields.llsec, "Vector '{}': llsec mismatch", vector.name);
        assert_eq!(encoded[2], fields.epoch, "Vector '{}': epoch mismatch", vector.name);

        let seqnum = u16::from_be_bytes([encoded[3], encoded[4]]);
        assert_eq!(seqnum, fields.seqnum, "Vector '{}': seqnum mismatch", vector.name);

        // Verify addr_mode from llsec byte
        let addr_mode = fields.llsec & 0x03;
        assert_eq!(addr_mode, fields.addr_mode, "Vector '{}': addr_mode mismatch", vector.name);

        println!("Vector '{}': {} bytes, epoch={}, seqnum={}, addr_mode={}",
            vector.name, encoded.len(), fields.epoch, fields.seqnum, fields.addr_mode);
    }

    println!("Validated {} link frame vectors", vectors.vectors.len());
}

#[test]
fn test_l2_payload_vectors() {
    let vectors_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/vectors/l2_payload.json");

    if !vectors_path.exists() {
        eprintln!("Vectors file not found at {:?}, skipping", vectors_path);
        return;
    }

    let content = fs::read_to_string(&vectors_path)
        .expect("Failed to read vectors file");

    #[derive(Deserialize)]
    struct L2PayloadFile {
        vectors: Vec<L2PayloadVector>,
    }

    #[derive(Deserialize)]
    struct L2PayloadVector {
        name: String,
        wrapped: String,
        dispatch: u8,
        kind: String,
        body: String,
    }

    let vectors: L2PayloadFile = serde_json::from_str(&content)
        .expect("Failed to parse vectors JSON");

    for vector in &vectors.vectors {
        let wrapped = hex_decode(&vector.wrapped);
        let body = hex_decode(&vector.body);

        // First byte must be dispatch
        assert!(!wrapped.is_empty(), "Vector '{}': empty wrapped", vector.name);
        assert_eq!(wrapped[0], vector.dispatch,
            "Vector '{}': dispatch mismatch (expected {:#x}, got {:#x})",
            vector.name, vector.dispatch, wrapped[0]);

        // Body should match remaining bytes
        assert_eq!(&wrapped[1..], &body[..],
            "Vector '{}': body mismatch", vector.name);

        // Verify dispatch matches kind
        let expected_dispatch = match vector.kind.as_str() {
            "schc" => 0x14,
            "routing" => 0x15,
            _ => panic!("Unknown kind: {}", vector.kind),
        };
        assert_eq!(vector.dispatch, expected_dispatch,
            "Vector '{}': kind/dispatch mismatch", vector.name);

        println!("Vector '{}': {} bytes, kind={}, dispatch={:#x}",
            vector.name, wrapped.len(), vector.kind, vector.dispatch);
    }

    println!("Validated {} L2 payload vectors", vectors.vectors.len());
}
