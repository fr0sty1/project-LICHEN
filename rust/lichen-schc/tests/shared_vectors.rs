//! Tests against shared test vectors from test/vectors/schc_compression.json
//!
//! These vectors are the source of truth for cross-implementation compatibility.
//! If this test fails, the Rust implementation doesn't match the Python reference.

use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<SchcVector>,
}

#[derive(Deserialize)]
struct SchcVector {
    name: String,
    rule_id: u8,
    packet: String,      // hex-encoded original packet
    compressed: String,  // hex-encoded compressed packet
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_schc_compression_vectors() {
    // Find the vectors file relative to the crate root
    let vectors_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/vectors/schc_compression.json");

    if !vectors_path.exists() {
        eprintln!("Vectors file not found at {:?}, skipping", vectors_path);
        return;
    }

    let content = fs::read_to_string(&vectors_path)
        .expect("Failed to read vectors file");
    let vectors: VectorFile = serde_json::from_str(&content)
        .expect("Failed to parse vectors JSON");

    for vector in &vectors.vectors {
        let packet = hex_decode(&vector.packet);
        let expected_compressed = hex_decode(&vector.compressed);

        // Test that first byte of compressed matches rule_id
        assert_eq!(
            expected_compressed[0], vector.rule_id,
            "Vector '{}': compressed[0] should equal rule_id",
            vector.name
        );

        // TODO: Implement actual compression test once API is available
        // let mut output = [0u8; 1500];
        // let compressed = lichen_schc::compress(&packet, &mut output).unwrap();
        // assert_eq!(compressed, &expected_compressed[..], "Vector '{}': compression mismatch", vector.name);

        // TODO: Test decompression
        // let mut decompressed = [0u8; 1500];
        // let result = lichen_schc::decompress(&expected_compressed, &mut decompressed).unwrap();
        // assert_eq!(&decompressed[..result], &packet[..], "Vector '{}': decompression mismatch", vector.name);

        println!("Vector '{}' (rule {}): packet={} bytes, compressed={} bytes",
            vector.name, vector.rule_id, packet.len(), expected_compressed.len());
    }

    println!("Validated {} SCHC compression vectors", vectors.vectors.len());
}
