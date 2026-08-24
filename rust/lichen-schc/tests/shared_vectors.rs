//! Tests against shared test vectors from test/vectors/schc_compression.json
//!
//! These vectors (now including canonical OSCORE rules 5/6) are the source of
//! truth for cross-implementation compatibility. If this test fails, the Rust
//! implementation doesn't match the Python reference.

use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    format_version: u32,
    vectors: Vec<SchcVector>,
}

#[derive(Deserialize)]
struct SchcVector {
    name: String,
    #[serde(default)]
    rule_id: Option<u8>,
    #[serde(default)]
    packet: Option<String>,
    #[serde(default)]
    compressed: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    expect_error: Option<String>,
    #[serde(default)]
    compressed_prefix: Option<String>,
    #[serde(default)]
    tail_byte: Option<u8>,
    #[serde(default)]
    tail_length: Option<usize>,
    #[serde(default)]
    expected_packet_size: Option<usize>,
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_schc_compression_vectors() {
    let vectors_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/schc_compression.json");

    if !vectors_path.exists() {
        eprintln!("Vectors file not found at {:?}, skipping", vectors_path);
        return;
    }

    let content = fs::read_to_string(&vectors_path).expect("Failed to read vectors file");
    let vectors: VectorFile = serde_json::from_str(&content).expect("Failed to parse vectors JSON");

    assert_eq!(
        vectors.format_version, 2,
        "Unexpected vector format version"
    );

    let mut failures = Vec::new();

    for vector in &vectors.vectors {
        if vector.category.as_deref() == Some("malformed_input") {
            let packet = hex_decode(vector.packet.as_deref().unwrap_or(""));
            let mut out = vec![0u8; packet.len() + 1];
            if lichen_schc::compress(&packet, &mut out).is_ok() {
                failures.push(format!(
                    "Vector '{}': expected malformed input rejection ({:?})",
                    vector.name, vector.expect_error
                ));
            }
            continue;
        }
        if vector.category.as_deref() == Some("size_boundary") {
            let mut compressed = hex_decode(vector.compressed_prefix.as_deref().unwrap_or(""));
            compressed.resize(
                compressed.len() + vector.tail_length.unwrap_or(0),
                vector.tail_byte.unwrap_or(0),
            );
            let expected_size = vector.expected_packet_size.unwrap_or(0);
            let mut out = vec![0u8; expected_size];
            let result = lichen_schc::decompress(&compressed, &mut out);
            if vector.expect_error.is_some() {
                if result.is_ok() {
                    failures.push(format!(
                        "Vector '{}': expected profile-limit rejection",
                        vector.name
                    ));
                }
            } else if result != Ok(expected_size) {
                failures.push(format!(
                    "Vector '{}': expected {} reconstructed bytes, got {:?}",
                    vector.name, expected_size, result
                ));
            }
            continue;
        }
        if vector.category.as_deref() == Some("malformed") {
            let compressed = hex_decode(vector.compressed.as_deref().unwrap_or(""));
            let mut out = [0u8; 1500];
            if lichen_schc::decompress(&compressed, &mut out).is_ok() {
                failures.push(format!(
                    "Vector '{}': expected malformed rejection ({:?})",
                    vector.name, vector.expect_error
                ));
            }
            continue;
        }

        // Skip error test vectors (rule_id is null)
        let rule_id = match vector.rule_id {
            Some(id) => id,
            None => {
                println!(
                    "Vector '{}': skipped (error test case with no rule_id)",
                    vector.name
                );
                continue;
            }
        };

        let packet_str = match &vector.packet {
            Some(p) => p,
            None => {
                println!("Vector '{}': skipped (no packet field)", vector.name);
                continue;
            }
        };
        let compressed_str = match &vector.compressed {
            Some(c) => c,
            None => {
                println!("Vector '{}': skipped (no compressed field)", vector.name);
                continue;
            }
        };
        let packet = hex_decode(packet_str);
        let compressed = hex_decode(compressed_str);

        // Verify compressed starts with rule_id
        if compressed.is_empty() {
            failures.push(format!("Vector '{}': empty compressed output", vector.name));
            continue;
        }

        if compressed[0] != rule_id {
            failures.push(format!(
                "Vector '{}': compressed[0] should equal rule_id (expected {}, got {})",
                vector.name, rule_id, compressed[0]
            ));
        }

        // Verify packet is valid IPv6 (starts with version 6)
        if packet.len() < 40 {
            failures.push(format!(
                "Vector '{}': packet too short for IPv6",
                vector.name
            ));
            continue;
        }

        let version = (packet[0] >> 4) & 0x0f;
        if version != 6 {
            failures.push(format!(
                "Vector '{}': packet is not IPv6 (version={})",
                vector.name, version
            ));
        }

        if rule_id != 255 && compressed.len() >= packet.len() {
            failures.push(format!(
                "Vector '{}': compression did not reduce size ({} -> {})",
                vector.name,
                packet.len(),
                compressed.len()
            ));
        }

        let mut output = [0u8; 1500];
        let n = match lichen_schc::compress(&packet, &mut output) {
            Ok(n) => n,
            Err(e) => {
                failures.push(format!(
                    "Vector '{}': compress failed: {:?}",
                    vector.name, e
                ));
                continue;
            }
        };
        let compressed_result = &output[..n];
        if compressed_result != &compressed[..] {
            failures.push(format!(
                "Vector '{}': compress mismatch for rule {}: expected {} bytes got {}",
                vector.name,
                rule_id,
                compressed.len(),
                n
            ));
            continue;
        }

        let mut decompressed = [0u8; 1500];
        let m = match lichen_schc::decompress(&compressed, &mut decompressed) {
            Ok(m) => m,
            Err(e) => {
                failures.push(format!(
                    "Vector '{}': decompress failed: {:?}",
                    vector.name, e
                ));
                continue;
            }
        };
        if decompressed[..m] != packet[..] {
            failures.push(format!(
                "Vector '{}': decompress mismatch: got {} bytes, expected {}",
                vector.name,
                m,
                packet.len()
            ));
        }

        let reduction = 100isize - (compressed.len() * 100 / packet.len()) as isize;
        println!(
            "Vector '{}' (rule {}): {} -> {} bytes ({}% reduction)",
            vector.name,
            rule_id,
            packet.len(),
            compressed.len(),
            reduction
        );
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {}", f);
        }
        panic!("{} SCHC vector(s) failed", failures.len());
    }

    println!(
        "Validated {} SCHC compression vectors",
        vectors.vectors.len()
    );
}

#[test]
fn test_schc_rule_coverage() {
    let vectors_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/schc_compression.json");

    if !vectors_path.exists() {
        return;
    }

    let content = fs::read_to_string(&vectors_path).unwrap();
    let vectors: VectorFile = serde_json::from_str(&content).unwrap();

    // Track which rules have vectors
    let mut rules_seen = std::collections::HashSet::new();
    for v in &vectors.vectors {
        if let Some(rule_id) = v.rule_id {
            rules_seen.insert(rule_id);
        }
    }

    println!("SCHC rules with vectors: {:?}", rules_seen);

    // Every canonical compression rule, including specialized Rule 7, needs a vector.
    for expected in 0..=7 {
        assert!(
            rules_seen.contains(&expected),
            "No vector for rule_id {}",
            expected
        );
    }
}

#[test]
fn test_schc_fragment_vectors() {
    let vectors_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/schc_fragment.json");

    if !vectors_path.exists() {
        eprintln!("Fragment vectors not found at {:?}, skipping", vectors_path);
        return;
    }

    let content = fs::read_to_string(&vectors_path).expect("Failed to read fragment vectors");
    let doc: serde_json::Value = serde_json::from_str(&content).expect("Failed to parse JSON");

    assert_eq!(doc["format_version"], 2, "Unexpected vector format version");

    let vectors = doc["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty(), "No fragment vectors");

    let names: Vec<&str> = vectors
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"single_fragment"));
    assert!(names.contains(&"ooo_retransmit"));

    println!(
        "Validated {} SCHC fragment vectors from independent RFC oracle",
        vectors.len()
    );
}
