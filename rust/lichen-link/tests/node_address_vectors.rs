//! Tests against shared test vectors from test/vectors/node_address.json
//!
//! These vectors are the source of truth for cross-implementation compatibility.
//! All implementations (Rust, C, Python) must produce identical output.

#[cfg(feature = "schnorr")]
mod node_address_tests {
    use std::fs;
    use std::path::Path;

    use serde::Deserialize;

    use lichen_link::identity::{human_address_from_pubkey, iid_from_pubkey};
    use lichen_link::PublicKey;

    #[derive(Deserialize)]
    struct VectorFile {
        vectors: Vec<NodeAddressVector>,
    }

    #[derive(Deserialize)]
    struct NodeAddressVector {
        name: String,
        pubkey: String,
        iid: String,
        human_address: String,
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
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
        let vectors: VectorFile =
            serde_json::from_str(&content).expect("Failed to parse vectors JSON");

        let mut failures = Vec::new();

        for vector in &vectors.vectors {
            let pubkey_bytes: [u8; 32] = match hex_decode(&vector.pubkey).try_into() {
                Ok(b) => b,
                Err(_) => {
                    failures.push(format!(
                        "Vector '{}': pubkey not 32 bytes",
                        vector.name
                    ));
                    continue;
                }
            };
            let expected_iid: [u8; 8] = match hex_decode(&vector.iid).try_into() {
                Ok(b) => b,
                Err(_) => {
                    failures.push(format!(
                        "Vector '{}': iid not 8 bytes",
                        vector.name
                    ));
                    continue;
                }
            };
            let expected_human = vector.human_address.as_bytes();

            let pubkey = PublicKey::new(pubkey_bytes);
            let iid = iid_from_pubkey(&pubkey);
            let human = human_address_from_pubkey(&pubkey);

            if iid != expected_iid {
                failures.push(format!(
                    "Vector '{}': IID mismatch (got {:02x?}, expected {:02x?})",
                    vector.name, iid, expected_iid
                ));
            }

            if &human[..] != expected_human {
                let got_str = core::str::from_utf8(&human).unwrap_or("(invalid utf8)");
                failures.push(format!(
                    "Vector '{}': human_address mismatch (got '{}', expected '{}')",
                    vector.name, got_str, vector.human_address
                ));
            }

            // Verify U/L bit is cleared
            if iid[0] & 0x02 != 0 {
                failures.push(format!(
                    "Vector '{}': IID U/L bit must be cleared",
                    vector.name
                ));
            }

            println!(
                "Vector '{}': iid={:02x?}, human_address='{}'",
                vector.name,
                iid,
                core::str::from_utf8(&human).unwrap_or("(invalid utf8)")
            );
        }

        if !failures.is_empty() {
            for f in &failures {
                eprintln!("FAIL: {}", f);
            }
            panic!("{} node address vector(s) failed", failures.len());
        }

        println!(
            "Validated {} node address vectors",
            vectors.vectors.len()
        );
    }
}
