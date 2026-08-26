#![cfg(feature = "schnorr")]

//! Cross-validation of the Rust Schnorr48 implementation against the
//! canonical corpus in `test/vectors/schnorr48.json`
//! (spec/drafts/draft-lichen-schnorr-00.md, Appendix A).
//!
//! The canonical signatures are the interchange format between the Python
//! reference implementation (`python/src/lichen/crypto/schnorr48.py`) and
//! this implementation: signing a valid vector must reproduce the exact
//! canonical signature bytes, and every canonical signature must verify
//! here exactly as it does on the Python side.

use std::fs;
use std::path::{Path, PathBuf};

use lichen_link::schnorr::{derive_keypair, sign, verify, verify_profile_message};
use lichen_link::Seed;
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    description: String,
    seed: Option<String>,
    private_key: Option<String>,
    public_key: String,
    message: String,
    signature: String,
    valid: bool,
}

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/schnorr48.json")
}

fn load_vectors() -> VectorFile {
    serde_json::from_str(
        &fs::read_to_string(vectors_path()).expect("read canonical Schnorr48 vectors"),
    )
    .expect("parse canonical Schnorr48 vectors")
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2, "hex value has unexpected length");
    let mut decoded = [0; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .expect("vector contains valid hexadecimal");
    }
    decoded
}

fn decode_message(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "message hex has an odd length");
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .expect("vector contains valid message hexadecimal")
        })
        .collect()
}

#[test]
fn canonical_vectors_full_corpus() {
    let document = load_vectors();

    for (i, vector) in document.vectors.iter().enumerate() {
        let description = &vector.description;
        let public_key = lichen_link::PublicKey::new(decode_hex::<32>(&vector.public_key));
        let message = decode_message(&vector.message);
        let signature_hex = vector.signature.clone();
        let valid = vector.valid;

        if !valid {
            // Malformed-length signatures must be rejected at the slice API.
            let sig_bytes = decode_message(&signature_hex);
            if sig_bytes.len() != 48 {
                assert!(
                    !verify_profile_message(&public_key, &message, &sig_bytes),
                    "vector {i} ({description}): malformed-length signature accepted"
                );
                continue;
            }
            let signature = <[u8; 48]>::try_from(sig_bytes.as_slice()).unwrap();
            assert!(
                !verify(&public_key, &message, &signature),
                "vector {i} ({description}): invalid signature accepted"
            );
            continue;
        }

        // Valid vectors carry the seed so implementations can re-derive and
        // re-sign; parity with Python requires bit-exact reproduction.
        let seed_hex = vector
            .seed
            .as_deref()
            .unwrap_or_else(|| panic!("vector {i} ({description}): missing seed"));
        let seed = Seed::new(decode_hex::<32>(seed_hex));
        let (private_key, derived_public) = derive_keypair(&seed);

        if let Some(expected_priv) = &vector.private_key {
            assert_eq!(
                private_key.as_bytes(),
                &decode_hex::<32>(expected_priv),
                "vector {i} ({description}): private key derivation mismatch"
            );
        }
        assert_eq!(
            derived_public.as_bytes(),
            &decode_hex::<32>(&vector.public_key),
            "vector {i} ({description}): public key derivation mismatch"
        );

        // Deterministic signing: repeated calls yield the canonical bytes.
        let expected = decode_hex::<48>(&signature_hex);
        let first = sign(&private_key, &derived_public, &message);
        let second = sign(&private_key, &derived_public, &message);
        assert_eq!(
            first, expected,
            "vector {i} ({description}): signature mismatch"
        );
        assert_eq!(
            first, second,
            "vector {i} ({description}): non-deterministic"
        );

        assert!(
            verify(&public_key, &message, &expected),
            "vector {i} ({description}): canonical signature rejected"
        );
        assert!(
            verify(&public_key, &message, &first),
            "vector {i} ({description}): freshly signed signature rejected"
        );
    }
}

#[test]
fn canonical_deterministic_signature_matches_repeatedly() {
    let document = load_vectors();
    let vector = document
        .vectors
        .iter()
        .find(|vector| vector.description.starts_with("Determinism:"))
        .expect("canonical corpus contains the determinism vector");

    assert!(vector.valid, "determinism vector must be signing-positive");
    let seed = Seed::new(decode_hex::<32>(
        vector.seed.as_deref().expect("determinism seed"),
    ));
    let (private_key, public_key) = derive_keypair(&seed);
    assert_eq!(
        private_key.as_bytes(),
        &decode_hex::<32>(
            vector
                .private_key
                .as_deref()
                .expect("determinism private key")
        )
    );
    assert_eq!(public_key.as_bytes(), &decode_hex::<32>(&vector.public_key));

    let message = decode_message(&vector.message);
    let expected = decode_hex::<48>(&vector.signature);
    let first = sign(&private_key, &public_key, &message);
    let second = sign(&private_key, &public_key, &message);

    assert_eq!(first, expected);
    assert_eq!(second, expected);
    assert_eq!(first, second);
    assert!(verify(&public_key, &message, &first));
}
