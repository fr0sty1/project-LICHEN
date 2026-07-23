//! Tests against shared test vectors from test/vectors/link_frame.json
//!
//! These vectors are the source of truth for cross-implementation compatibility.
//! If this test fails, the Rust implementation doesn't match the Python reference.

use std::fs;
use std::path::Path;

use serde::Deserialize;

use lichen_link::frame::{FrameError, LichenFrame, MAX_FRAME_LEN};

#[derive(Deserialize)]
struct VectorFile {
    format_version: u32,
    vectors: Vec<LinkFrameVector>,
}

#[derive(Deserialize)]
struct LinkFrameVector {
    name: String,
    encoded: String,
    fields: LinkFrameFields,
    #[serde(default)]
    expect: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct LinkFrameFields {
    epoch: u8,
    seqnum: u16,
    dst_addr: String,
    payload: String,
    mic: String,
    addr_mode: u8,
    mic_length: u8,
    signature_present: bool,
    encrypted: bool,
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
fn parser_rejects_length_255_frame() {
    let mut encoded = vec![0; MAX_FRAME_LEN + 1];
    encoded[0] = u8::MAX;
    assert_eq!(
        LichenFrame::from_bytes(&encoded),
        Err(FrameError::FrameTooLarge)
    );
}

#[test]
fn test_link_frame_vectors() {
    let vectors_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/link_frame.json");

    assert!(
        vectors_path.exists(),
        "Vectors file not found at {:?}",
        vectors_path
    );

    let content = fs::read_to_string(&vectors_path).expect("Failed to read vectors file");
    let vectors: VectorFile = serde_json::from_str(&content).expect("Failed to parse vectors JSON");

    assert_eq!(
        vectors.format_version, 2,
        "Unexpected vector format version"
    );

    let mut failures = Vec::new();

    for vector in &vectors.vectors {
        let encoded = hex_decode(&vector.encoded);
        let fields = &vector.fields;

        #[cfg(feature = "schnorr")]
        if let Some(crypto) = &vector.crypto {
            use lichen_link::schnorr::{derive_keypair, sign_frame, verify_frame};
            use lichen_link::{LinkSeqNum, Seed};

            let seed: [u8; 32] = hex_decode(&crypto.seed).try_into().unwrap();
            let expected_private = hex_decode(&crypto.private_key);
            let expected_public = hex_decode(&crypto.public_key);
            let expected_preimage = hex_decode(&crypto.preimage);
            let expected_signature: [u8; 48] = hex_decode(&crypto.signature).try_into().unwrap();
            let (private_key, public_key) = derive_keypair(&Seed::new(seed));
            assert_eq!(private_key.as_bytes().as_slice(), expected_private);
            assert_eq!(public_key.as_bytes().as_slice(), expected_public);
            assert_eq!(&encoded[..encoded.len() - 48], expected_preimage);

            let dst_addr = hex_decode(&fields.dst_addr);
            let payload = hex_decode(&fields.payload);
            let signature = sign_frame(
                encoded[0],
                encoded[1],
                fields.epoch,
                LinkSeqNum::new(fields.seqnum),
                &dst_addr,
                &payload,
                &private_key,
                &public_key,
            );
            assert_eq!(signature, expected_signature);
            assert_eq!(hex_decode(&fields.mic), expected_signature);
            assert_eq!(&encoded[encoded.len() - 48..], expected_signature);
            assert!(verify_frame(
                encoded[0],
                encoded[1],
                fields.epoch,
                LinkSeqNum::new(fields.seqnum),
                &dst_addr,
                &payload,
                &signature,
                &public_key,
            ));

            let mut tampered_dst = dst_addr.clone();
            tampered_dst[0] ^= 1;
            let mut tampered_payload = payload.clone();
            tampered_payload[0] ^= 1;
            let mut tampered_signature = signature;
            tampered_signature[0] ^= 1;
            assert!(!verify_frame(
                encoded[0] ^ 1,
                encoded[1],
                fields.epoch,
                LinkSeqNum::new(fields.seqnum),
                &dst_addr,
                &payload,
                &signature,
                &public_key
            ));
            assert!(!verify_frame(
                encoded[0],
                encoded[1],
                fields.epoch ^ 1,
                LinkSeqNum::new(fields.seqnum),
                &dst_addr,
                &payload,
                &signature,
                &public_key
            ));
            assert!(!verify_frame(
                encoded[0],
                encoded[1],
                fields.epoch,
                LinkSeqNum::new(fields.seqnum ^ 1),
                &dst_addr,
                &payload,
                &signature,
                &public_key
            ));
            assert!(!verify_frame(
                encoded[0],
                encoded[1] ^ 1,
                fields.epoch,
                LinkSeqNum::new(fields.seqnum),
                &dst_addr,
                &payload,
                &signature,
                &public_key
            ));
            assert!(!verify_frame(
                encoded[0],
                encoded[1],
                fields.epoch,
                LinkSeqNum::new(fields.seqnum),
                &tampered_dst,
                &payload,
                &signature,
                &public_key
            ));
            assert!(!verify_frame(
                encoded[0],
                encoded[1],
                fields.epoch,
                LinkSeqNum::new(fields.seqnum),
                &dst_addr,
                &tampered_payload,
                &signature,
                &public_key
            ));
            assert!(!verify_frame(
                encoded[0],
                encoded[1],
                fields.epoch,
                LinkSeqNum::new(fields.seqnum),
                &dst_addr,
                &payload,
                &tampered_signature,
                &public_key
            ));
        }

        // Verify minimum frame size (header + MIC)
        if encoded.len() < 5 {
            failures.push(format!(
                "Vector '{}': frame too short ({} bytes)",
                vector.name,
                encoded.len()
            ));
            continue;
        }

        // Parse LLSEC byte (byte 1)
        // Layout: bits 0-1 = addr_mode, bits 2-4 = mic_len, bit 5 = sig, bit 6 = enc
        let llsec = encoded[1];
        let addr_mode = llsec & 0x03;
        let mic_length_flag = (llsec >> 2) & 0x07; // 3 bits
        let sig_present = (llsec >> 5) & 0x01; // bit 5
        let encrypted = (llsec >> 6) & 0x01; // bit 6

        // Check addr_mode
        if addr_mode != fields.addr_mode {
            failures.push(format!(
                "Vector '{}': addr_mode mismatch (encoded: {}, expected: {})",
                vector.name, addr_mode, fields.addr_mode
            ));
        }

        // Check MIC length flag
        if mic_length_flag != fields.mic_length {
            failures.push(format!(
                "Vector '{}': mic_length mismatch (encoded: {}, expected: {})",
                vector.name, mic_length_flag, fields.mic_length
            ));
        }

        // Check signature_present flag
        if (sig_present != 0) != fields.signature_present {
            failures.push(format!(
                "Vector '{}': signature_present mismatch (encoded: {}, expected: {})",
                vector.name,
                sig_present != 0,
                fields.signature_present
            ));
        }

        // Check encrypted flag
        if (encrypted != 0) != fields.encrypted {
            failures.push(format!(
                "Vector '{}': encrypted mismatch (encoded: {}, expected: {})",
                vector.name,
                encrypted != 0,
                fields.encrypted
            ));
        }

        // Check epoch (byte 2)
        if encoded[2] != fields.epoch {
            failures.push(format!(
                "Vector '{}': epoch mismatch (encoded: {}, expected: {})",
                vector.name, encoded[2], fields.epoch
            ));
        }

        // Check seqnum (bytes 3-4, big-endian)
        let seqnum = u16::from_be_bytes([encoded[3], encoded[4]]);
        if seqnum != fields.seqnum {
            failures.push(format!(
                "Vector '{}': seqnum mismatch (encoded: {}, expected: {})",
                vector.name, seqnum, fields.seqnum
            ));
        }

        // Actually parse using lichen-link's frame parser
        match lichen_link::frame::LichenFrame::from_bytes(&encoded) {
            Ok(frame) => {
                if vector.expect.is_some() {
                    failures.push(format!("Vector '{}': expected parse failure", vector.name));
                    continue;
                }
                if frame.epoch != fields.epoch {
                    failures.push(format!(
                        "Vector '{}': parsed epoch {} != expected {}",
                        vector.name, frame.epoch, fields.epoch
                    ));
                }
                if frame.seqnum.get() != fields.seqnum {
                    failures.push(format!(
                        "Vector '{}': parsed seqnum {} != expected {}",
                        vector.name,
                        frame.seqnum.get(),
                        fields.seqnum
                    ));
                }
                if (frame.addr_mode as u8) != fields.addr_mode {
                    failures.push(format!(
                        "Vector '{}': parsed addr_mode {:?} != expected {}",
                        vector.name, frame.addr_mode, fields.addr_mode
                    ));
                }
                let parsed_sig = matches!(frame.signature, lichen_link::frame::Signature::Present);
                if parsed_sig != fields.signature_present {
                    failures.push(format!(
                        "Vector '{}': parsed signature_present {} != expected {}",
                        vector.name, parsed_sig, fields.signature_present
                    ));
                }
                let parsed_enc =
                    matches!(frame.encryption, lichen_link::frame::Encryption::Encrypted);
                if parsed_enc != fields.encrypted {
                    failures.push(format!(
                        "Vector '{}': parsed encrypted {} != expected {}",
                        vector.name, parsed_enc, fields.encrypted
                    ));
                }
                if frame.dst_addr != hex_decode(&fields.dst_addr) {
                    failures.push(format!(
                        "Vector '{}': parsed dst_addr mismatch",
                        vector.name
                    ));
                }
                if frame.payload != hex_decode(&fields.payload) {
                    failures.push(format!("Vector '{}': parsed payload mismatch", vector.name));
                }
                if frame.mic != hex_decode(&fields.mic) {
                    failures.push(format!("Vector '{}': parsed MIC mismatch", vector.name));
                }
                if frame.mic_length as u8 != fields.mic_length {
                    failures.push(format!(
                        "Vector '{}': parsed mic_length mismatch",
                        vector.name
                    ));
                }

                let mut rebuilt = vec![0u8; encoded.len()];
                match frame.write_to(&mut rebuilt) {
                    Ok(written) if rebuilt[..written] == encoded => {}
                    Ok(written) => failures.push(format!(
                        "Vector '{}': re-encoded bytes differ ({} bytes != {} bytes)",
                        vector.name,
                        written,
                        encoded.len()
                    )),
                    Err(e) => failures.push(format!(
                        "Vector '{}': re-encode failed: {:?}",
                        vector.name, e
                    )),
                }
            }
            Err(e) => {
                if vector.expect.is_none() {
                    failures.push(format!("Vector '{}': parse failed: {:?}", vector.name, e));
                }
            }
        }

        println!(
            "Vector '{}': {} bytes, epoch={}, seqnum={}, addr_mode={}, mic_len={}, sig={}, enc={}",
            vector.name,
            encoded.len(),
            fields.epoch,
            fields.seqnum,
            fields.addr_mode,
            fields.mic_length,
            fields.signature_present,
            fields.encrypted
        );
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {}", f);
        }
        panic!("{} link frame vector(s) failed", failures.len());
    }

    println!("Validated {} link frame vectors", vectors.vectors.len());
}

#[test]
fn test_l2_payload_vectors() {
    let vectors_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/l2_payload.json");

    assert!(
        vectors_path.exists(),
        "Vectors file not found at {:?}",
        vectors_path
    );

    let content = fs::read_to_string(&vectors_path).expect("Failed to read vectors file");

    #[derive(Deserialize)]
    struct L2PayloadFile {
        format_version: u32,
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

    let vectors: L2PayloadFile =
        serde_json::from_str(&content).expect("Failed to parse vectors JSON");

    assert_eq!(
        vectors.format_version, 2,
        "Unexpected vector format version"
    );

    let mut failures = Vec::new();

    for vector in &vectors.vectors {
        let wrapped = hex_decode(&vector.wrapped);
        let body = hex_decode(&vector.body);

        // First byte must be dispatch
        if wrapped.is_empty() {
            failures.push(format!("Vector '{}': empty wrapped", vector.name));
            continue;
        }

        if wrapped[0] != vector.dispatch {
            failures.push(format!(
                "Vector '{}': dispatch mismatch (expected {:#x}, got {:#x})",
                vector.name, vector.dispatch, wrapped[0]
            ));
        }

        // Body should match remaining bytes
        if wrapped.len() > 1 && wrapped[1..] != body[..] {
            failures.push(format!("Vector '{}': body mismatch", vector.name));
        }

        // Verify dispatch matches known kinds
        let expected_dispatch = match vector.kind.as_str() {
            "schc" => Some(0x14),
            "routing" => Some(0x15),
            "unknown" => None, // Unknown is intentionally unmatched
            _ => {
                failures.push(format!(
                    "Vector '{}': unrecognized kind '{}'",
                    vector.name, vector.kind
                ));
                None
            }
        };

        if let Some(expected) = expected_dispatch {
            if vector.dispatch != expected {
                failures.push(format!(
                    "Vector '{}': kind/dispatch mismatch (kind={}, dispatch={:#x}, expected={:#x})",
                    vector.name, vector.kind, vector.dispatch, expected
                ));
            }
        }

        println!(
            "Vector '{}': {} bytes, kind={}, dispatch={:#x}",
            vector.name,
            wrapped.len(),
            vector.kind,
            vector.dispatch
        );
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {}", f);
        }
        panic!("{} L2 payload vector(s) failed", failures.len());
    }

    println!("Validated {} L2 payload vectors", vectors.vectors.len());
}
