//! Tests against shared test vectors from test/vectors/link_frame.json
//!
//! These vectors are the source of truth for cross-implementation compatibility.
//! If this test fails, the Rust implementation doesn't match the Python reference.

use std::fs;
use std::path::Path;

use serde::Deserialize;

use lichen_link::frame::{FrameError, LichenFrame, MAX_FRAME_LEN};

#[derive(Deserialize)]
#[cfg(feature = "schnorr")]
struct CryptoMetadata {
    seed: String,
    private_key: String,
    public_key: String,
    preimage: String,
    signature: String,
    #[serde(default)]
    verification: Option<VerificationInputs>,
    #[serde(default)]
    tamper_cases: Vec<SignedTamperCase>,
}

#[derive(Deserialize)]
#[cfg(feature = "schnorr")]
struct VerificationInputs {
    length: u8,
    llsec: u8,
    epoch: u8,
    seqnum: u16,
    dst_len: u8,
    dst_addr: String,
    signer_eui64: String,
    payload: String,
    signature: String,
}

#[derive(Deserialize)]
#[cfg(feature = "schnorr")]
struct SignedTamperCase {
    name: String,
    component: String,
    production_path: String,
    verification: VerificationInputs,
    preimage: String,
    wire: String,
    expected_valid: bool,
}

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
    #[serde(default)]
    #[cfg(feature = "schnorr")]
    crypto: Option<CryptoMetadata>,
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
    #[serde(default)]
    signer_eui64: String,
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

#[cfg(feature = "schnorr")]
#[test]
fn canonical_link_signature_covers_exact_normative_transcript() {
    use lichen_link::schnorr::{verify_frame, verify_profile_message};
    use lichen_link::{LinkSeqNum, PublicKey};
    use std::collections::BTreeSet;

    let vectors_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/link_frame.json");
    let content = fs::read_to_string(vectors_path).expect("read canonical link-frame vectors");
    let vectors: VectorFile =
        serde_json::from_str(&content).expect("parse canonical link-frame vectors");
    let vector = vectors
        .vectors
        .iter()
        .find(|vector| vector.name == "short_addr_signed")
        .expect("canonical short-address signed vector");
    let crypto = vector
        .crypto
        .as_ref()
        .expect("signed vector crypto metadata");
    let wire = hex_decode(&vector.encoded);
    let frame = LichenFrame::from_bytes(&wire).expect("parse canonical signed frame");
    let public_key = PublicKey::new(
        hex_decode(&crypto.public_key)
            .try_into()
            .expect("canonical public key is 32 bytes"),
    );
    let signature = hex_decode(&crypto.signature);
    let canonical = crypto
        .verification
        .as_ref()
        .expect("canonical structured verification inputs");

    assert_eq!(frame.mic, signature);
    assert_eq!(canonical.dst_len as usize, frame.dst_addr.len());
    assert_eq!(hex_decode(&canonical.signature), signature);
    assert!(verify_frame(
        canonical.length,
        canonical.llsec,
        canonical.epoch,
        LinkSeqNum::new(canonical.seqnum),
        &hex_decode(&canonical.dst_addr),
        &hex_decode(&canonical.signer_eui64),
        &hex_decode(&canonical.payload),
        &signature,
        &public_key,
    ));

    // The independently generated canonical preimage verifies as-is. MIC is
    // an input to verification, not part of the signed transcript itself.
    let preimage = hex_decode(&crypto.preimage);
    assert!(verify_profile_message(&public_key, &preimage, &signature));
    let mut preimage_with_mic = preimage;
    preimage_with_mic.extend_from_slice(&signature);
    assert!(!verify_profile_message(
        &public_key,
        &preimage_with_mic,
        &signature,
    ));

    let covered: BTreeSet<_> = crypto
        .tamper_cases
        .iter()
        .map(|case| case.component.as_str())
        .collect();
    assert_eq!(
        covered,
        BTreeSet::from([
            "dst_addr",
            "dst_len",
            "epoch",
            "length",
            "llsec",
            "payload",
            "seqnum",
            "signature",
            "signer_eui64",
        ])
    );

    for case in &crypto.tamper_cases {
        let inputs = &case.verification;
        let destination = hex_decode(&inputs.dst_addr);
        let signer = hex_decode(&inputs.signer_eui64);
        let payload = hex_decode(&inputs.payload);
        let tampered_signature = hex_decode(&inputs.signature);
        let mut exact_wire = vec![inputs.length, inputs.llsec, inputs.epoch];
        exact_wire.extend_from_slice(&inputs.seqnum.to_be_bytes());
        exact_wire.extend_from_slice(&destination);
        exact_wire.extend_from_slice(&signer);
        exact_wire.extend_from_slice(&payload);
        exact_wire.extend_from_slice(&tampered_signature);
        assert_eq!(exact_wire, hex_decode(&case.wire), "{} wire", case.name);
        assert!(!case.expected_valid, "{} verdict", case.name);

        let fixed_preimage = hex_decode(&case.preimage);
        if case.production_path == "frame" {
            assert_eq!(
                inputs.dst_len as usize,
                destination.len(),
                "{} DST_LEN",
                case.name
            );
            assert!(
                !verify_frame(
                    inputs.length,
                    inputs.llsec,
                    inputs.epoch,
                    LinkSeqNum::new(inputs.seqnum),
                    &destination,
                    &signer,
                    &payload,
                    &tampered_signature,
                    &public_key,
                ),
                "{} production verifier accepted tamper",
                case.name
            );
        } else {
            assert_eq!(case.component, "dst_len");
            assert_eq!(case.production_path, "preimage");
        }
        assert!(
            !verify_profile_message(&public_key, &fixed_preimage, &tampered_signature),
            "{} fixed preimage accepted tamper",
            case.name
        );
    }
}

#[cfg(feature = "schnorr")]
#[test]
fn signed_address_modes_match_fixed_oracle_and_wire_boundaries() {
    use lichen_link::schnorr::{verify_frame, verify_profile_message};
    use lichen_link::{LinkSeqNum, PublicKey};
    use std::collections::BTreeSet;

    let vectors_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/vectors/link_frame_signed_modes.json");
    let content = fs::read_to_string(vectors_path).expect("read signed-mode vectors");
    let vectors: VectorFile = serde_json::from_str(&content).expect("parse signed-mode vectors");
    let mut covered_modes = BTreeSet::new();
    let mut max_modes = BTreeSet::new();

    for vector in &vectors.vectors {
        let wire = hex_decode(&vector.encoded);
        let frame = LichenFrame::from_bytes(&wire).expect("parse fixed signed-mode frame");
        let crypto = vector
            .crypto
            .as_ref()
            .expect("signed vector crypto metadata");
        let public_key = PublicKey::new(
            hex_decode(&crypto.public_key)
                .try_into()
                .expect("fixed public key is 32 bytes"),
        );
        let signature = hex_decode(&crypto.signature);
        let length = wire[0];
        let llsec = wire[1];

        covered_modes.insert(frame.addr_mode as u8);
        assert_eq!(frame.mic, signature, "{} MIC bytes", vector.name);
        assert!(
            verify_frame(
                length,
                llsec,
                frame.epoch,
                frame.seqnum,
                frame.dst_addr,
                frame.signer_eui64,
                frame.payload,
                &signature,
                &public_key,
            ),
            "{} production verification",
            vector.name
        );
        assert!(
            verify_profile_message(&public_key, &hex_decode(&crypto.preimage), &signature,),
            "{} fixed preimage verification",
            vector.name
        );

        let mut rebuilt = vec![0; wire.len()];
        let written = frame
            .write_to(&mut rebuilt)
            .expect("re-encode signed-mode frame");
        assert_eq!(&rebuilt[..written], wire, "{} canonical wire", vector.name);

        // Every proper prefix is incomplete, and a byte beyond the declared
        // LENGTH is never accepted (including 256-byte max-frame extensions).
        for cut in 0..wire.len() {
            assert!(
                LichenFrame::from_bytes(&wire[..cut]).is_err(),
                "{} accepted truncation at {}",
                vector.name,
                cut
            );
        }
        let mut extended_wire = wire.clone();
        extended_wire.push(0);
        assert!(
            LichenFrame::from_bytes(&extended_wire).is_err(),
            "{} accepted trailing byte",
            vector.name
        );

        // Mutate each transcript component through the production verifier.
        // For zero-width broadcast/elided destinations, a one-byte argument
        // mutates both the non-wire DST_LEN and the destination component.
        let mut altered_destination = frame.dst_addr.to_vec();
        if altered_destination.is_empty() {
            altered_destination.push(1);
        } else {
            altered_destination[0] ^= 1;
        }
        let mut altered_signer = frame.signer_eui64.to_vec();
        altered_signer[0] ^= 1;
        let mut altered_payload = frame.payload.to_vec();
        altered_payload[0] ^= 1;
        let mut altered_signature = signature.clone();
        altered_signature[0] ^= 1;

        let mutations = [
            (
                length ^ 1,
                llsec,
                frame.epoch,
                frame.seqnum,
                frame.dst_addr,
                frame.signer_eui64,
                frame.payload,
                signature.as_slice(),
            ),
            (
                length,
                llsec ^ 4,
                frame.epoch,
                frame.seqnum,
                frame.dst_addr,
                frame.signer_eui64,
                frame.payload,
                signature.as_slice(),
            ),
            (
                length,
                llsec,
                frame.epoch ^ 1,
                frame.seqnum,
                frame.dst_addr,
                frame.signer_eui64,
                frame.payload,
                signature.as_slice(),
            ),
            (
                length,
                llsec,
                frame.epoch,
                LinkSeqNum::new(frame.seqnum.get().wrapping_add(1)),
                frame.dst_addr,
                frame.signer_eui64,
                frame.payload,
                signature.as_slice(),
            ),
            (
                length,
                llsec,
                frame.epoch,
                frame.seqnum,
                altered_destination.as_slice(),
                frame.signer_eui64,
                frame.payload,
                signature.as_slice(),
            ),
            (
                length,
                llsec,
                frame.epoch,
                frame.seqnum,
                frame.dst_addr,
                altered_signer.as_slice(),
                frame.payload,
                signature.as_slice(),
            ),
            (
                length,
                llsec,
                frame.epoch,
                frame.seqnum,
                frame.dst_addr,
                frame.signer_eui64,
                altered_payload.as_slice(),
                signature.as_slice(),
            ),
            (
                length,
                llsec,
                frame.epoch,
                frame.seqnum,
                frame.dst_addr,
                frame.signer_eui64,
                frame.payload,
                altered_signature.as_slice(),
            ),
        ];
        for (
            mutation,
            (
                mut_length,
                mut_llsec,
                mut_epoch,
                mut_seqnum,
                mut_dst,
                mut_signer,
                mut_payload,
                mut_signature,
            ),
        ) in mutations.into_iter().enumerate()
        {
            assert!(
                !verify_frame(
                    mut_length,
                    mut_llsec,
                    mut_epoch,
                    mut_seqnum,
                    mut_dst,
                    mut_signer,
                    mut_payload,
                    mut_signature,
                    &public_key,
                ),
                "{} accepted transcript mutation {}",
                vector.name,
                mutation
            );
        }

        if vector.name.contains("max_payload") {
            max_modes.insert(frame.addr_mode as u8);
            let expected_payload = 254 - 4 - frame.addr_mode.addr_len() - 8 - 48;
            assert_eq!(
                wire.len(),
                MAX_FRAME_LEN,
                "{} maximum wire size",
                vector.name
            );
            assert_eq!(
                frame.payload.len(),
                expected_payload,
                "{} maximum payload",
                vector.name
            );

            let mut oversized_payload = frame.payload.to_vec();
            oversized_payload.push(0);
            let oversized = LichenFrame {
                epoch: frame.epoch,
                seqnum: frame.seqnum,
                dst_addr: frame.dst_addr,
                signer_eui64: frame.signer_eui64,
                payload: &oversized_payload,
                mic: frame.mic,
                addr_mode: frame.addr_mode,
                mic_length: frame.mic_length,
                signature: frame.signature,
                encryption: frame.encryption,
            };
            assert_eq!(
                oversized.write_to(&mut [0; MAX_FRAME_LEN + 1]),
                Err(FrameError::FrameTooLarge),
                "{} one-byte overflow",
                vector.name
            );
        }
    }

    assert_eq!(covered_modes, BTreeSet::from([0, 1, 2, 3]));
    assert_eq!(max_modes, BTreeSet::from([0, 1, 2, 3]));
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
        // Layout: bits 0-1 = addr_mode, bits 2-4 = mic_len, bit 5 = sig,
        // bit 6 = enc, bit 7 = SI (canonical signer EUI-64 present).
        let llsec = encoded[1];
        let addr_mode = llsec & 0x03;
        let mic_length_flag = (llsec >> 2) & 0x07; // 3 bits
        let sig_present = (llsec >> 5) & 0x01; // bit 5
        let encrypted = (llsec >> 6) & 0x01; // bit 6

        // Only validate raw field parsing for valid vectors (not error cases).
        // Error vectors have intentionally malformed encoded bytes that won't
        // match the fields (which show what they would be if valid).
        if vector.expect.is_none() {
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
                if frame.signer_eui64 != hex_decode(&fields.signer_eui64) {
                    failures.push(format!(
                        "Vector '{}': parsed signer EUI-64 mismatch",
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

                #[cfg(feature = "schnorr")]
                if let Some(crypto) = &vector.crypto {
                    use lichen_link::schnorr::{derive_keypair, verify_frame};
                    use lichen_link::{LinkSeqNum, Seed};

                    let seed_bytes: [u8; 32] = hex_decode(&crypto.seed)
                        .try_into()
                        .expect("crypto vector seed must be 32 bytes");
                    let (private_key, public_key) = derive_keypair(&Seed::new(seed_bytes));
                    if private_key.as_bytes().as_slice() != hex_decode(&crypto.private_key)
                        || public_key.as_bytes().as_slice() != hex_decode(&crypto.public_key)
                    {
                        failures.push(format!(
                            "Vector '{}': key derivation metadata mismatch",
                            vector.name
                        ));
                    }

                    let mut preimage = b"LICHEN-LINK-v1\0".to_vec();
                    preimage.extend_from_slice(&[
                        encoded[0],
                        encoded[1],
                        fields.epoch,
                        (fields.seqnum >> 8) as u8,
                        fields.seqnum as u8,
                        fields.dst_addr.len() as u8 / 2,
                    ]);
                    preimage.extend_from_slice(&hex_decode(&fields.dst_addr));
                    preimage.extend_from_slice(&hex_decode(&fields.signer_eui64));
                    preimage.extend_from_slice(&hex_decode(&fields.payload));
                    if preimage != hex_decode(&crypto.preimage) {
                        failures.push(format!(
                            "Vector '{}': signed preimage metadata mismatch",
                            vector.name
                        ));
                    }
                    let signature = hex_decode(&crypto.signature);
                    if signature != frame.mic
                        || !verify_frame(
                            encoded[0],
                            encoded[1],
                            fields.epoch,
                            LinkSeqNum::new(fields.seqnum),
                            frame.dst_addr,
                            frame.signer_eui64,
                            frame.payload,
                            &signature,
                            &public_key,
                        )
                    {
                        failures.push(format!(
                            "Vector '{}': independent Schnorr transcript failed verification",
                            vector.name
                        ));
                    }
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

#[test]
fn extended_addressing_uses_peer_eui64_not_key_derived_iid() {
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    let vectors_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/link-addressing.json");
    let content = fs::read_to_string(vectors_path).expect("read link-addressing vectors");
    let document: serde_json::Value =
        serde_json::from_str(&content).expect("parse link-addressing vectors");
    let vector = document["vectors"]
        .as_array()
        .and_then(|vectors| {
            vectors
                .iter()
                .find(|vector| vector["name"] == "extended_eui64")
        })
        .expect("extended_eui64 vector");

    assert_eq!(vector["addr_mode"], 2);
    assert_eq!(vector["must_not_use_key_derived_iid"], true);
    let peer_eui = hex_decode(vector["peer_eui64"].as_str().expect("peer EUI-64"));
    let key_iid = hex_decode(vector["key_derived_iid"].as_str().expect("key-derived IID"));
    assert_eq!(peer_eui, hex_decode(vector["dst_addr"].as_str().unwrap()));
    assert_ne!(peer_eui, key_iid);

    let encoded = hex_decode(vector["encoded"].as_str().expect("encoded frame"));
    let frame = LichenFrame::from_bytes(&encoded).expect("parse EXTENDED vector");
    assert_eq!(frame.addr_mode, lichen_link::frame::AddrMode::Extended);
    assert_eq!(frame.dst_addr, peer_eui);
    assert_ne!(frame.dst_addr, key_iid);

    // RFC 4291 interface identifiers invert the EUI-64 U/L bit when forming
    // the resolved link-local IPv6 destination.
    let mut resolved_iid: [u8; 8] = peer_eui.try_into().unwrap();
    resolved_iid[0] ^= 0x02;
    let expected = Ipv6Addr::from_str(
        vector["expected_destination"]
            .as_str()
            .expect("resolved destination"),
    )
    .unwrap()
    .octets();
    assert_eq!(&expected[..8], &[0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&expected[8..], &resolved_iid);

    #[cfg(feature = "schnorr")]
    {
        let vector = document["vectors"]
            .as_array()
            .and_then(|vectors| {
                vectors
                    .iter()
                    .find(|vector| vector["name"] == "key_derived_extended_eui64")
            })
            .expect("key_derived_extended_eui64 vector");
        let public_key: [u8; 32] = hex_decode(
            vector["sender_pubkey_hex"]
                .as_str()
                .expect("sender public key"),
        )
        .try_into()
        .unwrap();
        let derived_iid = lichen_link::iid_from_pubkey(&lichen_link::PublicKey::new(public_key));
        assert_eq!(
            derived_iid,
            hex_decode(vector["key_derived_iid"].as_str().unwrap()).as_slice()
        );
        let mut wire_eui = derived_iid;
        wire_eui[0] ^= 0x02;
        assert_eq!(
            wire_eui,
            hex_decode(vector["wire_eui64_hex"].as_str().unwrap()).as_slice()
        );
        assert_eq!(
            wire_eui,
            hex_decode(vector["dst_addr"].as_str().unwrap()).as_slice()
        );

        let encoded = hex_decode(vector["encoded"].as_str().unwrap());
        let frame = LichenFrame::from_bytes(&encoded).unwrap();
        assert_eq!(frame.addr_mode, lichen_link::frame::AddrMode::Extended);
        assert_eq!(frame.dst_addr, wire_eui);
        let expected = Ipv6Addr::from_str(vector["expected_destination"].as_str().unwrap())
            .unwrap()
            .octets();
        assert_eq!(&expected[8..], &derived_iid);
    }
}

// Cross-validation test for replay window (spec 4.4)

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct ReplayWindowVectorFile {
    format_version: u32,
    window_size: u32,
    vectors: Vec<ReplayWindowVector>,
}

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct ReplayWindowVector {
    name: String,
    #[serde(default)]
    sequence: Vec<ReplayStep>,
}

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct ReplayStep {
    epoch: u8,
    seqnum: u16,
    accept: bool,
}

/// Cross-validate Rust replay window against shared test vectors (spec 4.4).
///
/// These vectors ensure Python, Rust, and C implementations produce identical
/// accept/reject decisions for the same (epoch, seqnum) sequence. The Rust
/// ReplayProtector combines epoch tracking with the per-epoch ReplayWindow.
#[test]
#[cfg(all(feature = "schnorr", feature = "std"))]
fn test_replay_window_vectors() {
    use lichen_link::link_layer::ReplayProtector;
    use lichen_link::seqnum::LinkSeqNum;
    use lichen_link::PublicKey;

    let vectors_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/replay_window.json");

    assert!(
        vectors_path.exists(),
        "Vectors file not found at {:?}",
        vectors_path
    );

    let content = fs::read_to_string(&vectors_path).expect("Failed to read vectors file");
    let vectors: ReplayWindowVectorFile =
        serde_json::from_str(&content).expect("Failed to parse vectors JSON");

    assert_eq!(
        vectors.format_version, 2,
        "Unexpected vector format version"
    );
    assert_eq!(vectors.window_size, 32, "Unexpected window size");

    let mut failures = Vec::new();

    // Use a fixed test public key for the ReplayProtector
    let test_pubkey = PublicKey::from([0u8; 32]);

    for vector in &vectors.vectors {
        if vector.sequence.is_empty() {
            // Skip vectors without sequence (e.g., receiver_state vectors handled separately)
            continue;
        }

        // Fresh protector for each vector
        let mut protector = ReplayProtector::new();

        for (i, step) in vector.sequence.iter().enumerate() {
            let seqnum = LinkSeqNum::new(step.seqnum);
            let result = protector.check_and_update(&test_pubkey, step.epoch, seqnum);

            if result != step.accept {
                failures.push(format!(
                    "Vector '{}' step {}: epoch={}, seqnum={}, expected {}, got {}",
                    vector.name,
                    i,
                    step.epoch,
                    step.seqnum,
                    if step.accept { "accept" } else { "reject" },
                    if result { "accept" } else { "reject" }
                ));
            }
        }

        println!(
            "Vector '{}': {} steps validated",
            vector.name,
            vector.sequence.len()
        );
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {}", f);
        }
        panic!("{} replay window vector step(s) failed", failures.len());
    }

    let sequence_vectors: Vec<_> = vectors
        .vectors
        .iter()
        .filter(|v| !v.sequence.is_empty())
        .collect();
    println!(
        "Validated {} replay window sequence vectors",
        sequence_vectors.len()
    );
}

// Cross-validation test for epoch rollover (spec 4.4)

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct EpochRolloverVectorFile {
    format_version: u32,
    vectors: Vec<EpochRolloverVector>,
}

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct EpochRolloverVector {
    name: String,
    #[serde(default)]
    sender_sequence: Vec<EpochSenderStep>,
    #[serde(default)]
    key_rotation_required_after: bool,
    #[serde(default)]
    tuple: Option<EpochTuple>,
    #[serde(default)]
    counter: Option<u32>,
    #[serde(default)]
    hex: Option<String>,
    #[serde(default)]
    greater_than: Option<EpochOrderRef>,
    #[serde(default)]
    less_than: Option<EpochOrderRef>,
    #[serde(default)]
    receiver_state: Option<EpochReceiverState>,
    #[serde(default)]
    received: Option<EpochReceived>,
    #[serde(default)]
    expected: Option<EpochExpectation>,
    #[serde(default)]
    comparisons: Vec<EpochComparison>,
    #[serde(default)]
    cold_boot_epoch_range: Option<EpochRange>,
    #[serde(default)]
    examples: Vec<EpochColdBootExample>,
}

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct EpochSenderStep {
    epoch: u8,
    seqnum: u16,
    counter: u32,
    accept: bool,
}

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize, Debug)]
struct EpochTuple {
    epoch: u8,
    seqnum: u16,
}

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct EpochOrderRef {
    epoch: u8,
    seqnum: u16,
    counter: u32,
}

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct EpochReceiverState {
    last_epoch: u8,
    last_seqnum: u16,
    #[serde(default)]
    window: u32,
}

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct EpochReceived {
    epoch: u8,
    seqnum: u16,
    #[serde(default)]
    counter: Option<u32>,
}

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct EpochExpectation {
    accept: bool,
    reason: String,
}

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct EpochComparison {
    a: EpochTuple,
    b: EpochTuple,
    a_less_than_b: bool,
}

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct EpochRange {
    min: u8,
    max: u8,
}

#[cfg(all(feature = "schnorr", feature = "std"))]
#[derive(Deserialize)]
struct EpochColdBootExample {
    epoch: u8,
    seqnum: u16,
    counter: u32,
    valid_init: bool,
}

/// 24-bit logical replay counter: (epoch << 16) | seqnum, unsigned ordering.
fn epoch_counter(epoch: u8, seqnum: u16) -> u32 {
    (u32::from(epoch) << 16) | u32::from(seqnum)
}

/// Cross-validate Rust epoch rollover against shared test vectors (spec 4.4).
///
/// Drives the real ReplayProtector through the epoch_rollover.json vectors so
/// Python and Rust prove identical accept/reject decisions for epoch increment,
/// rollover rejection, tuple ordering, and replay detection across boundaries.
#[test]
#[cfg(all(feature = "schnorr", feature = "std"))]
fn test_epoch_rollover_vectors() {
    use lichen_link::link_layer::ReplayProtector;
    use lichen_link::seqnum::LinkSeqNum;
    use lichen_link::PublicKey;

    let vectors_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/epoch_rollover.json");

    assert!(
        vectors_path.exists(),
        "Vectors file not found at {:?}",
        vectors_path
    );

    let content = fs::read_to_string(&vectors_path).expect("Failed to read vectors file");
    let vectors: EpochRolloverVectorFile =
        serde_json::from_str(&content).expect("Failed to parse vectors JSON");

    assert_eq!(
        vectors.format_version, 2,
        "Unexpected vector format version"
    );

    let test_pubkey = PublicKey::from([0u8; 32]);
    let mut failures = Vec::new();

    for vector in &vectors.vectors {
        // Sender sequences: every step must be accepted, counters must match.
        if !vector.sender_sequence.is_empty() {
            let mut protector = ReplayProtector::new();
            for step in &vector.sender_sequence {
                if epoch_counter(step.epoch, step.seqnum) != step.counter {
                    failures.push(format!(
                        "Vector '{}': counter mismatch for ({}, {})",
                        vector.name, step.epoch, step.seqnum
                    ));
                }
                let accepted = protector.check_and_update(
                    &test_pubkey,
                    step.epoch,
                    LinkSeqNum::new(step.seqnum),
                );
                if accepted != step.accept {
                    failures.push(format!(
                        "Vector '{}': sender ({}, {}) expected {}, got {}",
                        vector.name, step.epoch, step.seqnum, step.accept, accepted
                    ));
                }
            }
            if vector.key_rotation_required_after {
                // Terminal counter reached: epoch wrap 255 -> 0 MUST be rejected.
                if protector.check_and_update(&test_pubkey, 0, LinkSeqNum::new(0)) {
                    failures.push(format!(
                        "Vector '{}': epoch rollover after terminal counter was accepted",
                        vector.name
                    ));
                }
            }
            continue;
        }

        // Receiver-state vectors: seed the protector to the recorded state,
        // then check the received frame against the expected decision.
        if let (Some(state), Some(received), Some(expected)) =
            (&vector.receiver_state, &vector.received, &vector.expected)
        {
            if let Some(counter) = received.counter {
                if epoch_counter(received.epoch, received.seqnum) != counter {
                    failures.push(format!(
                        "Vector '{}': received counter mismatch",
                        vector.name
                    ));
                }
            }

            let mut protector = ReplayProtector::new();
            let seeded = match expected.reason.as_str() {
                // The recorded bitmap shows this exact frame was already seen;
                // reconstruct that precondition through the public API:
                // accept the frame, advance to the recorded high-water mark,
                // then re-present the frame.
                "duplicate_in_window" => {
                    let offset =
                        u32::from(state.last_seqnum).wrapping_sub(u32::from(received.seqnum));
                    if offset >= 32 || state.window & (1 << offset) == 0 {
                        failures.push(format!(
                            "Vector '{}': recorded window {:#x} does not mark seqnum {} as seen",
                            vector.name, state.window, received.seqnum
                        ));
                    }
                    let first = protector.check_and_update(
                        &test_pubkey,
                        received.epoch,
                        LinkSeqNum::new(received.seqnum),
                    );
                    if !first {
                        failures.push(format!(
                            "Vector '{}': duplicate_in_window setup rejected first sight",
                            vector.name
                        ));
                    }
                    protector.check_and_update(
                        &test_pubkey,
                        state.last_epoch,
                        LinkSeqNum::new(state.last_seqnum),
                    )
                }
                _ => protector.check_and_update(
                    &test_pubkey,
                    state.last_epoch,
                    LinkSeqNum::new(state.last_seqnum),
                ),
            };
            if !seeded {
                failures.push(format!(
                    "Vector '{}': could not seed receiver state ({}, {})",
                    vector.name, state.last_epoch, state.last_seqnum
                ));
                continue;
            }

            let result = protector.check_and_update(
                &test_pubkey,
                received.epoch,
                LinkSeqNum::new(received.seqnum),
            );
            if result != expected.accept {
                failures.push(format!(
                    "Vector '{}': received ({}, {}) reason={} expected {}, got {}",
                    vector.name,
                    received.epoch,
                    received.seqnum,
                    expected.reason,
                    expected.accept,
                    result
                ));
            }
            continue;
        }

        // Tuple ordering vectors: counter math, canonical hex, ordering relations.
        if let Some(tuple) = &vector.tuple {
            let computed = epoch_counter(tuple.epoch, tuple.seqnum);
            if Some(computed) != vector.counter {
                failures.push(format!("Vector '{}': tuple counter mismatch", vector.name));
            }
            if let Some(hex) = &vector.hex {
                if format!("{computed:06x}") != *hex {
                    failures.push(format!(
                        "Vector '{}': hex mismatch (got {:06x}, want {})",
                        vector.name, computed, hex
                    ));
                }
            }
            if let Some(other) = &vector.greater_than {
                if epoch_counter(other.epoch, other.seqnum) != other.counter
                    || computed <= epoch_counter(other.epoch, other.seqnum)
                {
                    failures.push(format!(
                        "Vector '{}': greater_than ordering violated",
                        vector.name
                    ));
                }
            }
            if let Some(other) = &vector.less_than {
                if epoch_counter(other.epoch, other.seqnum) != other.counter
                    || computed >= epoch_counter(other.epoch, other.seqnum)
                {
                    failures.push(format!(
                        "Vector '{}': less_than ordering violated",
                        vector.name
                    ));
                }
            }
            continue;
        }

        // Unsigned comparison vectors: ordinary integer ordering, not serial arithmetic.
        for comp in &vector.comparisons {
            let a = epoch_counter(comp.a.epoch, comp.a.seqnum);
            let b = epoch_counter(comp.b.epoch, comp.b.seqnum);
            let ordered = if comp.a_less_than_b { a < b } else { a >= b };
            if !ordered {
                failures.push(format!(
                    "Vector '{}': comparison {:?} < {:?} violated",
                    vector.name, comp.a, comp.b
                ));
            }
        }

        // Cold-boot init vectors: counter math plus [min, max] validity.
        if let Some(range) = &vector.cold_boot_epoch_range {
            for example in &vector.examples {
                if epoch_counter(example.epoch, example.seqnum) != example.counter {
                    failures.push(format!(
                        "Vector '{}': cold boot counter mismatch for epoch {}",
                        vector.name, example.epoch
                    ));
                }
                let in_range = range.min <= example.epoch && example.epoch <= range.max;
                if in_range != example.valid_init {
                    failures.push(format!(
                        "Vector '{}': epoch {} valid_init mismatch",
                        vector.name, example.epoch
                    ));
                }
            }
        }
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {}", f);
        }
        panic!("{} epoch rollover vector check(s) failed", failures.len());
    }

    println!("Validated {} epoch rollover vectors", vectors.vectors.len());
}
