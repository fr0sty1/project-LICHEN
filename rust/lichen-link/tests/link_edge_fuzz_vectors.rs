// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Consumer for `test/vectors/link-edge-fuzz.json`.
//!
//! Negative cases treat `encoded` as the oracle. Valid frames are
//! re-encoded through `LichenFrame::write_to` after a parse that must
//! reproduce the committed fields.

use lichen_link::frame::{FrameError, LichenFrame};

const VECTORS_JSON: &str = include_str!("../../../test/vectors/link-edge-fuzz.json");

fn hex_decode(s: &str) -> Vec<u8> {
    if s.is_empty() {
        return Vec::new();
    }
    assert!(
        s.len().is_multiple_of(2),
        "odd hex length in vector field: {}",
        s.len()
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn matches_error(category: &str, error: FrameError, encoded: &[u8]) -> bool {
    match category {
        "reserved_mic_length" => {
            if encoded.len() < 2 {
                return false;
            }
            let mic_field = (encoded[1] >> 2) & 0x07;
            error == FrameError::ReservedMicLength(mic_field)
        }
        "empty_frame" => error == FrameError::Empty,
        "length_mismatch" => matches!(error, FrameError::TooShort(_) | FrameError::TrailingBytes),
        "frame_too_short"
        | "truncated_mic"
        | "declared_address_mic_short"
        | "truncated_signer_eui64" => matches!(error, FrameError::TooShort(_)),
        "si_without_s" => error == FrameError::SignatureSignerMismatch,
        "signed_encrypted_unsupported" | "encryption_unsupported" => {
            error == FrameError::EncryptedUnsupported
        }
        "frame_too_large" => error == FrameError::FrameTooLarge,
        _ => false,
    }
}

#[test]
fn link_edge_fuzz_vectors() {
    let document: serde_json::Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    assert_eq!(document["format_version"], 2);
    let vectors = document["vectors"].as_array().expect("vectors array");
    let mut seen = std::collections::BTreeSet::new();
    let mut failures = Vec::new();

    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        seen.insert(name.to_string());
        let encoded = hex_decode(vector["encoded"].as_str().expect("encoded"));
        let expected_error = vector
            .get("expect")
            .and_then(|expect| expect.get("error"))
            .and_then(|error| error.as_str());

        match LichenFrame::from_bytes(&encoded) {
            Ok(frame) => {
                if let Some(category) = expected_error {
                    failures.push(format!(
                        "{name}: expected {category} but parser accepted the frame"
                    ));
                    continue;
                }
                let fields = &vector["fields"];
                if frame.epoch != fields["epoch"].as_u64().unwrap() as u8 {
                    failures.push(format!("{name}: epoch mismatch"));
                }
                if u64::from(frame.seqnum.get()) != fields["seqnum"].as_u64().unwrap() {
                    failures.push(format!("{name}: seqnum mismatch"));
                }
                if (frame.addr_mode as u8) != fields["addr_mode"].as_u64().unwrap() as u8 {
                    failures.push(format!("{name}: addr_mode mismatch"));
                }
                if frame.dst_addr != hex_decode(fields["dst_addr"].as_str().unwrap()) {
                    failures.push(format!("{name}: dst_addr mismatch"));
                }
                if frame.payload != hex_decode(fields["payload"].as_str().unwrap()) {
                    failures.push(format!("{name}: payload mismatch"));
                }
                if frame.mic != hex_decode(fields["mic"].as_str().unwrap()) {
                    failures.push(format!("{name}: mic mismatch"));
                }
                if frame.signer_eui64 != hex_decode(fields["signer_eui64"].as_str().unwrap()) {
                    failures.push(format!("{name}: signer_eui64 mismatch"));
                }
                if frame.signature.is_present() != fields["signature_present"].as_bool().unwrap() {
                    failures.push(format!("{name}: signature_present mismatch"));
                }
                if frame.encryption.is_encrypted() != fields["encrypted"].as_bool().unwrap() {
                    failures.push(format!("{name}: encrypted mismatch"));
                }
                let mut rebuilt = vec![0u8; encoded.len()];
                match frame.write_to(&mut rebuilt) {
                    Ok(written) if rebuilt[..written] == encoded => {}
                    Ok(written) => failures.push(format!(
                        "{name}: re-encode length {written} != {}",
                        encoded.len()
                    )),
                    Err(error) => failures.push(format!("{name}: re-encode failed: {error:?}")),
                }
            }
            Err(error) => match expected_error {
                Some(category) if matches_error(category, error, &encoded) => {}
                Some(category) => {
                    failures.push(format!("{name}: expected {category}, got {error:?}"))
                }
                None => failures.push(format!("{name}: unexpected parse error {error:?}")),
            },
        }
    }

    for required in [
        "edge_encrypted_unsigned_rejected",
        "edge_fuzz_random_ffff",
        "edge_reserved_mic_5",
        "edge_si_without_s_raw",
        "edge_signer_eui64_truncated",
    ] {
        if !seen.contains(required) {
            failures.push(format!("missing required vector {required}"));
        }
    }

    if !failures.is_empty() {
        for failure in &failures {
            eprintln!("FAIL: {failure}");
        }
        panic!("{} link-edge-fuzz vector(s) failed", failures.len());
    }
}
