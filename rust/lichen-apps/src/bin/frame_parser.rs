// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Frame parser for cross-implementation interop testing.
//!
//! Takes a LICHEN frame (as file path or hex string) and outputs parsed fields as JSON.
//! Used by Python test suite to verify Rust parsing matches Python encoding.
//!
//! Usage:
//!   frame-parser frame.bin          # Parse binary file
//!   frame-parser --hex 0700010002616263  # Parse hex string

use std::env;
use std::fs;
use std::process;

use lichen_link::frame::{Encryption, LichenFrame, Signature};

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("Hex string must have even length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: frame-parser <file.bin> | frame-parser --hex <hexstring>");
        process::exit(1);
    }

    let frame_bytes = if args[1] == "--hex" {
        if args.len() < 3 {
            eprintln!("Missing hex string");
            process::exit(1);
        }
        match hex_decode(&args[2]) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Hex decode error: {}", e);
                process::exit(1);
            }
        }
    } else {
        match fs::read(&args[1]) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("File read error: {}", e);
                process::exit(1);
            }
        }
    };

    match LichenFrame::from_bytes(&frame_bytes) {
        Ok(frame) => {
            let json = serde_json::json!({
                "epoch": frame.epoch,
                "seqnum": frame.seqnum.get(),
                "addr_mode": frame.addr_mode as u8,
                "mic_length": frame.mic_length as u8,
                "signature_present": matches!(frame.signature, Signature::Present),
                "encrypted": matches!(frame.encryption, Encryption::Encrypted),
                "dst_addr": hex::encode(frame.dst_addr),
                "payload": hex::encode(frame.payload),
                "mic": hex::encode(frame.mic),
                "total_len": frame_bytes.len(),
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        Err(e) => {
            let json = serde_json::json!({
                "error": format!("{:?}", e),
                "input_len": frame_bytes.len(),
                "input_hex": hex::encode(&frame_bytes),
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
            process::exit(2);
        }
    }
}
