// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Production OSCORE -> SCHC Rule 5 -> OSCORE integration coverage.

use lichen_oscore::{Context, ContextId, OscoreError, SenderSequenceState, SenderStateStore};
use lichen_schc::{compress, decompress, SchcError};
use serde::Deserialize;
use std::fs;

const MAX_SEQUENCE: u64 = (1u64 << 40) - 1;

#[derive(Clone, Copy)]
struct Store(Option<SenderSequenceState>);

impl Store {
    fn at(sequence: u64) -> Self {
        Self(Some(SenderSequenceState {
            next_sequence: sequence,
            exhausted: false,
        }))
    }
}

impl SenderStateStore for Store {
    type Error = core::convert::Infallible;

    fn load(&mut self, _: &ContextId) -> Result<Option<SenderSequenceState>, Self::Error> {
        Ok(self.0)
    }

    fn compare_exchange(
        &mut self,
        _: &ContextId,
        expected: Option<SenderSequenceState>,
        next: SenderSequenceState,
    ) -> Result<bool, Self::Error> {
        if self.0 != expected {
            return Ok(false);
        }
        self.0 = Some(next);
        Ok(true)
    }
}

#[derive(Deserialize)]
struct Document {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    master_secret: String,
    master_salt: String,
    sender_id: String,
    recipient_id: String,
    id_context: Option<String>,
    sender_seq: u64,
    plaintext: Plaintext,
    oscore_option: String,
    ciphertext: String,
    ipv6_packet: String,
    schc_rule5: String,
}

#[derive(Deserialize)]
struct Plaintext {
    code: u8,
    options: String,
    payload: String,
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

fn vectors() -> Document {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/oscore_schc_roundtrip.json"
    );
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn context(vector: &Vector, receiver: bool, secret_override: Option<[u8; 16]>) -> Context {
    let secret: [u8; 16] =
        secret_override.unwrap_or_else(|| hex(&vector.master_secret).try_into().unwrap());
    let salt = hex(&vector.master_salt);
    let sender = hex(if receiver {
        &vector.recipient_id
    } else {
        &vector.sender_id
    });
    let recipient = hex(if receiver {
        &vector.sender_id
    } else {
        &vector.recipient_id
    });
    let id_context = vector.id_context.as_deref().map(hex);
    Context::new(
        &secret,
        Some(&salt),
        id_context.as_deref(),
        &sender,
        &recipient,
    )
    .unwrap()
    .restore_existing(&mut Store::at(if receiver { 0 } else { vector.sender_seq }))
    .unwrap()
}

fn extract_protected(packet: &[u8]) -> (&[u8], &[u8]) {
    let coap = &packet[48..];
    let option_offset = 4 + usize::from(coap[0] & 0x0f);
    assert_eq!(coap[option_offset] >> 4, 9);
    let option_len = usize::from(coap[option_offset] & 0x0f);
    let option = &coap[option_offset + 1..option_offset + 1 + option_len];
    let marker = option_offset + 1 + option_len;
    assert_eq!(coap[marker], 0xff);
    (option, &coap[marker + 1..])
}

fn checksum_sum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_packet(option: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    assert!(option.len() <= 12);
    let mut coap = vec![0x40, 0x02, 0x12, 0x34, 0x90 | option.len() as u8];
    coap.extend_from_slice(option);
    coap.push(0xff);
    coap.extend_from_slice(ciphertext);
    let udp_len = 8 + coap.len();
    let src = hex("fe800000000000000000000000000001");
    let dst = hex("fe800000000000000000000000000002");
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&5683u16.to_be_bytes());
    udp.extend_from_slice(&5683u16.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(&coap);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    let checksum = fold(checksum_sum(&pseudo) + checksum_sum(&udp));
    udp[6..8].copy_from_slice(&(if checksum == 0 { 0xffff } else { checksum }).to_be_bytes());
    let mut packet = vec![0x60, 0, 0, 0];
    packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    packet.extend_from_slice(&[17, 64]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(&udp);
    packet
}

#[test]
fn protect_compress_decompress_unprotect_matches_shared_vectors() {
    for vector in vectors().vectors {
        let mut sender = context(&vector, false, None);
        let mut store = Store::at(vector.sender_seq);
        let (ciphertext, option) = sender
            .reserve_sender(&mut store)
            .unwrap()
            .protect_request(
                vector.plaintext.code,
                &hex(&vector.plaintext.options),
                &hex(&vector.plaintext.payload),
            )
            .unwrap();
        assert_eq!(
            option.as_slice(),
            hex(&vector.oscore_option),
            "{}",
            vector.name
        );
        assert_eq!(
            ciphertext.as_slice(),
            hex(&vector.ciphertext),
            "{}",
            vector.name
        );

        let packet = hex(&vector.ipv6_packet);
        let expected = hex(&vector.schc_rule5);
        let mut compressed = vec![0xa5; packet.len() + 1];
        let compressed_len = compress(&packet, &mut compressed).unwrap();
        assert_eq!(
            &compressed[..compressed_len],
            expected.as_slice(),
            "{}",
            vector.name
        );
        let mut restored = vec![0xa5; packet.len()];
        let restored_len = decompress(&compressed[..compressed_len], &mut restored).unwrap();
        assert_eq!(
            &restored[..restored_len],
            packet.as_slice(),
            "{}",
            vector.name
        );

        let (option, ciphertext) = extract_protected(&restored[..restored_len]);
        let mut receiver = context(&vector, true, None);
        let (code, options, payload) = receiver.unprotect_request(option, ciphertext).unwrap();
        assert_eq!(code, vector.plaintext.code);
        assert_eq!(options.as_slice(), hex(&vector.plaintext.options));
        assert_eq!(payload.as_slice(), hex(&vector.plaintext.payload));
        assert_eq!(
            receiver.unprotect_request(option, ciphertext),
            Err(OscoreError::Replay)
        );
    }
}

#[test]
fn failures_do_not_advance_receiver_or_mutate_schc_output() {
    let vector = &vectors().vectors[0];
    let canonical = hex(&vector.schc_rule5);
    let mut restored = vec![0xa5; hex(&vector.ipv6_packet).len()];
    let restored_len = decompress(&canonical, &mut restored).unwrap();
    let (option, ciphertext) = extract_protected(&restored[..restored_len]);
    let mut receiver = context(vector, true, None);

    let mut corrupt = ciphertext.to_vec();
    *corrupt.last_mut().unwrap() ^= 0x80;
    assert!(receiver.unprotect_request(option, &corrupt).is_err());
    assert!(receiver
        .unprotect_request(option, &ciphertext[..ciphertext.len() - 1])
        .is_err());

    let mut wrong_secret: [u8; 16] = hex(&vector.master_secret).try_into().unwrap();
    wrong_secret[0] ^= 1;
    let mut wrong = context(vector, true, Some(wrong_secret));
    assert!(wrong.unprotect_request(option, ciphertext).is_err());

    assert!(receiver.unprotect_request(option, ciphertext).is_ok());
    assert_eq!(
        receiver.unprotect_request(option, ciphertext),
        Err(OscoreError::Replay)
    );

    let mut noncanonical = canonical.clone();
    noncanonical[22] |= 1;
    let mut sentinel = vec![0xa5; restored.len()];
    assert!(matches!(
        decompress(&noncanonical, &mut sentinel),
        Err(SchcError::NonCanonicalResidue(_))
    ));
    assert!(sentinel.iter().all(|byte| *byte == 0xa5));
}

#[test]
fn maximum_sender_sequence_crosses_rule5_once_then_exhausts() {
    let vector = &vectors().vectors[0];
    let mut store = Store::at(MAX_SEQUENCE);
    let mut sender = Context::new(
        &hex(&vector.master_secret).try_into().unwrap(),
        Some(&hex(&vector.master_salt)),
        None,
        &hex(&vector.sender_id),
        &hex(&vector.recipient_id),
    )
    .unwrap()
    .restore_existing(&mut store)
    .unwrap();
    let (ciphertext, option) = sender
        .reserve_sender(&mut store)
        .unwrap()
        .protect_request(
            vector.plaintext.code,
            &hex(&vector.plaintext.options),
            &hex(&vector.plaintext.payload),
        )
        .unwrap();
    assert_eq!(option[0] & 0x07, 5);
    assert!(sender.reserve_sender(&mut store).is_err());

    let packet = build_packet(&option, &ciphertext);
    let mut compressed = vec![0; packet.len() + 1];
    let compressed_len = compress(&packet, &mut compressed).unwrap();
    assert_eq!(compressed[0], 5);
    let mut restored = vec![0; packet.len()];
    let restored_len = decompress(&compressed[..compressed_len], &mut restored).unwrap();
    let (option, ciphertext) = extract_protected(&restored[..restored_len]);
    let mut receiver = context(vector, true, None);
    assert!(receiver.unprotect_request(option, ciphertext).is_ok());
}
