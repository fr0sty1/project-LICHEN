// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Consume committed LOADng JSON vectors through the public codecs.

use lichen_core::addr::Ipv6Addr;
use lichen_core::loadng::{seq_is_fresher, Rerr, RerrCode, Rrep, Rreq};
use serde_json::Value;

const SEQ_JSON: &str = include_str!("../../../test/vectors/loadng.json");
const MSG_JSON: &str = include_str!("../../../test/vectors/loadng_messages.json");

const RREQ_RREP_LEN: usize = 36;
const RERR_LEN: usize = 18;
const SIGNATURE_LEN: usize = 48;

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "odd-length hex: {value}");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn ipv6(value: &str) -> Ipv6Addr {
    Ipv6Addr(value.parse::<core::net::Ipv6Addr>().unwrap().octets())
}

#[test]
fn loadng_seq_freshness_vectors() {
    let document: Value = serde_json::from_str(SEQ_JSON).unwrap();
    assert_eq!(document["format_version"], 2);
    let mut executed = 0;
    for vector in document["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let a = vector["a"].as_u64().unwrap() as u16;
        let b = vector["b"].as_u64().unwrap() as u16;
        let expected = vector["b_fresher"].as_bool().unwrap();
        assert_eq!(
            seq_is_fresher(a, b),
            expected,
            "{name}: seq_is_fresher({a}, {b})"
        );
        executed += 1;
    }
    assert!(
        executed >= 16,
        "expected the committed freshness corpus, got {executed}"
    );
}

#[test]
fn loadng_message_vectors() {
    let document: Value = serde_json::from_str(MSG_JSON).unwrap();
    assert_eq!(document["format_version"], 2);
    let mut rreq = 0;
    let mut rrep = 0;
    let mut rerr = 0;
    for vector in document["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let encoded = decode_hex(vector["encoded"].as_str().unwrap());
        let fields = &vector["fields"];
        match vector["type"].as_str().unwrap() {
            "rreq" => {
                assert_body_len(name, encoded.len(), RREQ_RREP_LEN);
                let parsed = Rreq::from_bytes(&encoded)
                    .unwrap_or_else(|e| panic!("{name}: rreq parse failed: {e}"));
                assert_eq!(
                    parsed.flags,
                    fields["flags"].as_u64().unwrap() as u8,
                    "{name}"
                );
                assert_eq!(
                    parsed.hop_limit,
                    fields["hop_limit"].as_u64().unwrap() as u8,
                    "{name}"
                );
                assert_eq!(
                    parsed.seq_num,
                    fields["seq_num"].as_u64().unwrap() as u16,
                    "{name}"
                );
                assert_eq!(
                    parsed.originator,
                    ipv6(fields["originator"].as_str().unwrap()),
                    "{name}"
                );
                assert_eq!(
                    parsed.destination,
                    ipv6(fields["destination"].as_str().unwrap()),
                    "{name}"
                );
                let mut out = [0u8; RREQ_RREP_LEN];
                let n = parsed.write_to(&mut out).unwrap();
                assert_eq!(&out[..n], &encoded[..RREQ_RREP_LEN], "{name}: encode");
                rreq += 1;
            }
            "rrep" => {
                assert_body_len(name, encoded.len(), RREQ_RREP_LEN);
                let parsed = Rrep::from_bytes(&encoded)
                    .unwrap_or_else(|e| panic!("{name}: rrep parse failed: {e}"));
                assert_eq!(
                    parsed.flags,
                    fields["flags"].as_u64().unwrap() as u8,
                    "{name}"
                );
                assert_eq!(
                    parsed.hop_count,
                    fields["hop_count"].as_u64().unwrap() as u8,
                    "{name}"
                );
                assert_eq!(
                    parsed.seq_num,
                    fields["seq_num"].as_u64().unwrap() as u16,
                    "{name}"
                );
                assert_eq!(
                    parsed.originator,
                    ipv6(fields["originator"].as_str().unwrap()),
                    "{name}"
                );
                assert_eq!(
                    parsed.destination,
                    ipv6(fields["destination"].as_str().unwrap()),
                    "{name}"
                );
                let mut out = [0u8; RREQ_RREP_LEN];
                let n = parsed.write_to(&mut out).unwrap();
                assert_eq!(&out[..n], &encoded[..RREQ_RREP_LEN], "{name}: encode");
                rrep += 1;
            }
            "rerr" => {
                assert_body_len(name, encoded.len(), RERR_LEN);
                let parsed = Rerr::from_bytes(&encoded)
                    .unwrap_or_else(|e| panic!("{name}: rerr parse failed: {e}"));
                assert_eq!(
                    parsed.flags,
                    fields["flags"].as_u64().unwrap() as u8,
                    "{name}"
                );
                assert_eq!(
                    u8::from(parsed.error_code),
                    fields["error_code"].as_u64().unwrap() as u8,
                    "{name}"
                );
                assert_eq!(
                    parsed.unreachable,
                    ipv6(fields["unreachable"].as_str().unwrap()),
                    "{name}"
                );
                match fields["error_code"].as_u64().unwrap() {
                    0 => assert_eq!(parsed.error_code, RerrCode::Unspecified, "{name}"),
                    1 => assert_eq!(parsed.error_code, RerrCode::NoRoute, "{name}"),
                    other => {
                        assert_eq!(parsed.error_code, RerrCode::Other(other as u8), "{name}")
                    }
                }
                let mut out = [0u8; RERR_LEN];
                let n = parsed.write_to(&mut out).unwrap();
                assert_eq!(&out[..n], &encoded[..RERR_LEN], "{name}: encode");
                rerr += 1;
            }
            other => panic!("{name}: unknown type {other}"),
        }
    }
    assert!(rreq >= 7, "expected RREQ corpus, got {rreq}");
    assert!(rrep >= 5, "expected RREP corpus, got {rrep}");
    assert!(rerr >= 5, "expected RERR corpus, got {rerr}");
}

fn assert_body_len(name: &str, got: usize, body: usize) {
    assert!(
        got == body || got == body + SIGNATURE_LEN,
        "{name}: encoded length {got} is not {body} or {}",
        body + SIGNATURE_LEN
    );
}
