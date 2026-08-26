// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Canonical `ipv6-icmpv6.json` checksum consumers (RFC 4443 section 2.3).

use lichen_core::addr::Ipv6Addr;
use lichen_core::icmpv6::{checksum_valid, echo_reply, echo_request, ECHO_REPLY, ECHO_REQUEST};
use lichen_core::ipv6::IPV6_HEADER_LEN;
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/ipv6-icmpv6.json");

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn vectors() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS_JSON).expect("parse");
    document["vectors"].as_array().expect("vectors").clone()
}

#[test]
fn canonical_icmpv6_wires_have_valid_checksums() {
    for vector in vectors() {
        let name = vector["name"].as_str().unwrap();
        let wire = hex_decode(vector["wire"].as_str().unwrap());
        assert!(wire.len() >= IPV6_HEADER_LEN + 4, "{name}");
        let src = Ipv6Addr(wire[8..24].try_into().unwrap());
        let dst = Ipv6Addr(wire[24..40].try_into().unwrap());
        let icmpv6 = &wire[IPV6_HEADER_LEN..];
        assert_eq!(
            icmpv6[0],
            vector["icmp_type"].as_u64().unwrap() as u8,
            "{name}"
        );
        assert!(checksum_valid(&src, &dst, icmpv6), "{name} valid");
        let mut corrupted = icmpv6.to_vec();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xff;
        assert!(!checksum_valid(&src, &dst, &corrupted), "{name} corrupt");
        assert!(
            !checksum_valid(&src, &dst, &icmpv6[..3]),
            "{name} truncated"
        );
    }
}

#[test]
fn echo_builders_match_canonical_wires() {
    for vector in vectors() {
        let icmp_type = vector["icmp_type"].as_u64().unwrap() as u8;
        if icmp_type != ECHO_REQUEST && icmp_type != ECHO_REPLY {
            continue;
        }
        let name = vector["name"].as_str().unwrap();
        let wire = hex_decode(vector["wire"].as_str().unwrap());
        let src = Ipv6Addr(wire[8..24].try_into().unwrap());
        let dst = Ipv6Addr(wire[24..40].try_into().unwrap());
        let id = vector["identifier"].as_u64().unwrap() as u16;
        let seq = vector["sequence"].as_u64().unwrap() as u16;
        let data = hex_decode(vector["data"].as_str().unwrap());
        let mut buf = vec![0u8; IPV6_HEADER_LEN + 8 + data.len()];
        let n = if icmp_type == ECHO_REQUEST {
            echo_request(&src, &dst, id, seq, &data, &mut buf)
        } else {
            echo_reply(&src, &dst, id, seq, &data, &mut buf)
        };
        assert_eq!(n, wire.len(), "{name}");
        assert_eq!(&buf[..n], wire.as_slice(), "{name}");
    }
}
