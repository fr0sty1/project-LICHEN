// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_core::short_addr::{
    derive_short_addr, derive_short_addr_with_seed, is_reserved_short_addr, short_addr_from_iid,
    short_addr_to_iid,
};
use serde_json::Value;

const SHORT_ADDR_VECTORS: &str = include_str!("../../../test/vectors/short_addr_dad.json");
const CLARIFICATION_VECTORS: &str =
    include_str!("../../../test/vectors/dad_hash_clarification.json");
const IPV6_ADDRESS_VECTORS: &str = include_str!("../../../test/vectors/ipv6-addresses.json");
const LINK_ADDRESSING_VECTORS: &str = include_str!("../../../test/vectors/link-addressing.json");

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(
        value.len(),
        N * 2,
        "hex vector must contain exactly {N} bytes"
    );
    let mut decoded = [0u8; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .expect("vector must be hexadecimal");
    }
    decoded
}

fn decode_eui64(value: &str) -> [u8; 8] {
    decode_hex(value)
}

#[test]
fn canonical_derivation_vectors() {
    let document: Value =
        serde_json::from_str(SHORT_ADDR_VECTORS).expect("short-address vectors must parse");
    assert_eq!(document["format_version"], 2);

    let mut checked = 0;
    for vector in document["vectors"].as_array().expect("vectors array") {
        let (Some(eui64), Some(expected)) = (vector["eui64"].as_str(), vector["derived"].as_u64())
        else {
            continue;
        };
        assert_eq!(
            derive_short_addr(&decode_eui64(eui64)),
            expected as u16,
            "{}",
            vector["name"].as_str().expect("vector name")
        );
        checked += 1;
    }
    assert_eq!(
        checked, 6,
        "all canonical derivation vectors must be exercised"
    );
}

#[test]
fn canonical_seed_mixing_vectors() {
    let document: Value =
        serde_json::from_str(SHORT_ADDR_VECTORS).expect("short-address vectors must parse");
    let vector = document["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .find(|vector| vector["name"] == "seed_mixing_0011223344556677")
        .expect("seed-mixing vector");
    let eui64 = decode_eui64(vector["eui64"].as_str().expect("EUI-64"));

    for candidate in vector["seeds"].as_array().expect("seed candidates") {
        let seed = candidate["seed"].as_u64().expect("seed") as u32;
        let expected = candidate["addr"].as_u64().expect("address") as u16;
        assert_eq!(derive_short_addr_with_seed(&eui64, seed), expected);
    }
}

#[test]
fn authoritative_crc32_clarification_vectors() {
    let document: Value = serde_json::from_str(CLARIFICATION_VECTORS)
        .expect("DAD hash clarification vectors must parse");
    assert_eq!(document["format_version"], 2);
    assert_eq!(
        document["resolution"]["authoritative_algorithm"],
        "crc32_ieee"
    );

    let mut checked = 0;
    for vector in document["vectors"].as_array().expect("vectors array") {
        if vector["algorithm"] != "crc32_ieee" {
            continue;
        }
        let eui64 = decode_eui64(vector["eui64"].as_str().expect("EUI-64"));
        let expected = vector["derived_addr"].as_u64().expect("derived address") as u16;
        assert_eq!(
            derive_short_addr(&eui64),
            expected,
            "{}",
            vector["name"].as_str().expect("vector name")
        );
        checked += 1;
    }
    assert_eq!(
        checked, 2,
        "all authoritative clarification vectors must run"
    );
}

#[test]
fn canonical_short_address_iid_vectors() {
    let document: Value =
        serde_json::from_str(IPV6_ADDRESS_VECTORS).expect("IPv6 address vectors must parse");

    let mut checked = 0;
    for vector in document["vectors"].as_array().expect("vectors array") {
        let Some(short_addr) = vector["short_addr"].as_u64() else {
            continue;
        };
        let expected = decode_hex::<8>(vector["iid"].as_str().expect("IID hex"));
        let short_addr = short_addr as u16;

        assert_eq!(short_addr_to_iid(short_addr), expected);
        assert_eq!(short_addr_from_iid(&expected), Some(short_addr));
        assert_eq!(
            u16::from_be_bytes(decode_hex::<2>(
                vector["short_hex"].as_str().expect("short-address hex")
            )),
            short_addr
        );
        checked += 1;
    }
    assert_eq!(checked, 3, "all canonical short-IID vectors must run");
}

#[test]
fn reserved_short_address_vectors_are_well_formed_but_not_unicast() {
    let document: Value =
        serde_json::from_str(LINK_ADDRESSING_VECTORS).expect("link-addressing vectors must parse");

    let mut checked = 0;
    for vector in document["vectors"].as_array().expect("vectors array") {
        if vector["addr_mode_name"] != "SHORT" || vector["is_reserved"] != true {
            continue;
        }
        let wire = decode_hex::<2>(vector["dst_addr"].as_str().expect("destination hex"));
        let short_addr = u16::from_be_bytes(wire);
        let iid = short_addr_to_iid(short_addr);

        assert!(is_reserved_short_addr(short_addr));
        assert_eq!(short_addr_from_iid(&iid), Some(short_addr));
        assert!(vector["expected_destination"].is_null());
        assert_eq!(vector["expected_error"], "reserved short address");
        checked += 1;
    }
    assert_eq!(checked, 3, "all reserved short-address vectors must run");
}
