// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Canonical `ipv6-addresses.json` and `yggdrasil-derivation.json` consumers.
//!
//! Key-derived identities bind `fe80::/10` and native `0200::/8` to the same
//! SHA-512 IID. EUI-64 and short-address cases are link-interoperability
//! helpers, not node identities.

use lichen_core::addr::{iid_from_pubkey_bytes, ygg_addr_from_pubkey, Ipv6Addr, NodeId};
use lichen_core::short_addr::{short_addr_from_iid, short_addr_to_iid};
use serde_json::Value;

const IPV6_ADDRESS_VECTORS: &str = include_str!("../../../test/vectors/ipv6-addresses.json");
const YGG_DERIVATION_VECTORS: &str =
    include_str!("../../../test/vectors/yggdrasil-derivation.json");

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

fn ipv6_document() -> Value {
    serde_json::from_str(IPV6_ADDRESS_VECTORS).expect("ipv6-addresses.json must parse")
}

fn link_local_from_iid(iid: &[u8; 8]) -> [u8; 16] {
    let mut packed = [0u8; 16];
    packed[0] = 0xfe;
    packed[1] = 0x80;
    packed[8..].copy_from_slice(iid);
    packed
}

#[test]
fn key_derived_identity_binds_link_local_and_native() {
    let document = ipv6_document();
    assert_eq!(document["format_version"], 2);

    let mut checked = 0;
    for vector in document["vectors"].as_array().expect("vectors array") {
        if vector["profile"] != "key_derived_identity" {
            continue;
        }
        let name = vector["name"].as_str().expect("vector name");
        let pubkey = decode_hex::<32>(vector["pubkey"].as_str().expect("pubkey"));
        let expected_iid = decode_hex::<8>(vector["iid"].as_str().expect("iid"));
        let expected_native = decode_hex::<16>(vector["native_packed"].as_str().expect("native"));
        let expected_link_local =
            decode_hex::<16>(vector["link_local_packed"].as_str().expect("link-local"));

        let iid = iid_from_pubkey_bytes(&pubkey);
        let native = ygg_addr_from_pubkey(&pubkey);
        let link_local = link_local_from_iid(&iid);

        assert_eq!(iid, expected_iid, "{name}");
        assert_eq!(native, expected_native, "{name}");
        assert_eq!(link_local, expected_link_local, "{name}");
        assert_eq!(
            &native[8..],
            &iid[..],
            "{name}: native lower-64 must equal IID"
        );
        assert_eq!(native[0], 0x02, "{name}: 0200::/8 prefix");
        assert_eq!(iid[0] & 0x02, 0, "{name}: U/L bit must be clear");
        assert_eq!(&link_local[8..], &iid[..], "{name}: fe80 IID");
        assert!(Ipv6Addr(link_local).is_link_local(), "{name}");
        assert_eq!(
            vector["iid_in_native"], true,
            "{name}: corpus records the binding"
        );
        checked += 1;
    }
    assert_eq!(checked, 5, "all key-derived identity vectors must run");
}

#[test]
fn eui64_link_local_interoperability_vectors() {
    let document = ipv6_document();
    let mut checked = 0;
    for vector in document["vectors"].as_array().expect("vectors array") {
        let Some(eui64_hex) = vector["eui64"].as_str() else {
            continue;
        };
        let name = vector["name"].as_str().expect("vector name");
        let eui64 = decode_hex::<8>(eui64_hex);
        let expected_iid = decode_hex::<8>(vector["iid"].as_str().expect("iid"));
        let expected_link_local =
            decode_hex::<16>(vector["link_local_packed"].as_str().expect("link-local"));

        let from_node = NodeId(eui64).link_local_addr();
        let from_addr = Ipv6Addr::link_local_from_eui64(&eui64);
        assert_eq!(from_node, from_addr, "{name}");
        assert_eq!(from_node.0, expected_link_local, "{name}");
        assert_eq!(from_node.iid(), expected_iid, "{name}");
        assert!(from_node.is_link_local(), "{name}");
        checked += 1;
    }
    assert_eq!(checked, 3, "all EUI-64 interoperability vectors must run");
}

#[test]
fn short_address_rfc4944_iid_vectors() {
    let document = ipv6_document();
    let mut checked = 0;
    for vector in document["vectors"].as_array().expect("vectors array") {
        let Some(short_addr) = vector["short_addr"].as_u64() else {
            continue;
        };
        let name = vector["name"].as_str().expect("vector name");
        let short_addr = short_addr as u16;
        let expected = decode_hex::<8>(vector["iid"].as_str().expect("iid"));
        assert_eq!(short_addr_to_iid(short_addr), expected, "{name}");
        assert_eq!(short_addr_from_iid(&expected), Some(short_addr), "{name}");
        checked += 1;
    }
    assert_eq!(checked, 3, "all short-address IID vectors must run");
}

#[test]
fn yggdrasil_derivation_corpus_matches_native_profile() {
    let entries: Vec<Value> =
        serde_json::from_str(YGG_DERIVATION_VECTORS).expect("yggdrasil-derivation.json must parse");

    let mut positive = 0;
    let mut binding = 0;
    let mut negative = 0;
    for entry in entries {
        if entry["test_type"] == "negative" {
            let attacker =
                decode_hex::<32>(entry["attacker_pubkey"].as_str().expect("attacker pubkey"));
            let victim = decode_hex::<8>(entry["victim_iid"].as_str().expect("victim iid"));
            assert_ne!(
                iid_from_pubkey_bytes(&attacker),
                victim,
                "attacker pubkey must not derive victim IID"
            );
            negative += 1;
            continue;
        }
        if entry["test_type"] == "binding_invariant" {
            let pubkey = decode_hex::<32>(entry["pubkey"].as_str().expect("pubkey"));
            let addr = ygg_addr_from_pubkey(&pubkey);
            let iid = iid_from_pubkey_bytes(&pubkey);
            assert_eq!(&addr[8..], &iid[..]);
            assert_eq!(addr[0], 0x02);
            binding += 1;
            continue;
        }
        let pubkey = decode_hex::<32>(entry["pubkey"].as_str().expect("pubkey"));
        let addr = ygg_addr_from_pubkey(&pubkey);
        let iid = iid_from_pubkey_bytes(&pubkey);
        if let Some(expected) = entry["ygg_addr"].as_str() {
            assert_eq!(addr, decode_hex::<16>(expected));
        }
        if let Some(expected) = entry["iid"].as_str() {
            assert_eq!(iid, decode_hex::<8>(expected));
        }
        assert_eq!(&addr[8..], &iid[..]);
        assert_eq!(addr[0], 0x02);
        positive += 1;
    }
    assert!(positive >= 4, "positive derivation entries must run");
    assert_eq!(binding, 1, "binding-invariant entry must run");
    assert_eq!(negative, 1, "negative attack entry must run");
}
