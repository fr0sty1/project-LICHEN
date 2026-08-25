//! Tests against the shared corpus in test/vectors/yggdrasil_address.json.
//!
//! Three entry kinds (see the `profile` discriminator):
//! 1. `lichen_native_sha512` — driven byte-exact through
//!    [`ygg_addr_from_pubkey`] / [`iid_from_pubkey_bytes`], including the
//!    IID binding invariant.
//! 2. The single upstream yggdrasil-go anchor (`upstream_addr_for_key`).
//!    Upstream bit-packs the inverted key with no hash, so it is intentionally
//!    NOT reproducible by the LICHEN native SHA-512 profile; the test asserts
//!    that documented divergence instead of equality.
//! 3. `error_case` length rejections — not expressible here because the Rust
//!    API takes `&[u8; 32]`, which enforces key length at the type level.

use serde_json::Value;

const VECTORS_JSON: &str = include_str!("../../../test/vectors/yggdrasil_address.json");

const ANCHOR_NAME: &str = "upstream_addr_for_key";
const ANCHOR_ADDRESS: [u8; 16] = [
    0x02, 0x00, 0x84, 0x8a, 0x60, 0x4f, 0xbb, 0x7e, 0x43, 0x84, 0x65, 0xdb, 0x8d, 0xb6, 0x68, 0x95,
];

fn load_document() -> Value {
    serde_json::from_str(VECTORS_JSON).expect("yggdrasil_address.json must parse")
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0, "odd-length hex: {value}");
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn native_vectors<'a>(document: &'a Value) -> Vec<&'a Value> {
    document["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .filter(|v| v["profile"] == "lichen_native_sha512")
        .collect()
}

#[test]
fn corpus_shape() {
    let document = load_document();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(native_vectors(&document).len() >= 10);
    assert_eq!(
        vectors.iter().filter(|v| v["name"] == ANCHOR_NAME).count(),
        1,
        "exactly one upstream anchor expected"
    );
    assert!(
        vectors.iter().any(|v| v["expect_error"] == "pubkey_length"),
        "length-rejection cases expected"
    );
}

#[test]
fn lichen_native_vectors_byte_exact() {
    for vector in native_vectors(&load_document()) {
        let name = vector["name"].as_str().unwrap();
        let pubkey_vec = decode_hex(vector["public_key"].as_str().unwrap());
        let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
        let expected = decode_hex(vector["address"].as_str().unwrap());

        let addr = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
        assert_eq!(&addr[..], &expected[..], "{name}");

        let iid = lichen_core::addr::iid_from_pubkey_bytes(&pubkey);
        assert_eq!(
            &addr[8..16],
            &iid[..],
            "{name}: lower 64 bits must equal IID"
        );
        assert_eq!(addr[0], 0x02, "{name}: 0200::/8 prefix byte");
        assert_eq!(iid[0] & 0x02, 0, "{name}: U/L bit must be clear in IID");
    }
}

#[test]
fn upstream_anchor_diverges_from_lichen_native_profile() {
    // Upstream AddrForKey never hashes the key; LICHEN derives from SHA-512.
    // Pin the difference so neither side is changed by accident. Constants are
    // from upstream address_test.go @422836ee (external oracle).
    let document = load_document();
    let anchor = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == ANCHOR_NAME)
        .expect("anchor present");
    let expected = decode_hex(anchor["address"].as_str().unwrap());
    assert_eq!(&expected[..], &ANCHOR_ADDRESS[..]);

    let pubkey_vec = decode_hex(anchor["public_key"].as_str().unwrap());
    let pubkey: [u8; 32] = pubkey_vec.try_into().expect("32-byte key");
    let derived = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
    assert_ne!(&derived[..], &ANCHOR_ADDRESS[..]);
    assert_eq!(derived[0], ANCHOR_ADDRESS[0], "only the prefix byte agrees");
}
