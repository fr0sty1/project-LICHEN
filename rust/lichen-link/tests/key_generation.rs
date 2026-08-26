// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

#![cfg(feature = "schnorr")]

//! Key-generation contract shared with the Python identity implementation.
//!
//! Randomness is supplied by the platform as an exact `[u8; 32]`; this keeps
//! the cryptographic core `no_std` and makes invalid seed lengths impossible to
//! pass to `Seed::new`.  Deterministic derivation is pinned to Appendix A of
//! `draft-lichen-schnorr-00`.

use lichen_link::identity::Identity;
use lichen_link::schnorr::{derive_keypair, sign, verify};
use lichen_link::{iid_from_pubkey, ygg_addr_from_pubkey, PublicKey, Seed};

// This type assertion is intentional: changing the constructor to accept an
// unchecked slice would weaken the compile-time invalid-length guarantee.
const EXACT_SEED_CONSTRUCTOR: fn([u8; 32]) -> Seed = Seed::new;
const EXACT_PUBLIC_KEY_CONSTRUCTOR: fn([u8; 32]) -> PublicKey = PublicKey::new;

#[test]
fn seed_constructor_requires_exactly_32_bytes() {
    let seed = EXACT_SEED_CONSTRUCTOR([0; 32]);
    assert_eq!(seed.as_bytes(), &[0; 32]);
}

#[test]
fn zero_seed_derives_appendix_a_keypair_deterministically() {
    let seed = Seed::new([0; 32]);
    let (private_a, public_a) = derive_keypair(&seed);
    let (private_b, public_b) = derive_keypair(&seed);

    assert_eq!(
        private_a.as_bytes(),
        &hex32("5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f156")
    );
    assert_eq!(
        public_a.as_bytes(),
        &hex32("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
    );
    assert_eq!(private_a.as_bytes(), private_b.as_bytes());
    assert_eq!(public_a, public_b);
}

#[test]
fn identity_key_is_the_schnorr_signing_key() {
    let seed_bytes = core::array::from_fn(|index| index as u8);
    let message = b"LICHEN identity signing-key binding v1";
    let identity = Identity::from_seed(Seed::new(seed_bytes));
    let (expected_private, expected_public) = derive_keypair(&Seed::new(seed_bytes));

    assert_eq!(identity.seed.as_bytes(), &seed_bytes);
    assert_eq!(identity.privkey.as_bytes(), expected_private.as_bytes());
    assert_eq!(identity.pubkey, expected_public);
    assert_eq!(identity.iid, iid_from_pubkey(&identity.pubkey));
    assert_eq!(
        identity.ygg_addr,
        ygg_addr_from_pubkey(identity.pubkey.as_bytes())
    );

    let signature = sign(&identity.privkey, &identity.pubkey, message);
    assert_eq!(
        signature,
        hex48(
            "e79cdb76ffbfb5d711fed7dddc5fc159f79885f1391c86780349a90193081746\
             a035cb23218db114d28236f44a002e07"
        )
    );
    assert_eq!(
        signature,
        sign(&identity.privkey, &identity.pubkey, message)
    );
    assert!(verify(&identity.pubkey, message, &signature));

    let other_seed = core::array::from_fn(|index| (31 - index) as u8);
    let other = Identity::from_seed(Seed::new(other_seed));
    assert!(!verify(&other.pubkey, message, &signature));

    let mismatched_signature = sign(&other.privkey, &identity.pubkey, message);
    assert_ne!(mismatched_signature, signature);
    assert!(!verify(&identity.pubkey, message, &mismatched_signature));
    assert!(!verify(&other.pubkey, message, &mismatched_signature));
}

#[test]
fn exported_public_key_is_owned_and_drives_both_addresses() {
    let identity = Identity::from_seed(Seed::new(core::array::from_fn(|index| index as u8)));
    let exported_public = identity.pubkey.into_bytes();
    drop(identity);

    assert_eq!(
        exported_public,
        hex32("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
    );

    // The owned export has no lifetime tie to `Identity`; reconstructing the
    // fixed-width public type preserves the exact address-derivation input.
    let public_key = EXACT_PUBLIC_KEY_CONSTRUCTOR(exported_public);
    assert_eq!(iid_from_pubkey(&public_key), hex8("ed4242ead4ac6948"));
    assert_eq!(
        ygg_addr_from_pubkey(public_key.as_bytes()),
        hex16("02ed4242ead4ac69ed4242ead4ac6948")
    );
}

#[test]
fn cold_starts_reconstruct_the_exact_same_identity_and_addresses() {
    let seed = core::array::from_fn(|index| index as u8);
    let first = cold_start(seed);
    // An unrelated derivation between starts proves reconstruction is not
    // selected from mutable process-global key or address state.
    let different = cold_start(core::array::from_fn(|index| (31 - index) as u8));
    let second = cold_start(seed);

    assert_eq!(first, second);
    assert_eq!(
        first,
        (
            hex32("3894eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6f"),
            hex32("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"),
            hex8("ed4242ead4ac6948"),
            hex16("fe80000000000000ed4242ead4ac6948"),
            hex16("02ed4242ead4ac69ed4242ead4ac6948"),
        )
    );
    assert_ne!(first.0, different.0);
    assert_ne!(first.1, different.1);
    assert_ne!(first.2, different.2);
    assert_ne!(first.3, different.3);
    assert_ne!(first.4, different.4);
}

type IdentitySnapshot = ([u8; 32], [u8; 32], [u8; 8], [u8; 16], [u8; 16]);

fn cold_start(seed: [u8; 32]) -> IdentitySnapshot {
    let identity = Identity::from_seed(Seed::new(seed));
    let mut link_local = [0; 16];
    link_local[..2].copy_from_slice(&[0xfe, 0x80]);
    link_local[8..].copy_from_slice(&identity.iid);
    (
        *identity.privkey.as_bytes(),
        identity.pubkey.into_bytes(),
        identity.iid,
        link_local,
        identity.ygg_addr,
    )
}

fn hex32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("fixed Appendix A hex");
    }
    bytes
}

fn hex48(value: &str) -> [u8; 48] {
    let compact: std::string::String = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert_eq!(compact.len(), 96);
    let mut bytes = [0; 48];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
            .expect("fixed identity signature hex");
    }
    bytes
}

fn hex8(value: &str) -> [u8; 8] {
    decode_hex(value)
}

fn hex16(value: &str) -> [u8; 16] {
    decode_hex(value)
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .expect("fixed identity export hex");
    }
    bytes
}
