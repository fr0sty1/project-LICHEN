// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_gateway::trust::{
    build_identity_proof_transcript, iid_from_pubkey, GatewayChallengeIssuer,
    GatewayIdentityPresentation, TofuResult, TrustError, TrustStore, VerifiedGatewayIdentity,
};
use lichen_link::keys::Seed;
use schnorr48::{derive_keypair, sign};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static PATH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
struct Document {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    pubkey_hex: String,
    iid_hex: String,
    repetitions: usize,
    concurrent_observers: usize,
    snapshot_generation: Option<u64>,
    minimum_generation: Option<u64>,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    result: String,
    entry_count: usize,
    state_unchanged: bool,
    durable_commits: Option<usize>,
}

fn document() -> Document {
    serde_json::from_str(include_str!("../../../test/vectors/tofu_edge_cases.json")).unwrap()
}

fn vector<'a>(document: &'a Document, name: &str) -> &'a Vector {
    document
        .vectors
        .iter()
        .find(|case| case.name == name)
        .unwrap()
}

fn fixed<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn verified(seed: [u8; 32]) -> VerifiedGatewayIdentity {
    let (private, public) = derive_keypair(&Seed::new(seed));
    let pubkey = *public.as_bytes();
    let iid = iid_from_pubkey(&pubkey);
    let session = [0x71; 32];
    let mut issuer = GatewayChallengeIssuer::new([0x72; 32], 1).unwrap();
    let authority = issuer.issue(iid, session, 10, 100).unwrap();
    let challenge = *authority.challenge();
    let signature = sign(
        &private,
        &public,
        &build_identity_proof_transcript(&iid, &challenge),
    );
    issuer
        .verify_identity(
            authority,
            &session,
            11,
            GatewayIdentityPresentation {
                pubkey: &pubkey,
                claimed_iid: &iid,
                challenge: &challenge,
                signature: &signature,
            },
        )
        .unwrap()
}

fn store_path(label: &str) -> PathBuf {
    let sequence = PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "lichen-tofu-edge-{label}-{}-{sequence}.bin",
        std::process::id()
    ))
}

#[test]
fn canonical_contacts_drive_rust_tofu_store() {
    let document = document();
    let alice = verified([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ]);
    let bob = verified([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2,
    ]);
    let first = vector(&document, "first_contact");
    assert_eq!(alice.pubkey(), &fixed::<32>(&first.pubkey_hex));
    assert_eq!(alice.iid(), &fixed::<8>(&first.iid_hex));

    let mut store = TrustStore::new_ephemeral(4).unwrap();
    assert_eq!(store.verify_tofu(&alice).unwrap(), TofuResult::PinAndAccept);
    assert_eq!(store.len(), first.expected.entry_count);

    let repeat = vector(&document, "idempotent_repeat");
    for _ in 0..repeat.repetitions {
        assert_eq!(store.verify_tofu(&alice).unwrap(), TofuResult::AcceptKnown);
    }
    assert!(repeat.expected.state_unchanged);
    assert_eq!(store.len(), repeat.expected.entry_count);

    let independent = vector(&document, "independent_peer");
    assert_eq!(bob.pubkey(), &fixed::<32>(&independent.pubkey_hex));
    assert_eq!(bob.iid(), &fixed::<8>(&independent.iid_hex));
    assert_eq!(store.verify_tofu(&bob).unwrap(), TofuResult::PinAndAccept);
    assert_eq!(store.len(), independent.expected.entry_count);
}

#[test]
fn malformed_and_conflict_vectors_fail_before_mutation() {
    let document = document();
    for name in [
        "malformed_pubkey_short",
        "malformed_pubkey_long",
        "malformed_iid_short",
        "malformed_iid_long",
    ] {
        let case = vector(&document, name);
        assert!(
            hex::decode(&case.pubkey_hex).unwrap().len() != 32
                || hex::decode(&case.iid_hex).unwrap().len() != 8
        );
        assert_eq!(case.expected.result, "reject_malformed");
        assert!(case.expected.state_unchanged);
    }

    let mismatch = vector(&document, "derivation_mismatch");
    let pubkey = fixed::<32>(&mismatch.pubkey_hex);
    let iid = fixed::<8>(&mismatch.iid_hex);
    assert_ne!(iid_from_pubkey(&pubkey), iid);
    assert_eq!(mismatch.expected.entry_count, 0);

    let alice = verified([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ]);
    let mut store = TrustStore::new_ephemeral(4).unwrap();
    store.verify_tofu(&alice).unwrap();
    let before = store.generation();
    let replay = vector(&document, "replayed_collision");
    for _ in 0..replay.repetitions {
        assert_ne!(
            iid_from_pubkey(&fixed::<32>(&replay.pubkey_hex)),
            fixed::<8>(&replay.iid_hex)
        );
    }
    assert_eq!(store.generation(), before);
    assert_eq!(store.len(), replay.expected.entry_count);
}

#[test]
fn reboot_and_rollback_vectors_drive_sealed_store() {
    let document = document();
    let alice = verified([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ]);
    let mut store = TrustStore::new_ephemeral(4).unwrap();
    store.verify_tofu(&alice).unwrap();
    let path = store_path("restore");
    let sealing_seed = [0x75; 32];
    store.save_atomic(&path, &sealing_seed).unwrap();

    let reboot = vector(&document, "reboot_restore");
    let loaded =
        TrustStore::load(&path, &sealing_seed, reboot.minimum_generation.unwrap(), 4).unwrap();
    assert_eq!(loaded.len(), reboot.expected.entry_count);

    let rollback = vector(&document, "rollback_snapshot_rejected");
    assert!(rollback.snapshot_generation.unwrap() < rollback.minimum_generation.unwrap());
    assert!(matches!(
        TrustStore::load(&path, &sealing_seed, store.generation() + 1, 4),
        Err(TrustError::RollbackDetected { .. })
    ));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn concurrency_vector_requires_one_serialized_pin() {
    let document = document();
    let case = vector(&document, "concurrent_first_contact");
    let alice = verified([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ]);
    let mut store = TrustStore::new_ephemeral(4).unwrap();
    let results: Vec<_> = (0..case.concurrent_observers)
        .map(|_| store.verify_tofu(&alice).unwrap())
        .collect();
    assert_eq!(results, [TofuResult::PinAndAccept, TofuResult::AcceptKnown]);
    assert_eq!(store.len(), case.expected.entry_count);
    assert_eq!(case.expected.durable_commits, Some(1));
}
