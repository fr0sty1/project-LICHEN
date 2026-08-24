use std::{fs, path::Path};

use lichen_link::{
    identity::{Identity, PeerIdentity},
    keys::Seed,
    link_layer::LinkLayer,
};
use lichen_schc::{AuthenticatedPeerSchcContext, ExpectedDioRole};
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<AuthenticatedDioVector>,
}

#[derive(Deserialize)]
struct AuthenticatedDioVector {
    name: String,
    sender_seed_hex: String,
    sender_pubkey_hex: String,
    receiver_seed_hex: String,
    receiver_pubkey_hex: String,
    wire_hex: String,
    expected_rpl_instance_id: u8,
    expected_dodag_id_hex: String,
    expected_mop: u8,
    expected_role: String,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    admitted: bool,
    compatible: Option<bool>,
    error: Option<String>,
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn authenticated_dio_vectors_drive_production_admission() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/vectors/authenticated_schc_dio.json");
    let corpus: VectorFile = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    for vector in corpus.vectors {
        let sender_seed: [u8; 32] = hex(&vector.sender_seed_hex).try_into().unwrap();
        let receiver_seed: [u8; 32] = hex(&vector.receiver_seed_hex).try_into().unwrap();
        let sender = Identity::from_seed(Seed::new(sender_seed));
        let receiver_identity = Identity::from_seed(Seed::new(receiver_seed));
        assert_eq!(
            sender.pubkey.as_bytes().as_slice(),
            hex(&vector.sender_pubkey_hex)
        );
        assert_eq!(
            receiver_identity.pubkey.as_bytes().as_slice(),
            hex(&vector.receiver_pubkey_hex)
        );
        let mut receiver = LinkLayer::new(receiver_identity);
        receiver.add_peer(PeerIdentity::from_pubkey(sender.pubkey));
        let frame = receiver.receive_frame(&hex(&vector.wire_hex)).unwrap();
        let dodag_id: [u8; 16] = hex(&vector.expected_dodag_id_hex).try_into().unwrap();
        let role = match vector.expected_role.as_str() {
            "root" => ExpectedDioRole::Root,
            "peer" => ExpectedDioRole::Peer,
            other => panic!("unknown role {other}"),
        };
        let result = AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
            frame,
            vector.expected_rpl_instance_id,
            &dodag_id,
            vector.expected_mop,
            role,
        );
        assert_eq!(result.is_ok(), vector.expected.admitted, "{}", vector.name);
        match result {
            Ok(peer) => {
                assert_eq!(
                    Some(peer.allows_dodag_join()),
                    vector.expected.compatible,
                    "{}",
                    vector.name
                );
                assert_eq!(
                    vector.expected.error.as_deref(),
                    if peer.allows_dodag_join() {
                        None
                    } else {
                        Some("incompatible_rule_version")
                    },
                    "{}",
                    vector.name
                );
            }
            Err(_) => assert!(vector.expected.error.is_some(), "{}", vector.name),
        }
    }
}
