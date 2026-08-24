use std::{fs, path::Path};

use lichen_link::{keys::PublicKey, schnorr};
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<RootAuthorizationVector>,
}

#[derive(Deserialize)]
struct RootAuthorizationVector {
    name: String,
    pubkey_hex: String,
    message_hex: String,
    signature_hex: String,
    dodagid_hex: String,
    expected_valid: bool,
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn root_authorization_vectors_bind_signer_key_to_dodagid() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/root_authorization.json");
    let vectors: VectorFile = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    for vector in vectors.vectors {
        let pubkey = hex(&vector.pubkey_hex);
        let message = hex(&vector.message_hex);
        let signature = hex(&vector.signature_hex);
        let dodag_id = hex(&vector.dodagid_hex);
        let actual = match (
            <[u8; 32]>::try_from(pubkey.as_slice()),
            <[u8; 48]>::try_from(signature.as_slice()),
            <[u8; 16]>::try_from(dodag_id.as_slice()),
        ) {
            (Ok(pubkey), Ok(signature), Ok(dodag_id)) => {
                let key = PublicKey::new(pubkey);
                lichen_link::ygg_addr_from_pubkey(&pubkey) == dodag_id
                    && schnorr::verify(&key, &message, &signature)
            }
            _ => false,
        };
        assert_eq!(actual, vector.expected_valid, "{}", vector.name);
    }
}
