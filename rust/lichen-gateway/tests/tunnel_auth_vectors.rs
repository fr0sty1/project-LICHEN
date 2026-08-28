// SPDX-License-Identifier: GPL-3.0-only

use lichen_gateway::tunnel_auth::{
    build_root_post, route_hash, AuthenticatedRoot, DecapsulationRequest, TunnelAuthError,
    TunnelAuthorization, TunnelAuthorizationTable, TunnelDirection,
};
use schnorr48::{derive_keypair, PublicKey, Seed};
use serde_json::Value;
use std::net::Ipv6Addr;

fn bytes<const N: usize>(hex_value: &str) -> [u8; N] {
    hex::decode(hex_value).unwrap().try_into().unwrap()
}

fn named<'a>(corpus: &'a Value, section: &str, name: &str) -> &'a Value {
    corpus[section]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap()
}

fn identity(corpus: &Value, name: &str) -> ([u8; 8], PublicKey) {
    let value = named(corpus, "identities", name);
    (
        bytes(value["iid_hex"].as_str().unwrap()),
        PublicKey::new(bytes(value["public_key_hex"].as_str().unwrap())),
    )
}

fn denial(error: TunnelAuthError) -> &'static str {
    match error {
        TunnelAuthError::MalformedCbor
        | TunnelAuthError::NonCanonicalCbor
        | TunnelAuthError::InvalidPrefix => "malformed",
        TunnelAuthError::UnsupportedAlgorithm => "algorithm",
        TunnelAuthError::MissingOscoreAuthentication => "oscore-required",
        TunnelAuthError::WrongRoot => "wrong-root",
        TunnelAuthError::RootIdentityMismatch => "key-binding",
        TunnelAuthError::WrongEgress => "wrong-egress",
        TunnelAuthError::InvalidRoute => "invalid-route",
        TunnelAuthError::WrongDirection => "wrong-direction",
        TunnelAuthError::SourceOutsideMesh => "source-scope",
        TunnelAuthError::DestinationInMesh => "destination-scope",
        TunnelAuthError::Expired => "expired",
        TunnelAuthError::ClockRollback => "clock-regression",
        TunnelAuthError::Replay => "replay",
        TunnelAuthError::Revoked => "revoked",
        TunnelAuthError::InvalidSignature => "signature",
        TunnelAuthError::UnauthorizedTunnel => "no-authorization",
        TunnelAuthError::BufferTooSmall | TunnelAuthError::TableDisabled => "capacity",
    }
}

fn claim(value: &Value) -> TunnelAuthorization {
    TunnelAuthorization::new(
        bytes(value["prefix_hex"].as_str().unwrap()),
        value["prefix_len"].as_u64().unwrap() as u8,
        bytes(value["route_hash_hex"].as_str().unwrap()),
        value["path_seq"].as_u64().unwrap(),
        value["expiry"].as_u64().unwrap(),
        bytes(value["egress_iid_hex"].as_str().unwrap()),
    )
    .unwrap()
}

fn apply_setup(
    table: &mut TunnelAuthorizationTable<4>,
    corpus: &Value,
    setup: &[Value],
    own_iid: [u8; 8],
) {
    for action in setup {
        match action["action"].as_str().unwrap() {
            "receive" => {
                let message = named(
                    corpus,
                    "authorizations",
                    action["message"].as_str().unwrap(),
                );
                let wire = hex::decode(message["cose_sign1_hex"].as_str().unwrap()).unwrap();
                let (sender_iid, sender_key) = identity(corpus, action["sender"].as_str().unwrap());
                table
                    .accept_post(
                        &wire,
                        AuthenticatedRoot {
                            iid: sender_iid,
                            public_key: &sender_key,
                            oscore_authenticated: true,
                        },
                        own_iid,
                        action["now"].as_u64().unwrap(),
                    )
                    .unwrap();
            }
            "revoke" => {
                let message = named(
                    corpus,
                    "authorizations",
                    action["message"].as_str().unwrap(),
                );
                let claim = claim(message);
                table
                    .revoke(
                        claim.prefix,
                        claim.prefix_len,
                        claim.route_hash,
                        action["through_path_seq"].as_u64().unwrap(),
                    )
                    .unwrap();
            }
            "change_root" => {
                table.set_root(identity(corpus, action["identity"].as_str().unwrap()).0);
            }
            action => panic!("unsupported setup action {action}"),
        }
    }
}

#[test]
fn canonical_tunnel_authorization_vector_matches_byte_for_byte() {
    let corpus: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/tunnel_authorization.json"
    )))
    .unwrap();
    let vector = named(&corpus, "authorizations", "valid");

    let seed = Seed::new(bytes(vector["root_seed_hex"].as_str().unwrap()));
    let (private_key, public_key) = derive_keypair(&seed);
    assert_eq!(
        public_key.as_bytes(),
        &bytes::<32>(vector["root_public_key_hex"].as_str().unwrap())
    );
    let root_iid = bytes(vector["root_iid_hex"].as_str().unwrap());
    let egress_iid = bytes(vector["egress_iid_hex"].as_str().unwrap());
    let route: Vec<[u8; 8]> = vector["route_hops_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hop| bytes(hop.as_str().unwrap()))
        .collect();
    assert_eq!(
        route_hash(&route).unwrap(),
        bytes::<16>(vector["route_hash_hex"].as_str().unwrap())
    );

    let claim = claim(vector);
    let post = build_root_post(claim, &route, root_iid, &private_key, &public_key).unwrap();
    let canonical_wire = hex::decode(vector["cose_sign1_hex"].as_str().unwrap()).unwrap();
    assert_eq!(post.body.as_bytes(), canonical_wire);

    let now = corpus["constants"]["evaluation_time"].as_u64().unwrap();
    let mut table = TunnelAuthorizationTable::<4>::default();
    table.set_root(root_iid);
    assert_eq!(
        table.accept_post(
            &canonical_wire,
            AuthenticatedRoot {
                iid: root_iid,
                public_key: &public_key,
                oscore_authenticated: true,
            },
            egress_iid,
            now,
        ),
        Ok(claim)
    );
    assert_eq!(
        table.authorize_decapsulation(
            DecapsulationRequest {
                direction: TunnelDirection::MeshToExternal,
                inner_source: claim.prefix,
                source_is_mesh: true,
                destination_is_mesh: false,
                route: &route,
            },
            now,
        ),
        Ok(())
    );
}

#[test]
fn canonical_direct_post_cases_fail_closed() {
    let corpus: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/tunnel_authorization.json"
    )))
    .unwrap();
    let own_iid = identity(&corpus, "egress").0;

    for case in corpus["post_cases"].as_array().unwrap() {
        let active_root = case["active_root"].as_str().unwrap();
        let (active_iid, _) = identity(&corpus, active_root);
        let mut table = TunnelAuthorizationTable::<4>::default();
        table.set_root(active_iid);
        apply_setup(
            &mut table,
            &corpus,
            case["setup"].as_array().unwrap(),
            own_iid,
        );
        let sender = case["oscore_sender"].as_str().unwrap();
        let (sender_iid, sender_key) = identity(&corpus, sender);
        let message = named(&corpus, "authorizations", case["message"].as_str().unwrap());
        let wire = hex::decode(message["cose_sign1_hex"].as_str().unwrap()).unwrap();
        let result = table.accept_post(
            &wire,
            AuthenticatedRoot {
                iid: sender_iid,
                public_key: &sender_key,
                oscore_authenticated: case["oscore_authenticated"].as_bool().unwrap(),
            },
            own_iid,
            case["now"].as_u64().unwrap(),
        );
        let expected = &case["expected"];
        assert_eq!(
            result.is_ok(),
            expected["allowed"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        match result {
            Ok(_) => {
                assert_eq!(expected["denial"], "none");
                assert_eq!(expected["response_code"], 204);
            }
            Err(error) => {
                assert_eq!(
                    denial(error),
                    expected["denial"].as_str().unwrap(),
                    "{}",
                    case["name"]
                );
                assert_eq!(error.coap_response_code(), 0x83);
                assert_eq!(expected["response_code"], 403);
            }
        }
    }
}

#[test]
fn canonical_decapsulation_cases_enforce_least_privilege() {
    let corpus: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test/vectors/tunnel_authorization.json"
    )))
    .unwrap();
    let own_iid = identity(&corpus, "egress").0;

    for case in corpus["decapsulation_cases"].as_array().unwrap() {
        let mut table = TunnelAuthorizationTable::<4>::default();
        table.set_root(identity(&corpus, case["active_root"].as_str().unwrap()).0);
        apply_setup(
            &mut table,
            &corpus,
            case["setup"].as_array().unwrap(),
            own_iid,
        );
        let route: Vec<[u8; 8]> = case["route_hops_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|hop| bytes(hop.as_str().unwrap()))
            .collect();
        let source = case["inner_source"]
            .as_str()
            .unwrap()
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets();
        let destination = case["inner_destination"]
            .as_str()
            .unwrap()
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets();
        let result = table.authorize_decapsulation(
            DecapsulationRequest {
                direction: if case["direction"] == "mesh-to-external" {
                    TunnelDirection::MeshToExternal
                } else {
                    TunnelDirection::ExternalToMesh
                },
                inner_source: source,
                source_is_mesh: source[0] == 0x02,
                destination_is_mesh: matches!(destination[0], 0x02 | 0xff),
                route: &route,
            },
            case["now"].as_u64().unwrap(),
        );
        let expected = &case["expected"];
        assert_eq!(
            result.is_ok(),
            expected["allowed"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        match result {
            Ok(()) => {
                assert_eq!(expected["denial"], "none");
                assert_eq!(expected["response_code"], 204);
            }
            Err(error) => {
                assert_eq!(
                    denial(error),
                    expected["denial"].as_str().unwrap(),
                    "{}",
                    case["name"]
                );
                assert_eq!(error.coap_response_code(), 0x83);
                assert_eq!(expected["response_code"], 403);
            }
        }
    }
}
