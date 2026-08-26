#![cfg(feature = "std")]

use lichen_node::stack::add_rpl_source_route;
use serde::Deserialize;

const VECTORS: &str = include_str!("../../../test/vectors/srh_root_insertion.json");

#[derive(Deserialize)]
struct Document {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    packet: String,
    route: Vec<String>,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    accepted: bool,
    packet: Option<String>,
    first_hop: Option<String>,
}

fn decode_address(value: &str) -> [u8; 16] {
    hex::decode(value).unwrap().try_into().unwrap()
}

#[test]
fn canonical_root_insertion_vectors_match() {
    let document: Document = serde_json::from_str(VECTORS).unwrap();
    for case in document.cases {
        let packet = hex::decode(&case.packet).unwrap();
        let route: Vec<[u8; 16]> = case
            .route
            .iter()
            .map(|address| decode_address(address))
            .collect();
        let mut output = [0u8; 512];
        let result = add_rpl_source_route(&packet, &route, &mut output);

        if !case.expected.accepted {
            assert!(result.is_err(), "{} unexpectedly accepted", case.name);
            continue;
        }

        let length = result.unwrap_or_else(|error| panic!("{}: {error}", case.name));
        assert_eq!(
            hex::encode(&output[..length]),
            case.expected.packet.unwrap(),
            "{}",
            case.name
        );
        assert_eq!(
            route.first().copied().unwrap(),
            decode_address(&case.expected.first_hop.unwrap()),
            "{}",
            case.name
        );
    }
}
