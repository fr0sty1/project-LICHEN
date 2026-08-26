use lichen_rpl::routing::{SourceRoutingHeader, MAX_ROUTE_HOPS};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../test/vectors/source_route_hop_limit.json");

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(digits, 16).unwrap()
        })
        .collect()
}

fn address(value: &Value) -> [u8; 16] {
    decode_hex(value.as_str().unwrap()).try_into().unwrap()
}

#[test]
fn canonical_source_route_hop_limit_vectors_match_codec() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(document["vector_type"], "source_route_hop_limit");
    assert_eq!(document["format_version"], 2);

    for vector in document["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let wire = decode_hex(vector["ext_data"].as_str().unwrap());
        let decoded = SourceRoutingHeader::from_bytes(&wire)
            .unwrap_or_else(|error| panic!("{name}: decode failed: {error}"));

        assert_eq!(
            decoded.segments_left,
            vector["segments_left"].as_u64().unwrap() as u8,
            "{name}"
        );
        let expected_addresses: Vec<[u8; 16]> = vector["addresses"]
            .as_array()
            .unwrap()
            .iter()
            .map(address)
            .collect();
        assert_eq!(decoded.addresses, expected_addresses, "{name}");
        assert_eq!(
            decoded.validate_hop_limit(vector["hop_limit"].as_u64().unwrap() as u8),
            vector["expected"]["accepted"].as_bool().unwrap(),
            "{name}"
        );

        let mut encoded = vec![0xff; wire.len()];
        let encoded_len = decoded
            .write_to(&mut encoded)
            .unwrap_or_else(|error| panic!("{name}: encode failed: {error}"));
        assert_eq!(&encoded[..encoded_len], wire, "{name}");
    }
}

#[test]
fn codec_enforces_profile_route_limits() {
    let too_many_addresses = vec![[0x02; 16]; MAX_ROUTE_HOPS + 1];
    let srh = SourceRoutingHeader {
        segments_left: 0,
        addresses: too_many_addresses.clone(),
    };
    let mut wire = vec![0; 6 + too_many_addresses.len() * 16];
    assert!(srh.write_to(&mut wire).is_err());

    wire[0] = 3;
    assert!(SourceRoutingHeader::from_bytes(&wire).is_err());

    let overlong_complete_route = vec![[0x02; 16]; MAX_ROUTE_HOPS + 1];
    assert!(SourceRoutingHeader::from_route(&overlong_complete_route).is_err());
}

#[test]
fn decoder_ignores_reserved_bits_but_rejects_padding() {
    let mut reserved = [3, 0, 0, 0x0f, 0xaa, 0x55];
    assert!(SourceRoutingHeader::from_bytes(&reserved).is_ok());

    reserved[3] = 0x1f;
    assert!(SourceRoutingHeader::from_bytes(&reserved).is_err());
}
