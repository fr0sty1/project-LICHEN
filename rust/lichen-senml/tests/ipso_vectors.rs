//! Cross-language IPSO Smart Object path and SenML-CBOR vectors.

use std::fs;
use std::path::Path as FsPath;

use lichen_senml::cbor;
use lichen_senml::ipso::{object_definition, Path, PathError};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorDocument {
    format_version: u32,
    vectors: Vec<PositiveVector>,
    invalid_paths: Vec<InvalidVector>,
}

#[derive(Debug, Deserialize)]
struct PositiveVector {
    id: String,
    object_id: u16,
    object_name: String,
    instance_id: u16,
    resource_id: Option<u16>,
    path: String,
    unit: Option<String>,
    value: Option<f64>,
    cbor_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InvalidVector {
    path: String,
    error_kind: String,
}

fn load_vectors() -> VectorDocument {
    let path =
        FsPath::new(env!("CARGO_MANIFEST_DIR")).join("../../test/vectors/ipso_smart_objects.json");
    let contents = fs::read_to_string(path).expect("read IPSO vectors");
    serde_json::from_str(&contents).expect("parse IPSO vectors")
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

#[test]
fn positive_vectors_format_parse_and_encode() {
    let document = load_vectors();
    assert_eq!(document.format_version, 2);
    for vector in document.vectors {
        let path = Path {
            object_id: vector.object_id,
            instance_id: vector.instance_id,
            resource_id: vector.resource_id,
        };
        let mut name_storage = [0_u8; 17];
        let name = path.write_name(&mut name_storage).unwrap();
        assert_eq!(name, vector.path, "{}", vector.id);
        assert_eq!(Path::parse(&vector.path), Ok(path), "{}", vector.id);

        let definition = object_definition(vector.object_id).expect("known vector object");
        assert_eq!(definition.name, vector.object_name, "{}", vector.id);

        if let Some(value) = vector.value {
            let expected_unit = vector.unit.as_deref();
            assert_eq!(path.default_unit(), expected_unit, "{}", vector.id);
            let mut name_storage = [0_u8; 17];
            let record = path
                .record(&mut name_storage, value, path.default_unit())
                .unwrap();
            let mut encoded = [0_u8; 128];
            let encoded_len = cbor::encode(&[record], &mut encoded).unwrap();
            let expected = decode_hex(vector.cbor_hex.as_deref().expect("CBOR vector"));
            assert_eq!(&encoded[..encoded_len], expected, "{}", vector.id);
        }
    }
}

#[test]
fn invalid_vectors_are_rejected_by_kind() {
    let document = load_vectors();
    for vector in document.invalid_paths {
        let expected = match vector.error_kind.as_str() {
            "invalid_shape" => PathError::InvalidShape,
            "invalid_component" => PathError::InvalidComponent,
            "non_canonical" => PathError::NonCanonical,
            "out_of_range" => PathError::OutOfRange,
            other => panic!("unknown error kind {other}"),
        };
        assert_eq!(Path::parse(&vector.path), Err(expected), "{}", vector.path);
    }
}
