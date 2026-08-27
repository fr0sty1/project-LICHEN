//! Drive `test/vectors/sos_cbor.json` through `SosAlert` CBOR codec.

use lichen_link::{SosAlert, SosCborError};
use serde_json::Value;

const SOS_CBOR_JSON: &str = include_str!("../../../test/vectors/sos_cbor.json");

fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd hex length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn sos_cbor_hex_vectors_decode_and_reencode() {
    let doc: Value = serde_json::from_str(SOS_CBOR_JSON).expect("sos_cbor.json");
    let vectors = doc["vectors"].as_array().expect("vectors");
    let mut driven = 0usize;
    for vector in vectors {
        let Some(hex) = vector["cbor_hex"].as_str() else {
            continue;
        };
        let name = vector["name"].as_str().unwrap_or("?");
        let wire = decode_hex(hex);
        assert_eq!(
            wire.len(),
            vector["cbor_length"].as_u64().expect("cbor_length") as usize,
            "{name} length"
        );
        if vector["expected"]["decode_success"] == Value::Bool(false) {
            // Negative vector: the wire is structurally valid CBOR whose
            // coordinates violate the documented contract, so from_cbor
            // must reject it (never panic) and positive assertions are skipped.
            let error = vector["expected"]["error"].as_str().unwrap_or_default();
            match SosAlert::from_cbor(&wire) {
                Ok(alert) => panic!("{name}: expected rejection ({error}), decoded {alert:?}"),
                Err(SosCborError::InvalidValue) => {}
                Err(other) => panic!("{name}: unexpected error {other:?} for {error}"),
            }
            driven += 1;
            continue;
        }
        let alert = SosAlert::from_cbor(&wire).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(alert.to_cbor(), wire, "{name} re-encode");
        let payload = &vector["cbor_payload"];
        assert_eq!(alert.alert_type.as_str(), payload["type"].as_str().unwrap());
        assert_eq!(alert.node, payload["node"].as_str().unwrap());
        assert_eq!(alert.ts, payload["ts"].as_u64().unwrap());
        assert_eq!(alert.seq, payload["seq"].as_u64().unwrap() as u32);
        match payload.get("lat") {
            Some(v) => assert_eq!(alert.lat, Some(v.as_f64().unwrap()), "{name} lat"),
            None => assert_eq!(alert.lat, None, "{name} lat absent"),
        }
        match payload.get("lon") {
            Some(v) => assert_eq!(alert.lon, Some(v.as_f64().unwrap()), "{name} lon"),
            None => assert_eq!(alert.lon, None, "{name} lon absent"),
        }
        match payload.get("msg") {
            Some(v) => assert_eq!(alert.msg.as_deref(), v.as_str(), "{name} msg"),
            None => assert_eq!(alert.msg, None, "{name} msg absent"),
        }
        if vector["expected"].get("lat_negative") == Some(&Value::Bool(true)) {
            assert!(alert.lat.unwrap() < 0.0, "{name} southern hemisphere");
        }
        let canonical = alert.to_canonical_cbor();
        let from_canonical = SosAlert::from_cbor(&canonical)
            .unwrap_or_else(|e| panic!("{name}: canonical decode {e:?}"));
        assert_eq!(from_canonical.alert_type, alert.alert_type, "{name}");
        assert_eq!(from_canonical.node, alert.node, "{name}");
        assert_eq!(from_canonical.ts, alert.ts, "{name}");
        assert_eq!(from_canonical.seq, alert.seq, "{name}");
        driven += 1;
    }
    // Five positive vectors + six negative vectors with cbor_hex.
    assert_eq!(driven, 11, "expected eleven cbor_hex payloads");
}

#[test]
fn sos_type_validation_accepts_five_spec_types() {
    let doc: Value = serde_json::from_str(SOS_CBOR_JSON).expect("sos_cbor.json");
    let vector = doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "sos_type_validation")
        .expect("sos_type_validation");
    let types = vector["valid_types"].as_array().unwrap();
    assert_eq!(types.len(), 5);
    for t in types {
        let token = t.as_str().unwrap();
        let alert = SosAlert::new(
            lichen_link::SosAlertType::from_str(token).expect(token),
            "0200:0000:0000:0000:0000:0000:0000:0001".into(),
            0,
            1,
        );
        let decoded = SosAlert::from_cbor(&alert.to_cbor()).expect(token);
        assert_eq!(decoded.alert_type.as_str(), token);
    }
}
