use lichen_link::keys::PublicKey;
use lichen_rpl::{
    message::{DaoEnvelopeError, SignedDaoEnvelope},
    routing::{dao_origin_digest, DaoVerifyError, SignatureVerifiedDao},
};
use serde_json::Value;

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn array<const N: usize>(value: &Value, field: &str) -> [u8; N] {
    hex(value[field].as_str().unwrap()).try_into().unwrap()
}

#[test]
fn dao_origin_signature_vectors_match_fixed_literals() {
    let document: Value = serde_json::from_str(include_str!(
        "../../../test/vectors/dao_origin_signature.json"
    ))
    .unwrap();

    for vector in document["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let wire = hex(vector["signed_dao"].as_str().unwrap());
        let source = array::<16>(vector, "source_ipv6");
        let dodag = array::<16>(vector, "effective_dodag_id");
        let active_dodag = array::<16>(vector, "active_dodag_id");
        let public_key = PublicKey::new(array::<32>(vector, "public_key"));
        let reason = vector["expected"]["reason"].as_str().unwrap();

        let envelope = SignedDaoEnvelope::from_bytes(&wire);
        if name == "wrong_scope_precedes_malformed_option" {
            assert!(envelope.is_err(), "{name}: framing must be malformed");
            assert!(matches!(
                SignatureVerifiedDao::verify_signature(
                    &wire,
                    source,
                    0,
                    active_dodag,
                    Some(public_key),
                ),
                Err(DaoVerifyError::WrongInstance)
            ));
            continue;
        }
        match reason {
            "duplicate_option" => {
                assert_eq!(
                    envelope,
                    Err(DaoEnvelopeError::DuplicateSignature),
                    "{name}"
                );
                continue;
            }
            "nonterminal_option" => {
                assert_eq!(
                    envelope,
                    Err(DaoEnvelopeError::NonTerminalSignature),
                    "{name}"
                );
                continue;
            }
            "unknown_option" => {
                assert_eq!(
                    envelope,
                    Err(DaoEnvelopeError::UnknownOption(0x7e)),
                    "{name}"
                );
                continue;
            }
            "bad_option_length" | "malformed_dao" | "missing_signature" | "nonzero_reserved"
            | "truncated" | "unsupported_flags" | "zero_sequence" => {
                assert!(envelope.is_err(), "{name}: {envelope:?}");
                continue;
            }
            _ => {}
        }
        let envelope = envelope.unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(
            envelope.unsigned_bytes,
            hex(vector["unsigned_dao"].as_str().unwrap()),
            "{name} unsigned DAO"
        );
        assert_eq!(
            envelope.origin.origin_sequence,
            vector["sequence"].as_u64().unwrap(),
            "{name} sequence"
        );
        assert_eq!(
            dao_origin_digest(
                source,
                dodag,
                envelope.origin.origin_sequence,
                envelope.unsigned_bytes
            ),
            array::<64>(vector, "digest"),
            "{name} digest"
        );

        let key = vector["key_available"]
            .as_bool()
            .unwrap()
            .then_some(public_key);
        let result = SignatureVerifiedDao::verify_signature(&wire, source, 0, active_dodag, key);
        match reason {
            "accepted"
            | "idempotent"
            | "reconciled"
            | "replay"
            | "sequence_conflict"
            | "duplicate_target"
            | "inconsistent_transit"
            | "missing_target"
            | "missing_transit"
            | "multiple_target"
            | "target_mismatch"
            | "unsupported_transit_e"
            | "unauthorized_target" => {
                assert!(result.is_ok(), "{name}: {result:?}")
            }
            "dodag_mismatch" => {
                assert!(matches!(result, Err(DaoVerifyError::WrongDodag)), "{name}")
            }
            "instance_mismatch" => {
                assert!(
                    matches!(result, Err(DaoVerifyError::WrongInstance)),
                    "{name}"
                )
            }
            "unknown_key" => assert!(matches!(result, Err(DaoVerifyError::UnknownKey)), "{name}"),
            "iid_mismatch" => assert!(matches!(result, Err(DaoVerifyError::IidMismatch)), "{name}"),
            "invalid_signature" => {
                assert!(
                    matches!(result, Err(DaoVerifyError::BadSignature)),
                    "{name}: {result:?}"
                )
            }
            other => panic!("unhandled vector reason {other}"),
        }
    }
}

#[test]
fn exact_lengths_unknown_options_and_d0_scope_reject_before_crypto() {
    let d0 = hex("0000002a05120080fd424c494348454e000000000000010006140000f1fffe8000000000000000000000000000011238000000000000002b863bacaf8461f0c95bcfbd65ce62218cc148f03a95049076082d7f0dec8eccfa64db1ebaaac15f6e15bb05184199570e");
    let source = hex("fe80000000000000bd4e02f43853c45c").try_into().unwrap();
    let dodag = hex("fd424c494348454e0000000000000001").try_into().unwrap();
    let key = PublicKey::new(
        hex("207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6")
            .try_into()
            .unwrap(),
    );
    assert!(matches!(
        SignatureVerifiedDao::verify_signature(&d0, source, 1, dodag, Some(key)),
        Err(DaoVerifyError::WrongInstance)
    ));
    let mut wrong_dodag = dodag;
    wrong_dodag[15] ^= 1;
    assert!(matches!(
        SignatureVerifiedDao::verify_signature(&d0, source, 0, wrong_dodag, Some(key)),
        Err(DaoVerifyError::BadSignature)
    ));

    let mut unknown = d0.clone();
    unknown.splice(46..46, [0x7f, 0]);
    assert!(matches!(
        SignedDaoEnvelope::from_bytes(&unknown),
        Err(DaoEnvelopeError::UnknownOption(0x7f))
    ));

    let mut short_target = d0;
    short_target[5] = 17;
    assert!(matches!(
        SignedDaoEnvelope::from_bytes(&short_target),
        Err(DaoEnvelopeError::InvalidOptionLength)
    ));
}
