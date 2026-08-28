// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Consume `test/vectors/rpl_messages.json` through the public RPL codecs.

use lichen_rpl::message::{
    Dao, DaoAck, Dio, Dis, DodagConfig, RplError, RplTarget, TransitInfo, OPT_DODAG_CONFIG,
    OPT_RPL_TARGET, OPT_TRANSIT_INFO,
};
use serde_json::Value;

const JSON: &str = include_str!("../../../test/vectors/rpl_messages.json");

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "odd-length hex: {value}");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn ipv6_octets(value: &str) -> [u8; 16] {
    value.parse::<core::net::Ipv6Addr>().unwrap().octets()
}

#[test]
fn rpl_messages_json_vectors() {
    let document: Value = serde_json::from_str(JSON).unwrap();
    assert_eq!(document["format_version"], 2);
    let mut dio = 0;
    let mut dao = 0;
    let mut dis = 0;
    let mut dao_ack = 0;
    let mut option = 0;

    for vector in document["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        match vector["type"].as_str().unwrap() {
            "dio" => {
                consume_dio(name, vector);
                dio += 1;
            }
            "dao" => {
                consume_dao(name, vector);
                dao += 1;
            }
            "dis" => {
                consume_dis(name, vector);
                dis += 1;
            }
            "dao_ack" => {
                consume_dao_ack(name, vector);
                dao_ack += 1;
            }
            "option" => {
                consume_option(name, vector);
                option += 1;
            }
            other => panic!("{name}: unknown type {other}"),
        }
    }

    assert!(dio >= 6, "expected DIO corpus, got {dio}");
    assert!(dao >= 1, "expected DAO corpus, got {dao}");
    assert!(dis >= 5, "expected DIS corpus, got {dis}");
    assert!(dao_ack >= 5, "expected DAO-ACK corpus, got {dao_ack}");
    assert!(option >= 17, "expected option corpus, got {option}");
}

fn consume_option(name: &str, vector: &Value) {
    let encoded = decode_hex(vector["encoded"].as_str().unwrap());
    let option_type = vector["option_type"].as_u64().unwrap() as u8;
    assert_eq!(encoded[0], option_type, "{name}: type");
    assert_eq!(encoded[1] as usize, encoded.len() - 2, "{name}: length");
    match option_type {
        OPT_DODAG_CONFIG => {
            let result = DodagConfig::from_bytes(&encoded[2..]);
            if vector.get("expect_error").is_some() {
                assert_eq!(result, Err(RplError::InvalidOption), "{name}");
                return;
            }
            let config = result.unwrap();
            let fields = &vector["fields"];
            assert_eq!(config.pcs, fields["pcs"].as_u64().unwrap() as u8);
            assert_eq!(
                config.a_flag,
                fields["authentication_enabled"].as_bool().unwrap()
            );
            assert_eq!(
                config.gateway_centric,
                fields["gateway_centric"].as_bool().unwrap()
            );
            assert_eq!(
                config.dio_int_doublings,
                fields["dio_int_doublings"].as_u64().unwrap() as u8
            );
            assert_eq!(
                config.dio_int_min,
                fields["dio_int_min"].as_u64().unwrap() as u8
            );
            assert_eq!(
                config.dio_redundancy_const,
                fields["dio_redundancy_const"].as_u64().unwrap() as u8
            );
            assert_eq!(
                config.max_rank_increase,
                fields["max_rank_increase"].as_u64().unwrap() as u16
            );
            assert_eq!(
                config.min_hop_rank_increase,
                fields["min_hop_rank_increase"].as_u64().unwrap() as u16
            );
            assert_eq!(config.ocp, fields["ocp"].as_u64().unwrap() as u16);
            assert_eq!(
                config.def_lifetime,
                fields["default_lifetime"].as_u64().unwrap() as u8
            );
            assert_eq!(
                config.lifetime_unit,
                fields["lifetime_unit"].as_u64().unwrap() as u16
            );
            let mut actual = [0u8; 16];
            let written = config.write_to(&mut actual).unwrap();
            assert_eq!(&actual[..written], encoded, "{name}: encode");
        }
        OPT_RPL_TARGET => {
            let result = RplTarget::from_bytes(&encoded[2..]);
            if vector.get("expect_error").is_some() {
                assert_eq!(result, Err(RplError::InvalidOption), "{name}");
                return;
            }
            let target = result.unwrap();
            let fields = &vector["fields"];
            assert_eq!(
                target.prefix_len,
                fields["prefix_length"].as_u64().unwrap() as u8
            );
            assert_eq!(
                target.prefix,
                ipv6_octets(fields["prefix"].as_str().unwrap())
            );
            let mut actual = [0u8; 20];
            let written = target.write_to(&mut actual).unwrap();
            assert_eq!(&actual[..written], encoded, "{name}: encode");
        }
        OPT_TRANSIT_INFO => {
            let result = TransitInfo::from_bytes(&encoded[2..]);
            if vector.get("expect_error").is_some() {
                assert_eq!(result, Err(RplError::InvalidOption), "{name}");
                return;
            }
            let transit = result.unwrap();
            let fields = &vector["fields"];
            assert_eq!(transit.external, fields["external"].as_bool().unwrap());
            assert_eq!(
                transit.path_control,
                fields["path_control"].as_u64().unwrap() as u8
            );
            assert_eq!(
                transit.path_sequence,
                fields["path_sequence"].as_u64().unwrap() as u8
            );
            assert_eq!(
                transit.path_lifetime,
                fields["path_lifetime"].as_u64().unwrap() as u8
            );
            assert_eq!(
                transit.parent_address,
                ipv6_octets(fields["parent_address"].as_str().unwrap())
            );
            let mut actual = [0u8; 22];
            let written = transit.write_to(&mut actual).unwrap();
            assert_eq!(&actual[..written], encoded, "{name}: encode");
        }
        other => panic!("{name}: unsupported option type {other}"),
    }
}

fn consume_dio(name: &str, vector: &Value) {
    let fields = &vector["fields"];
    let dio = Dio {
        rpl_instance_id: fields["rpl_instance_id"].as_u64().unwrap() as u8,
        version: fields["version"].as_u64().unwrap() as u8,
        rank: fields["rank"].as_u64().unwrap() as u16,
        grounded: fields["grounded"].as_bool().unwrap(),
        mode_of_operation: fields["mode_of_operation"].as_u64().unwrap() as u8,
        preference: fields["preference"].as_u64().unwrap() as u8,
        dtsn: fields["dtsn"].as_u64().unwrap() as u8,
        flags: fields["flags"].as_u64().unwrap() as u8,
        dodag_id: ipv6_octets(fields["dodag_id"].as_str().unwrap()),
    };
    let mode = vector["schc_version_mode"].as_str().unwrap();
    let options = decode_hex(vector["options_hex"].as_str().unwrap());
    let mut actual = [0u8; 64];
    let result = match mode {
        "insert_current" => dio.write_to(&mut actual),
        "propagate_root" | "explicit" | "malformed" | "duplicate" => {
            dio.write_to_with_schc_version_option(Some(&options), &mut actual)
        }
        other => panic!("{name}: unknown SCHC version mode {other}"),
    };
    if vector.get("expect_error").is_some() {
        assert_eq!(result, Err(RplError::InvalidOption), "{name}");
        return;
    }
    let written = result.unwrap();
    let expected = decode_hex(vector["encoded"].as_str().unwrap());
    assert_eq!(&actual[..written], expected, "{name}: encode");
    assert_eq!(Dio::from_bytes(&actual[..written]).unwrap(), dio, "{name}");
}

fn consume_dao(name: &str, vector: &Value) {
    let encoded = decode_hex(vector["encoded"].as_str().unwrap());
    let fields = &vector["fields"];
    let dodag_id = if fields["dodag_id"].is_null() {
        None
    } else {
        Some(ipv6_octets(fields["dodag_id"].as_str().unwrap()))
    };
    let dao = Dao {
        rpl_instance_id: fields["rpl_instance_id"].as_u64().unwrap() as u8,
        ack_requested: fields["ack_requested"].as_bool().unwrap(),
        flags: fields["flags"].as_u64().unwrap() as u8,
        dao_sequence: fields["dao_sequence"].as_u64().unwrap() as u8,
        dodag_id,
    };
    assert_eq!(Dao::from_bytes(&encoded).unwrap(), dao, "{name}");
    let mut actual = [0u8; 64];
    let written = dao.write_to(&mut actual).unwrap();
    assert_eq!(&actual[..written], encoded, "{name}: encode");
}

fn consume_dis(name: &str, vector: &Value) {
    let encoded = decode_hex(vector["encoded"].as_str().unwrap());
    if let Some(expect_error) = vector.get("expect_error") {
        let result = Dis::from_bytes(&encoded);
        match expect_error.as_str().unwrap() {
            "too_short" => {
                assert!(
                    matches!(result, Err(RplError::TooShort(_))),
                    "{name}: {result:?}"
                );
            }
            "nonzero_reserved" => {
                assert_eq!(result, Err(RplError::InvalidOption), "{name}");
            }
            other => panic!("{name}: unknown expect_error {other}"),
        }
        return;
    }
    let fields = &vector["fields"];
    let dis = Dis {
        flags: fields["flags"].as_u64().unwrap() as u8,
        reserved: fields["reserved"].as_u64().unwrap() as u8,
    };
    assert_eq!(Dis::from_bytes(&encoded).unwrap(), dis, "{name}");
    let mut actual = [0u8; 64];
    let written = dis.write_to(&mut actual).unwrap();
    assert_eq!(&actual[..written], &encoded[..2], "{name}: encode");
}

fn consume_dao_ack(name: &str, vector: &Value) {
    let encoded = decode_hex(vector["encoded"].as_str().unwrap());
    if let Some(expect_error) = vector.get("expect_error") {
        let result = DaoAck::from_bytes(&encoded);
        match expect_error.as_str().unwrap() {
            "too_short" | "missing_dodagid" => {
                assert!(
                    matches!(result, Err(RplError::TooShort(_))),
                    "{name}: {result:?}"
                );
            }
            "nonzero_reserved_flags" | "malformed_options" => {
                assert_eq!(result, Err(RplError::InvalidOption), "{name}");
            }
            other => panic!("{name}: unknown expect_error {other}"),
        }
        return;
    }
    let fields = &vector["fields"];
    let dodag_id = if fields["dodag_id"].is_null() {
        None
    } else {
        Some(ipv6_octets(fields["dodag_id"].as_str().unwrap()))
    };
    let ack = DaoAck {
        rpl_instance_id: fields["rpl_instance_id"].as_u64().unwrap() as u8,
        flags: fields["flags"].as_u64().unwrap() as u8,
        dao_sequence: fields["dao_sequence"].as_u64().unwrap() as u8,
        status: fields["status"].as_u64().unwrap() as u8,
        dodag_id,
    };
    assert_eq!(DaoAck::from_bytes(&encoded).unwrap(), ack, "{name}");
    let mut actual = [0u8; 64];
    let written = ack.write_to(&mut actual).unwrap();
    assert_eq!(&actual[..written], encoded, "{name}: encode");
}
