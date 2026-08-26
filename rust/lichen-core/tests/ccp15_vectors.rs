// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Cross-language CCP-15 vector consumer.

use lichen_core::lichen_hash_32;
use lichen_core::rf_health::{
    interference_score_tenths, select_channel, CcaResult, CcaState, RfHealthMetrics,
};
use lichen_core::tdma_beacon::slot_for;
use serde::Deserialize;

const FP_SCALE: u32 = 1 << 16;

#[derive(Deserialize)]
struct Document {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
#[serde(tag = "category")]
enum Vector {
    #[serde(rename = "cca")]
    Cca {
        name: String,
        input: CcaInput,
        expected: CcaExpected,
    },
    #[serde(rename = "interference")]
    Interference {
        name: String,
        input: InterferenceInput,
        expected: InterferenceExpected,
    },
    #[serde(rename = "frequency_agility")]
    Frequency {
        name: String,
        input: FrequencyInput,
        expected: FrequencyExpected,
    },
    #[serde(rename = "sf_adaptation")]
    Sf {
        name: String,
        input: SfInput,
        expected: SfExpected,
    },
    #[serde(rename = "tdma")]
    Tdma {
        name: String,
        input: TdmaInput,
        expected: TdmaExpected,
    },
}

#[derive(Deserialize)]
struct CcaInput {
    channel_busy: bool,
    backoff_exp: u8,
    retries: u8,
}

#[derive(Deserialize)]
struct CcaExpected {
    result: String,
    backoff_exp: u8,
    retries: u8,
    tx_allowed: bool,
}

#[derive(Deserialize)]
struct InterferenceInput {
    busy_percent: u8,
    packet_error_permille: u16,
}

#[derive(Deserialize)]
struct InterferenceExpected {
    score_tenths: u16,
}

#[derive(Deserialize)]
struct FrequencyInput {
    eui64_hex: String,
    epoch: u32,
    density: u8,
    n_channels: u8,
}

#[derive(Deserialize)]
struct FrequencyExpected {
    hash_32: String,
    channel: u8,
}

#[derive(Deserialize)]
struct SfInput {
    assigned_sf: u8,
    density: u8,
    ema_snr: i8,
    ema_loss_permille: u16,
    utilization: u8,
    load_factor_permille: u16,
}

#[derive(Deserialize)]
struct SfExpected {
    sf: u8,
    tx_allowed: bool,
}

#[derive(Deserialize)]
struct TdmaInput {
    eui64_hex: String,
    sfn: u32,
    num_slots: u8,
}

#[derive(Deserialize)]
struct TdmaExpected {
    hash_32: String,
    slot: u8,
}

fn decode_eui64(encoded: &str) -> [u8; 8] {
    assert_eq!(encoded.len(), 16, "EUI-64 must contain 16 hex digits");
    let mut decoded = [0u8; 8];
    for (index, octet) in decoded.iter_mut().enumerate() {
        *octet =
            u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).expect("valid EUI-64 hex");
    }
    decoded
}

fn expected_hash(encoded: &str) -> u32 {
    u32::from_str_radix(encoded, 16).expect("valid hash_32 hex")
}

#[test]
fn ccp15_vectors_drive_rust_implementations() {
    let doc: Document = serde_json::from_str(include_str!("../../../test/vectors/ccp15.json"))
        .expect("valid ccp15 vectors");
    let mut covered = [false; 5];

    for vector in doc.vectors {
        match vector {
            Vector::Cca {
                name,
                input,
                expected,
            } => {
                covered[0] = true;
                let mut state = CcaState::new(input.backoff_exp, input.retries)
                    .expect("schema-valid CCA state");
                let result = state.on_cad_result(input.channel_busy);
                let result_name = match result {
                    CcaResult::TxSuccess => "tx_success",
                    CcaResult::CadBusy => "cad_busy",
                    CcaResult::RetryExhausted => "retry_exhausted",
                };
                assert_eq!(result_name, expected.result, "{name}");
                assert_eq!(state.backoff_exp(), expected.backoff_exp, "{name}");
                assert_eq!(state.retries(), expected.retries, "{name}");
                assert_eq!(result.tx_allowed(), expected.tx_allowed, "{name}");
            }
            Vector::Interference {
                name,
                input,
                expected,
            } => {
                covered[1] = true;
                let score =
                    interference_score_tenths(input.busy_percent, input.packet_error_permille)
                        .expect("schema-valid interference inputs");
                assert_eq!(score, expected.score_tenths, "{name}");
            }
            Vector::Frequency {
                name,
                input,
                expected,
            } => {
                covered[2] = true;
                let eui64 = decode_eui64(&input.eui64_hex);
                let mut hash_input = [0u8; 12];
                hash_input[..8].copy_from_slice(&eui64);
                hash_input[8..].copy_from_slice(&input.epoch.to_le_bytes());
                assert_eq!(
                    lichen_hash_32(&hash_input),
                    expected_hash(&expected.hash_32),
                    "{name}"
                );
                assert_eq!(
                    select_channel(&eui64, input.epoch, input.density, input.n_channels),
                    expected.channel,
                    "{name}"
                );
            }
            Vector::Sf {
                name,
                input,
                expected,
            } => {
                covered[3] = true;
                let mut metrics = RfHealthMetrics::new();
                metrics.record_density(input.density);
                metrics.record_rx(input.ema_snr);
                metrics.record_load_factor(u32::from(input.load_factor_permille) * FP_SCALE / 1000);
                let utilization = u32::from(input.utilization) * FP_SCALE / 100;
                let loss = u32::from(input.ema_loss_permille) * FP_SCALE / 1000;
                let (sf, tx_allowed) = metrics.adaptive_sf_select(
                    Some(input.assigned_sf),
                    Some(utilization),
                    Some(loss),
                );
                assert_eq!(sf, expected.sf, "{name}");
                assert_eq!(tx_allowed, expected.tx_allowed, "{name}");
            }
            Vector::Tdma {
                name,
                input,
                expected,
            } => {
                covered[4] = true;
                let eui64 = decode_eui64(&input.eui64_hex);
                assert_eq!(
                    lichen_hash_32(&eui64),
                    expected_hash(&expected.hash_32),
                    "{name}"
                );
                assert_eq!(
                    slot_for(&eui64, input.sfn, input.num_slots),
                    Some(expected.slot),
                    "{name}"
                );
            }
        }
    }

    assert!(covered.into_iter().all(|seen| seen));
}
