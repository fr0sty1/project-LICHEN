// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Integer-only SX127x LoRa packet-airtime calculation.
//!
//! Implements the Semtech packet-airtime formula without floating point, so
//! embedded and hosted builds produce the same microsecond result. The final
//! fractional microsecond is truncated, matching the canonical LICHEN timing
//! vectors and the existing simulator representation.

/// Default LICHEN spreading factor.
pub const DEFAULT_SPREADING_FACTOR: u8 = 10;
/// Default LICHEN signal bandwidth in hertz.
pub const DEFAULT_BANDWIDTH_HZ: u32 = 125_000;
/// Default LICHEN coding-rate denominator (4/5).
pub const DEFAULT_CODING_RATE: u8 = 5;
/// Default LICHEN preamble length in symbols.
pub const DEFAULT_PREAMBLE_SYMBOLS: u16 = 8;

/// Signal bandwidths supported by the SX127x LoRa modem.
pub const SUPPORTED_BANDWIDTHS_HZ: [u32; 10] = [
    7_800, 10_400, 15_600, 20_800, 31_250, 41_700, 62_500, 125_000, 250_000, 500_000,
];

const MIN_PREAMBLE_SYMBOLS: u16 = 6;

/// Invalid LoRa airtime parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AirtimeError {
    /// LoRa PHY payloads are limited to 255 bytes.
    InvalidPayloadLength(u16),
    /// The SX127x supports spreading factors 6 through 12.
    InvalidSpreadingFactor(u8),
    /// SF6 requires implicit-header mode.
    Sf6RequiresImplicitHeader,
    /// The bandwidth is not one of the SX127x register encodings.
    InvalidBandwidth(u32),
    /// The coding-rate denominator must select 4/5 through 4/8.
    InvalidCodingRate(u8),
    /// The preamble is shorter than the supported six-symbol minimum.
    InvalidPreamble(u16),
}

impl core::fmt::Display for AirtimeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPayloadLength(length) => {
                write!(formatter, "payload length must be 0..=255, got {length}")
            }
            Self::InvalidSpreadingFactor(sf) => {
                write!(formatter, "spreading factor must be 6..=12, got {sf}")
            }
            Self::Sf6RequiresImplicitHeader => {
                formatter.write_str("spreading factor 6 requires implicit-header mode")
            }
            Self::InvalidBandwidth(bandwidth) => {
                write!(formatter, "unsupported SX127x bandwidth: {bandwidth} Hz")
            }
            Self::InvalidCodingRate(coding_rate) => write!(
                formatter,
                "coding-rate denominator must be 5..=8, got {coding_rate}"
            ),
            Self::InvalidPreamble(preamble) => write!(
                formatter,
                "preamble must be at least {MIN_PREAMBLE_SYMBOLS} symbols, got {preamble}"
            ),
        }
    }
}

/// SX127x LoRa modem parameters that affect packet airtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AirtimeConfig {
    /// Spreading factor, from 6 through 12.
    pub spreading_factor: u8,
    /// Signal bandwidth in hertz.
    pub bandwidth_hz: u32,
    /// Coding-rate denominator: 5 means 4/5, through 8 meaning 4/8.
    pub coding_rate: u8,
    /// Programmed preamble length in symbols.
    pub preamble_symbols: u16,
    /// Whether the PHY payload CRC is enabled.
    pub crc_enabled: bool,
    /// Whether the modem uses implicit-header mode.
    pub implicit_header: bool,
    /// Explicit low-data-rate optimization selection. `None` enables it
    /// automatically when the symbol duration is at least 16 ms.
    pub low_data_rate_optimization: Option<bool>,
}

impl Default for AirtimeConfig {
    fn default() -> Self {
        Self {
            spreading_factor: DEFAULT_SPREADING_FACTOR,
            bandwidth_hz: DEFAULT_BANDWIDTH_HZ,
            coding_rate: DEFAULT_CODING_RATE,
            preamble_symbols: DEFAULT_PREAMBLE_SYMBOLS,
            crc_enabled: true,
            implicit_header: false,
            low_data_rate_optimization: None,
        }
    }
}

impl AirtimeConfig {
    /// Return whether low-data-rate optimization is active.
    ///
    /// In automatic mode it is enabled when `T_symbol >= 16 ms`, expressed as
    /// an integer comparison to avoid target-dependent floating-point results.
    fn low_data_rate_optimization_enabled(&self) -> bool {
        match self.low_data_rate_optimization {
            Some(enabled) => enabled,
            None => (1_u32 << self.spreading_factor) * 1_000 >= 16 * self.bandwidth_hz,
        }
    }

    fn validate(&self, payload_len: u16) -> Result<(), AirtimeError> {
        if payload_len > 255 {
            return Err(AirtimeError::InvalidPayloadLength(payload_len));
        }
        if self.spreading_factor < 6 || self.spreading_factor > 12 {
            return Err(AirtimeError::InvalidSpreadingFactor(self.spreading_factor));
        }
        if self.spreading_factor == 6 && !self.implicit_header {
            return Err(AirtimeError::Sf6RequiresImplicitHeader);
        }
        if !SUPPORTED_BANDWIDTHS_HZ.contains(&self.bandwidth_hz) {
            return Err(AirtimeError::InvalidBandwidth(self.bandwidth_hz));
        }
        if self.coding_rate < 5 || self.coding_rate > 8 {
            return Err(AirtimeError::InvalidCodingRate(self.coding_rate));
        }
        if self.preamble_symbols < MIN_PREAMBLE_SYMBOLS {
            return Err(AirtimeError::InvalidPreamble(self.preamble_symbols));
        }
        Ok(())
    }
}

/// Calculate packet airtime with the default LICHEN LoRa profile.
pub fn airtime_us(payload_len: u16) -> Result<u64, AirtimeError> {
    airtime_us_with_config(payload_len, &AirtimeConfig::default())
}

/// Calculate SX127x LoRa packet airtime in microseconds.
///
/// This evaluates:
///
/// `Tpacket = (Npreamble + 4.25 + 8 + Ncoded) * 2^SF / BW`
///
/// entirely with integers. The coding rate is represented by its denominator
/// (`5` for 4/5 through `8` for 4/8).
pub fn airtime_us_with_config(
    payload_len: u16,
    config: &AirtimeConfig,
) -> Result<u64, AirtimeError> {
    config.validate(payload_len)?;

    let sf = i32::from(config.spreading_factor);
    let de = i32::from(config.low_data_rate_optimization_enabled());
    let ih = i32::from(config.implicit_header);
    let crc = i32::from(config.crc_enabled);

    let payload_numerator = 8 * i32::from(payload_len) - 4 * sf + 28 + 16 * crc - 20 * ih;
    let payload_denominator = 4 * (sf - 2 * de);
    let coded_blocks = if payload_numerator <= 0 {
        0
    } else {
        (payload_numerator + payload_denominator - 1) / payload_denominator
    };
    let payload_symbols = 8_u64 + coded_blocks as u64 * u64::from(config.coding_rate);

    // Count quarter-symbols so the 4.25-symbol preamble suffix stays exact.
    let quarter_symbols = 4 * u64::from(config.preamble_symbols) + 17 + 4 * payload_symbols;
    let numerator = quarter_symbols * (1_u64 << config.spreading_factor) * 1_000_000;
    let denominator = 4 * u64::from(config.bandwidth_hz);

    Ok(numerator / denominator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_and_normative_profiles_match() {
        assert_eq!(airtime_us(60), Ok(698_368));

        let sf9 = AirtimeConfig {
            spreading_factor: 9,
            ..AirtimeConfig::default()
        };
        assert_eq!(airtime_us_with_config(60, &sf9), Ok(369_664));

        let maximum = AirtimeConfig {
            low_data_rate_optimization: Some(false),
            ..AirtimeConfig::default()
        };
        assert_eq!(airtime_us_with_config(255, &maximum), Ok(2_295_808));
    }

    #[test]
    fn all_sx127x_sf_bandwidth_and_coding_rate_combinations_are_safe() {
        for spreading_factor in 6..=12 {
            for bandwidth_hz in SUPPORTED_BANDWIDTHS_HZ {
                for coding_rate in 5..=8 {
                    let config = AirtimeConfig {
                        spreading_factor,
                        bandwidth_hz,
                        coding_rate,
                        implicit_header: spreading_factor == 6,
                        ..AirtimeConfig::default()
                    };
                    assert!(airtime_us_with_config(255, &config).is_ok());
                }
            }
        }
    }

    #[test]
    fn low_data_rate_optimization_auto_threshold_and_override() {
        let automatic = AirtimeConfig {
            spreading_factor: 11,
            ..AirtimeConfig::default()
        };
        assert!(automatic.low_data_rate_optimization_enabled());

        let enabled = AirtimeConfig {
            low_data_rate_optimization: Some(true),
            ..automatic
        };
        let disabled = AirtimeConfig {
            low_data_rate_optimization: Some(false),
            ..automatic
        };
        assert_eq!(
            airtime_us_with_config(60, &automatic),
            airtime_us_with_config(60, &enabled)
        );
        assert!(
            airtime_us_with_config(60, &enabled).unwrap()
                > airtime_us_with_config(60, &disabled).unwrap()
        );
    }

    #[test]
    fn header_and_crc_terms_cover_zero_payload_edges() {
        let explicit_crc = AirtimeConfig {
            spreading_factor: 7,
            ..AirtimeConfig::default()
        };
        let implicit_crc = AirtimeConfig {
            implicit_header: true,
            ..explicit_crc
        };
        let explicit_no_crc = AirtimeConfig {
            crc_enabled: false,
            ..explicit_crc
        };

        let explicit_crc_us = airtime_us_with_config(0, &explicit_crc).unwrap();
        assert!(explicit_crc_us > airtime_us_with_config(0, &implicit_crc).unwrap());
        assert!(explicit_crc_us > airtime_us_with_config(0, &explicit_no_crc).unwrap());
    }

    #[test]
    fn invalid_radio_parameters_are_rejected() {
        assert_eq!(
            airtime_us(256),
            Err(AirtimeError::InvalidPayloadLength(256))
        );
        assert_eq!(
            airtime_us_with_config(
                1,
                &AirtimeConfig {
                    spreading_factor: 5,
                    ..AirtimeConfig::default()
                }
            ),
            Err(AirtimeError::InvalidSpreadingFactor(5))
        );
        assert_eq!(
            airtime_us_with_config(
                1,
                &AirtimeConfig {
                    spreading_factor: 6,
                    ..AirtimeConfig::default()
                }
            ),
            Err(AirtimeError::Sf6RequiresImplicitHeader)
        );
        assert_eq!(
            airtime_us_with_config(
                1,
                &AirtimeConfig {
                    bandwidth_hz: 0,
                    ..AirtimeConfig::default()
                }
            ),
            Err(AirtimeError::InvalidBandwidth(0))
        );
        assert_eq!(
            airtime_us_with_config(
                1,
                &AirtimeConfig {
                    coding_rate: 4,
                    ..AirtimeConfig::default()
                }
            ),
            Err(AirtimeError::InvalidCodingRate(4))
        );
        assert_eq!(
            airtime_us_with_config(
                1,
                &AirtimeConfig {
                    preamble_symbols: 5,
                    ..AirtimeConfig::default()
                }
            ),
            Err(AirtimeError::InvalidPreamble(5))
        );
    }
}
