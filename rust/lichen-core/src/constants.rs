//! Protocol constants mirroring `constants.toml` at the repo root.

// LoRa physical layer
pub const LORA_SYNC_WORD: u8 = 0x34;
pub const LORA_SPREADING_FACTOR: u8 = 10;
pub const LORA_BANDWIDTH_HZ: u32 = 125_000;
pub const LORA_PREAMBLE_SYMBOLS: u8 = 8;
/// Maximum LoRa frame payload in bytes (SX1262 limit).
pub const LORA_MAX_PAYLOAD: usize = 255;

// SCHC (RFC 8724)
/// Maximum decompressed packet size for SCHC buffers (updated for SRH/Routing
/// Header overhead in local_mesh paths per RFC 6554). Covers IPv6 MTU 1280
/// + max practical SRH (~8+16*8=136 bytes) + margin.
pub const SCHC_MAX_DECOMPRESSED: usize = 1500;

// Well-known UDP ports (spec Section 9.1)
pub const PORT_COMPACT_COT: u16 = 5681;
pub const PORT_SENML: u16 = 5682;
pub const PORT_COAP: u16 = 5683;
pub const PORT_COAP_DTLS: u16 = 5684; // Reserved, not used (OSCORE instead)
pub const PORT_CAYENNE_LPP: u16 = 5685;
pub const PORT_APRS_IS: u16 = 5686;
pub const PORT_NMEA: u16 = 5687;
pub const PORT_MQTT_SN: u16 = 10883;

// SCHC rule IDs (RFC 8724) — spec appendix-schc.md and constants.toml
pub const RULE_LINK_LOCAL_COAP: u8 = 0;
pub const RULE_GLOBAL_COAP: u8 = 1;
pub const RULE_ICMPV6_ECHO: u8 = 2;
pub const RULE_RPL_DIO: u8 = 3;
pub const RULE_RPL_DAO: u8 = 4;
pub const RULE_LINK_LOCAL_OSCORE: u8 = 5;
pub const RULE_GLOBAL_OSCORE: u8 = 6;
pub const RULE_MQTT_SN: u8 = 7; // Future use; not in constants.toml yet
pub const RULE_UNCOMPRESSED: u8 = 255;

// Authenticated L2 inner-payload dispatch bytes.
pub const L2_DISPATCH_SCHC: u8 = 0x14;
pub const L2_DISPATCH_ROUTING: u8 = 0x15;

// RPL constants (RFC 6550)
pub const RPL_INSTANCE_ID: u8 = 0;
pub const RPL_MODE_OF_OPERATION: u8 = 1; // Non-Storing
pub const RPL_ICMPV6_TYPE: u8 = 155;
pub const RPL_INFINITE_RANK: u16 = 0xFFFF;
pub const RPL_ROOT_RANK: u16 = 256;
pub const RPL_MIN_HOP_RANK_INCREASE: u16 = 256;

pub const ANNOUNCE_TYPE_BYTE: u8 = 0x01;
pub const SENML_CONTENT_FORMAT: u16 = 112;
pub const SENML_BASE_NAME_PREFIX: &str = "urn:dev:mac:";
pub const SENML_LOCATION_LAT: &str = "lat";
pub const SENML_LOCATION_LON: &str = "lon";
pub const SENML_LOCATION_ALT: &str = "alt";
pub const SENML_LOCATION_SPEED: &str = "speed";
pub const SENML_LOCATION_HEADING: &str = "heading";
pub const SENML_LOCATION_UNIT_DEG: &str = "deg";
pub const SENML_LOCATION_UNIT_M: &str = "m";
pub const SENML_LOCATION_UNIT_MS: &str = "m/s";
pub const SENML_BATTERY_PCT: &str = "pct";
pub const SENML_BATTERY_MV: &str = "mv";
pub const SENML_BATTERY_CHARGING: &str = "charging";
pub const SENML_BATTERY_UNIT_PCT: &str = "%";
pub const SENML_BATTERY_UNIT_MV: &str = "mV";
pub const SENML_TELEMETRY_TEMP: &str = "temp";
pub const SENML_TELEMETRY_HUMIDITY: &str = "hum";
pub const SENML_TELEMETRY_PRESSURE: &str = "pressure";
pub const SENML_TELEMETRY_UNIT_CEL: &str = "Cel";
pub const SENML_TELEMETRY_UNIT_RH: &str = "%RH";
pub const SENML_TELEMETRY_UNIT_PA: &str = "Pa";
pub const TDMA_GUARD_MS: u32 = 50;
pub const TDMA_SLOT_MS: u32 = 250;
