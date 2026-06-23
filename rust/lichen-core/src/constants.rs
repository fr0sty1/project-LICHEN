//! Protocol constants mirroring `constants.toml` at the repo root.

// LoRa physical layer
pub const LORA_SYNC_WORD: u8 = 0x34;
pub const LORA_SPREADING_FACTOR: u8 = 10;
pub const LORA_BANDWIDTH_HZ: u32 = 125_000;
pub const LORA_PREAMBLE_SYMBOLS: u8 = 8;

// Well-known UDP ports
pub const PORT_COAP: u16 = 5683;
pub const PORT_COAP_DTLS: u16 = 5684;
pub const PORT_MQTT_SN: u16 = 10883;

// SCHC rule IDs (RFC 8724) — spec appendix-schc.md
pub const RULE_LINK_LOCAL_COAP: u8 = 0;
pub const RULE_GLOBAL_COAP: u8 = 1;
pub const RULE_ICMPV6_ECHO: u8 = 2;
pub const RULE_RPL_DIO: u8 = 3;
pub const RULE_RPL_DAO: u8 = 4;
pub const RULE_UNCOMPRESSED: u8 = 255;

// RPL constants (RFC 6550)
pub const RPL_INSTANCE_ID: u8 = 0;
pub const RPL_MODE_OF_OPERATION: u8 = 1; // Non-Storing
pub const RPL_ICMPV6_TYPE: u8 = 155;
pub const RPL_INFINITE_RANK: u16 = 0xFFFF;
pub const RPL_ROOT_RANK: u16 = 256;
pub const RPL_MIN_HOP_RANK_INCREASE: u16 = 256;

// Announce frame type byte (spec §05-routing)
pub const ANNOUNCE_TYPE_BYTE: u8 = 0x01;
