//! GCP-4 Discovery: backbone multicast and LoRa fallback.
//!
//! Per spec 08-gateway-coordination.md GCP-4:
//!
//! ## 4.1. Backbone Discovery (Primary)
//! - Gateways send multicast CoAP GET to `ff02::1` on backbone for
//!   `/.well-known/lichen-gw/info`.
//! - Response contains: gateway IID, capabilities, current slot map, superframe
//!   time, supported federation modes.
//! - Periodic announcements and on-change notifications via CoAP Observe.
//!
//! ## 4.2. LoRa Discovery (Fallback)
//! - Gateway announce frames include GATEWAY flag in link layer.
//! - Other gateways receiving on LoRa establish radio-path awareness.
//! - Used when backbone is unavailable or for initial synchronization.
//!
//! This module provides:
//! - [`BackboneDiscoveryRequest`]: CoAP GET request for backbone discovery
//! - [`BACKBONE_MULTICAST_ADDR`]: IPv6 all-nodes multicast address for discovery
//! - [`GATEWAY_INFO_PATH`]: URI path segments for gateway info resource
//! - [`LoraGatewayAnnounce`]: Wire format for LoRa gateway announcements
//! - [`GATEWAY_FLAG`]: Bit mask for GATEWAY flag in announce type byte
//! - [`is_gateway_announce`]: Check if a type byte indicates gateway announce
//! - [`TimeMasterCandidate`]: Re-exported from slot module for time master election

use crate::slot::iid_to_u64;
use lichen_coap::codec::{CoapBuilder, CoapError};
use lichen_coap::message::{MessageCode, MessageType};
use lichen_coap::option::OptionNumber;

// ─── GCP-4.1 Backbone Discovery Constants ────────────────────────────────────

/// IPv6 all-nodes multicast address for backbone discovery (ff02::1).
///
/// Per GCP-4.1, gateways send multicast CoAP GET to this address on the
/// backbone link to discover other gateways.
pub const BACKBONE_MULTICAST_ADDR: [u8; 16] = [
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// IPv6 all-nodes multicast address as a string.
pub const BACKBONE_MULTICAST_STR: &str = "ff02::1";

/// URI path segments for gateway info resource.
///
/// The full path is `/.well-known/lichen-gw/info`.
pub const GATEWAY_INFO_PATH: [&str; 3] = [".well-known", "lichen-gw", "info"];

/// CoAP Observe register value (0 = register for notifications).
pub const OBSERVE_REGISTER: u32 = 0;

/// CoAP Observe deregister value (1 = deregister).
pub const OBSERVE_DEREGISTER: u32 = 1;

// ─── Backbone Discovery Request ──────────────────────────────────────────────

/// CoAP GET request for backbone gateway discovery (GCP-4.1).
///
/// Encodes a CoAP Confirmable GET request for `/.well-known/lichen-gw/info`
/// suitable for multicast to `ff02::1`. Optionally includes Observe option
/// to register for periodic announcements.
///
/// # Example
///
/// ```
/// use lichen_gateway::discovery::BackboneDiscoveryRequest;
///
/// let req = BackboneDiscoveryRequest::new(1, &[0xab, 0xcd]);
/// let mut buf = [0u8; 64];
/// let len = req.encode(&mut buf).unwrap();
///
/// // Message is ready to send via UDP multicast to ff02::1:5683
/// assert!(len > 0);
/// ```
#[derive(Debug, Clone)]
pub struct BackboneDiscoveryRequest {
    /// CoAP message ID.
    pub message_id: u16,
    /// Token for request/response matching.
    pub token: Vec<u8>,
    /// If Some, include Observe option with this value.
    pub observe: Option<u32>,
}

impl BackboneDiscoveryRequest {
    /// Create a new discovery request.
    pub fn new(message_id: u16, token: &[u8]) -> Self {
        Self {
            message_id,
            token: token.to_vec(),
            observe: None,
        }
    }

    /// Create a discovery request with Observe registration.
    ///
    /// Pass `observe=0` to register for notifications, `observe=1` to deregister.
    pub fn with_observe(message_id: u16, token: &[u8], observe: u32) -> Self {
        Self {
            message_id,
            token: token.to_vec(),
            observe: Some(observe),
        }
    }

    /// Encode the request into a CoAP message.
    ///
    /// Returns the number of bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, CoapError> {
        let mut builder = CoapBuilder::new(
            buf,
            MessageType::Confirmable,
            MessageCode::GET,
            self.message_id,
            &self.token,
        )?;

        // Add Observe option first if present (option number 6)
        // Observe option must come before Uri-Path (option number 11)
        if let Some(obs_val) = self.observe {
            // Encode observe value as minimal-length uint
            let obs_bytes = obs_val.to_be_bytes();
            let obs_value: &[u8] = match obs_val {
                0 => &obs_bytes[3..4], // Single byte for 0 (but can be empty per RFC 7641)
                1..=0xFF => &obs_bytes[3..4],
                0x100..=0xFFFF => &obs_bytes[2..4],
                0x10000..=0xFFFFFF => &obs_bytes[1..4],
                _ => &obs_bytes[..],
            };
            // Per RFC 7641, Observe=0 can be encoded as empty or single 0x00
            let obs_value = if obs_val == 0 { &[0u8][..] } else { obs_value };
            builder.option(OptionNumber::Observe as u16, obs_value)?;
        }

        // Add Uri-Path options (option number 11)
        for segment in &GATEWAY_INFO_PATH {
            builder.uri_path(segment)?;
        }

        Ok(builder.finish())
    }
}

/// Parse a CoAP Observe option value.
///
/// Returns the observe sequence number, or None if not an Observe option.
pub fn parse_observe_option(value: &[u8]) -> Option<u32> {
    if value.is_empty() {
        return Some(0);
    }
    if value.len() > 3 {
        return None; // Observe is max 3 bytes (24-bit)
    }
    let mut result = 0u32;
    for &b in value {
        result = (result << 8) | (b as u32);
    }
    Some(result)
}

// ─── GCP-4.2 LoRa Discovery Constants ────────────────────────────────────────

/// GATEWAY flag bit in announce type byte (bit 7).
///
/// Per GCP-4.2, gateway announce frames set this flag to distinguish
/// them from regular node announces.
pub const GATEWAY_FLAG: u8 = 0x80;

/// Wire format length for LoRa gateway announce payload.
///
/// Format: type(1) + iid_short(4) + epoch(4) + channel(1) = 10 bytes
pub const LORA_ANNOUNCE_LEN: usize = 10;

/// Check if a type byte indicates a gateway announce (GATEWAY flag set).
#[inline]
pub fn is_gateway_announce(type_byte: u8) -> bool {
    type_byte & GATEWAY_FLAG != 0
}

/// Error type for LoRa gateway announce parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoraAnnounceError {
    /// Payload too short (expected 10 bytes).
    TooShort { got: usize, expected: usize },
    /// GATEWAY flag not set in type byte.
    GatewayFlagNotSet,
    /// Channel ID out of range (must be 0-15).
    InvalidChannelId { got: u8 },
}

impl core::fmt::Display for LoraAnnounceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { got, expected } => {
                write!(
                    f,
                    "payload too short: got {} bytes, expected {}",
                    got, expected
                )
            }
            Self::GatewayFlagNotSet => write!(f, "GATEWAY flag not set"),
            Self::InvalidChannelId { got } => {
                write!(f, "channel_id out of range: got {}, expected 0-15", got)
            }
        }
    }
}

impl std::error::Error for LoraAnnounceError {}

/// LoRa gateway announce frame (GCP-4.2 fallback discovery).
///
/// Wire format (10 bytes total):
/// ```text
/// +------+-------------+------------------+------------+
/// | Type | IID Short   | Superframe Epoch | Channel ID |
/// | 1B   | 4B          | 4B               | 1B         |
/// +------+-------------+------------------+------------+
/// ```
///
/// - Type byte: bit 7 (0x80) = GATEWAY flag, bits 0-6 = reserved
/// - IID Short: last 4 bytes of gateway's IID (EUI-64 or derived)
/// - Superframe Epoch: current superframe Unix timestamp (big-endian)
/// - Channel ID: LoRa channel (0-15)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoraGatewayAnnounce {
    /// Short IID (last 4 bytes of gateway's full IID).
    pub iid_short: [u8; 4],
    /// Current superframe epoch (Unix timestamp).
    pub superframe_epoch: u32,
    /// LoRa channel ID (0-15).
    pub channel_id: u8,
}

impl LoraGatewayAnnounce {
    /// Create a new LoRa gateway announce.
    ///
    /// # Panics
    ///
    /// Debug builds panic if `channel_id > 15`.
    pub fn new(iid_short: [u8; 4], superframe_epoch: u32, channel_id: u8) -> Self {
        debug_assert!(
            channel_id <= 15,
            "channel_id must be 0-15, got {}",
            channel_id
        );
        Self {
            iid_short,
            superframe_epoch,
            channel_id,
        }
    }

    /// Create from full IID (extracts last 4 bytes).
    pub fn from_full_iid(iid: &[u8; 8], superframe_epoch: u32, channel_id: u8) -> Self {
        let mut iid_short = [0u8; 4];
        iid_short.copy_from_slice(&iid[4..8]);
        Self::new(iid_short, superframe_epoch, channel_id)
    }

    /// Encode to wire format (10 bytes).
    ///
    /// Returns the encoded bytes with GATEWAY flag set in type byte.
    pub fn encode(&self) -> [u8; LORA_ANNOUNCE_LEN] {
        let mut buf = [0u8; LORA_ANNOUNCE_LEN];
        buf[0] = GATEWAY_FLAG | 0x01; // Type byte: GATEWAY flag + announce type
        buf[1..5].copy_from_slice(&self.iid_short);
        buf[5..9].copy_from_slice(&self.superframe_epoch.to_be_bytes());
        buf[9] = self.channel_id;
        buf
    }

    /// Decode from wire format.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Payload is too short (< 10 bytes)
    /// - GATEWAY flag is not set in type byte
    pub fn decode(data: &[u8]) -> Result<Self, LoraAnnounceError> {
        if data.len() < LORA_ANNOUNCE_LEN {
            return Err(LoraAnnounceError::TooShort {
                got: data.len(),
                expected: LORA_ANNOUNCE_LEN,
            });
        }

        let type_byte = data[0];
        if !is_gateway_announce(type_byte) {
            return Err(LoraAnnounceError::GatewayFlagNotSet);
        }

        let mut iid_short = [0u8; 4];
        iid_short.copy_from_slice(&data[1..5]);

        let superframe_epoch = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
        let channel_id = data[9];

        // SECURITY: Validate channel_id is in documented range (0-15)
        if channel_id > 15 {
            return Err(LoraAnnounceError::InvalidChannelId { got: channel_id });
        }

        Ok(Self {
            iid_short,
            superframe_epoch,
            channel_id,
        })
    }
}

// ─── IPv6 Address Utilities ──────────────────────────────────────────────────

/// Parse an IPv6 address string to bytes.
///
/// Supports both full and abbreviated formats (e.g., "fe80::1" or "fe80::1234:5678:9abc:def0").
pub fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    // Use standard library parsing
    let addr: std::net::Ipv6Addr = s.parse().ok()?;
    Some(addr.octets())
}

/// Compare two IPv6 addresses as IIDs (last 8 bytes).
///
/// Returns:
/// - -1 if a < b (a wins slot conflict)
/// - 0 if a == b
/// - 1 if a > b (b wins slot conflict)
///
/// Per GCP-6.3: lowest IID (as unsigned big-endian u64) wins.
pub fn compare_ipv6_iids(a: &[u8; 16], b: &[u8; 16]) -> i32 {
    let a_iid: [u8; 8] = a[8..16].try_into().unwrap();
    let b_iid: [u8; 8] = b[8..16].try_into().unwrap();

    let a_val = iid_to_u64(&a_iid);
    let b_val = iid_to_u64(&b_iid);

    match a_val.cmp(&b_val) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

// Re-export time master election from slot module
pub use crate::slot::{
    elect_time_master as elect_gw_time_master, TimeMasterCandidate as GatewayTimeMasterCandidate,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot::{elect_time_master, TimeMasterCandidate};

    // Helper to decode hex string
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ─── GCP-4.1 Backbone Discovery Tests ───────────────────────────────────────

    #[test]
    fn backbone_multicast_addr() {
        // Verify constant matches ff02::1
        let parsed = parse_ipv6(BACKBONE_MULTICAST_STR).unwrap();
        assert_eq!(parsed, BACKBONE_MULTICAST_ADDR);
    }

    #[test]
    fn coap_get_gateway_info() {
        // Vector: coap_get_gateway_info
        // CON GET for /.well-known/lichen-gw/info with mid=1, token=abcd
        let req = BackboneDiscoveryRequest::new(1, &[0xab, 0xcd]);
        let mut buf = [0u8; 64];
        let len = req.encode(&mut buf).unwrap();
        let encoded = hex::encode(&buf[..len]);

        // Expected from test vector (without observe option)
        // Ver=1, Type=0 (CON), TKL=2 -> 0x42
        // Code=0.01 GET -> 0x01
        // MID=0x0001
        // Token=0xabcd
        // Options: Uri-Path x3
        assert_eq!(
            encoded,
            "42010001abcdbb2e77656c6c2d6b6e6f776e096c696368656e2d677704696e666f"
        );
    }

    #[test]
    fn coap_observe_registration() {
        // Vector: coap_observe_registration
        // CON GET with Observe=0 for registering notifications
        let req = BackboneDiscoveryRequest::with_observe(2, &[0xde, 0xad], OBSERVE_REGISTER);
        let mut buf = [0u8; 64];
        let len = req.encode(&mut buf).unwrap();
        let encoded = hex::encode(&buf[..len]);

        // Expected from test vector
        // Ver=1, Type=0 (CON), TKL=2 -> 0x42
        // Code=0.01 GET -> 0x01
        // MID=0x0002
        // Token=0xdead
        // Options: Observe=0 (0x6100), Uri-Path x3
        assert_eq!(
            encoded,
            "42010002dead61005b2e77656c6c2d6b6e6f776e096c696368656e2d677704696e666f"
        );
    }

    #[test]
    fn observe_option_parsing() {
        // Empty value = 0
        assert_eq!(parse_observe_option(&[]), Some(0));
        // Single byte
        assert_eq!(parse_observe_option(&[0x00]), Some(0));
        assert_eq!(parse_observe_option(&[0x01]), Some(1));
        assert_eq!(parse_observe_option(&[0xFF]), Some(255));
        // Two bytes
        assert_eq!(parse_observe_option(&[0x01, 0x00]), Some(256));
        // Three bytes (max)
        assert_eq!(parse_observe_option(&[0xFF, 0xFF, 0xFF]), Some(0xFF_FF_FF));
        // Four bytes is invalid (Observe is max 24-bit)
        assert_eq!(parse_observe_option(&[0x01, 0x00, 0x00, 0x00]), None);
    }

    #[test]
    fn gateway_info_path_segments() {
        // Verify path segments match spec
        assert_eq!(GATEWAY_INFO_PATH[0], ".well-known");
        assert_eq!(GATEWAY_INFO_PATH[1], "lichen-gw");
        assert_eq!(GATEWAY_INFO_PATH[2], "info");
    }

    // ─── Test vectors from gateway_discovery.json (LoRa) ────────────────────────

    #[test]
    fn lora_announce_basic() {
        // Vector: lora_announce_basic
        // iid_short: "1234def0", superframe_epoch: 1720000000, channel_id: 7
        let announce = LoraGatewayAnnounce::new([0x12, 0x34, 0xde, 0xf0], 1720000000, 7);
        let encoded = announce.encode();
        assert_eq!(hex::encode(encoded), "811234def066851e0007");

        // Decode round-trip
        let decoded = LoraGatewayAnnounce::decode(&encoded).unwrap();
        assert_eq!(decoded.iid_short, [0x12, 0x34, 0xde, 0xf0]);
        assert_eq!(decoded.superframe_epoch, 1720000000);
        assert_eq!(decoded.channel_id, 7);
    }

    #[test]
    fn lora_announce_channel_zero() {
        // Vector: lora_announce_channel_zero
        // iid_short: "aabbccdd", superframe_epoch: 1720001234, channel_id: 0
        let announce = LoraGatewayAnnounce::new([0xaa, 0xbb, 0xcc, 0xdd], 1720001234, 0);
        let encoded = announce.encode();
        assert_eq!(hex::encode(encoded), "81aabbccdd668522d200");

        let decoded = LoraGatewayAnnounce::decode(&encoded).unwrap();
        assert_eq!(decoded.superframe_epoch, 1720001234);
        assert_eq!(decoded.channel_id, 0);
    }

    #[test]
    fn lora_announce_max_channel() {
        // Vector: lora_announce_max_channel
        // iid_short: "deadbeef", superframe_epoch: 0, channel_id: 15
        let announce = LoraGatewayAnnounce::new([0xde, 0xad, 0xbe, 0xef], 0, 15);
        let encoded = announce.encode();
        assert_eq!(hex::encode(encoded), "81deadbeef000000000f");

        let decoded = LoraGatewayAnnounce::decode(&encoded).unwrap();
        assert_eq!(decoded.superframe_epoch, 0);
        assert_eq!(decoded.channel_id, 15);
    }

    #[test]
    fn gateway_flag_set() {
        // Vector: gateway_flag_set - type byte 129 (0x81) has GATEWAY flag
        assert!(is_gateway_announce(129));
        assert!(is_gateway_announce(0x81));
        assert!(is_gateway_announce(0x80)); // Just flag, no other bits
        assert!(is_gateway_announce(0xFF)); // All bits set
    }

    #[test]
    fn gateway_flag_clear() {
        // Vector: gateway_flag_clear - type byte 1 does not have GATEWAY flag
        assert!(!is_gateway_announce(1));
        assert!(!is_gateway_announce(0x00));
        assert!(!is_gateway_announce(0x7F)); // All bits except flag
    }

    #[test]
    fn lora_announce_missing_gateway_flag() {
        // Vector: lora_announce_missing_gateway_flag
        // Announce without GATEWAY flag should be rejected
        let data = hex_decode("011234def066851e0007");
        let result = LoraGatewayAnnounce::decode(&data);
        assert!(matches!(result, Err(LoraAnnounceError::GatewayFlagNotSet)));
    }

    #[test]
    fn lora_announce_truncated() {
        // Vector: lora_announce_truncated
        // Payload too short (only 3 bytes)
        let data = hex_decode("811234");
        let result = LoraGatewayAnnounce::decode(&data);
        assert!(matches!(
            result,
            Err(LoraAnnounceError::TooShort {
                got: 3,
                expected: 10
            })
        ));
    }

    #[test]
    fn lora_announce_invalid_channel_id() {
        // Malformed frame with channel_id=255 (out of range 0-15)
        // This should be rejected to prevent tuning to invalid channels
        let data = hex_decode("811234def066851e00ff"); // channel_id=255 at end
        let result = LoraGatewayAnnounce::decode(&data);
        assert!(matches!(
            result,
            Err(LoraAnnounceError::InvalidChannelId { got: 255 })
        ));

        // Edge case: channel_id=16 (just above valid range)
        let data = hex_decode("811234def066851e0010"); // channel_id=16 at end
        let result = LoraGatewayAnnounce::decode(&data);
        assert!(matches!(
            result,
            Err(LoraAnnounceError::InvalidChannelId { got: 16 })
        ));
    }

    #[test]
    fn iid_compare_lower_wins() {
        // Vector: iid_compare_lower_wins
        // a: fe80::0001:0001:0001:0001, b: fe80::ffff:ffff:ffff:ffff
        // Result: -1 (a < b, a wins)
        let a = parse_ipv6("fe80::0001:0001:0001:0001").unwrap();
        let b = parse_ipv6("fe80::ffff:ffff:ffff:ffff").unwrap();
        assert_eq!(compare_ipv6_iids(&a, &b), -1);
    }

    #[test]
    fn iid_compare_higher_loses() {
        // Vector: iid_compare_higher_loses
        // a: fe80::ffff:ffff:ffff:ffff, b: fe80::0001:0001:0001:0001
        // Result: 1 (a > b, a loses)
        let a = parse_ipv6("fe80::ffff:ffff:ffff:ffff").unwrap();
        let b = parse_ipv6("fe80::0001:0001:0001:0001").unwrap();
        assert_eq!(compare_ipv6_iids(&a, &b), 1);
    }

    #[test]
    fn iid_compare_equal() {
        // Vector: iid_compare_equal
        let a = parse_ipv6("fe80::1234:5678:9abc:def0").unwrap();
        let b = parse_ipv6("fe80::1234:5678:9abc:def0").unwrap();
        assert_eq!(compare_ipv6_iids(&a, &b), 0);
    }

    #[test]
    fn time_master_gps_preferred() {
        // Vector: time_master_gps_preferred
        // GPS gateway wins over non-GPS with lower IID
        let non_gps = parse_ipv6("fe80::0001").unwrap();
        let gps = parse_ipv6("fe80::ffff").unwrap();

        let candidates = vec![
            TimeMasterCandidate {
                iid: non_gps[8..16].try_into().unwrap(),
                has_gps: false,
            },
            TimeMasterCandidate {
                iid: gps[8..16].try_into().unwrap(),
                has_gps: true,
            },
        ];

        let elected = elect_time_master(&candidates).unwrap();
        // GPS gateway should be elected despite higher IID
        assert!(elected.has_gps);
        assert_eq!(elected.iid, gps[8..16]);
    }

    #[test]
    fn time_master_lowest_iid_among_gps() {
        // Vector: time_master_lowest_iid_among_gps
        // Lowest IID wins among GPS-equipped gateways
        let high_iid = parse_ipv6("fe80::ffff").unwrap();
        let low_iid = parse_ipv6("fe80::0001").unwrap();

        let candidates = vec![
            TimeMasterCandidate {
                iid: high_iid[8..16].try_into().unwrap(),
                has_gps: true,
            },
            TimeMasterCandidate {
                iid: low_iid[8..16].try_into().unwrap(),
                has_gps: true,
            },
        ];

        let elected = elect_time_master(&candidates).unwrap();
        assert_eq!(elected.iid, low_iid[8..16]);
    }

    #[test]
    fn time_master_lowest_iid_no_gps() {
        // Vector: time_master_lowest_iid_no_gps
        // Lowest IID wins when no GPS available
        let high_iid = parse_ipv6("fe80::ffff").unwrap();
        let low_iid = parse_ipv6("fe80::0001").unwrap();

        let candidates = vec![
            TimeMasterCandidate {
                iid: high_iid[8..16].try_into().unwrap(),
                has_gps: false,
            },
            TimeMasterCandidate {
                iid: low_iid[8..16].try_into().unwrap(),
                has_gps: false,
            },
        ];

        let elected = elect_time_master(&candidates).unwrap();
        assert_eq!(elected.iid, low_iid[8..16]);
    }

    #[test]
    fn time_master_empty() {
        // Vector: time_master_empty
        // No candidates returns None
        let candidates: Vec<TimeMasterCandidate> = vec![];
        let elected = elect_time_master(&candidates);
        assert!(elected.is_none());
    }

    #[test]
    fn from_full_iid() {
        let full_iid: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let announce = LoraGatewayAnnounce::from_full_iid(&full_iid, 1720000000, 5);
        // Should extract last 4 bytes
        assert_eq!(announce.iid_short, [0x9a, 0xbc, 0xde, 0xf0]);
    }
}
