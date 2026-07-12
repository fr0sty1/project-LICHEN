//! Compact Cursor on Target (CoT) binary encoding.
//!
//! Implements the compact CoT format defined in LICHEN spec Section 10.1.1.
//! This provides a minimal binary encoding of tactical messages for LoRa mesh
//! transport, reducing typical CoT XML from 400+ bytes to 17-20 bytes.
//!
//! # Wire Format
//!
//! PLI (Position Location Information) encoding (17 bytes):
//! ```text
//! +--------+--------+--------+--------+--------+--------+
//! | subtype| latitude (int32) | longitude (int32)       |
//! +--------+--------+--------+--------+--------+--------+
//! | altitude| course | speed  | team   | role   |
//! | (int16) |(uint16)|(uint16)| (uint8)| (uint8)|
//! +--------+--------+--------+--------+--------+--------+
//! ```
//!
//! Chat encoding (variable length):
//! ```text
//! +--------+--------+--------//--------+--------+--------//--------+
//! | 0x01   |dest_type| dest_id (if any) | length |    UTF-8 text   |
//! +--------+--------+--------//--------+--------+--------//--------+
//! ```

use core::fmt;

use crate::error::{BufferTooSmall, TooShort};

/// PLI payload size in bytes (excluding subtype byte).
const PLI_PAYLOAD_SIZE: usize = 16;
/// Total PLI size including subtype byte.
pub const PLI_TOTAL_SIZE: usize = 17;

/// Compact CoT message subtype.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompactCotType {
    /// Chat message (b-t-f).
    Chat = 0x01,
    /// Friendly ground PLI (a-f-G-*).
    FriendlyPli = 0x02,
    /// Hostile ground PLI (a-h-G-*).
    HostilePli = 0x03,
    /// Neutral ground PLI (a-n-G-*).
    NeutralPli = 0x04,
    /// Unknown ground PLI (a-u-G-*).
    UnknownPli = 0x05,
    /// Point marker (b-m-p-*).
    Marker = 0x10,
    /// Alert (b-a-*).
    Alert = 0x20,
}

impl CompactCotType {
    /// Parse subtype from byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Chat),
            0x02 => Some(Self::FriendlyPli),
            0x03 => Some(Self::HostilePli),
            0x04 => Some(Self::NeutralPli),
            0x05 => Some(Self::UnknownPli),
            0x10 => Some(Self::Marker),
            0x20 => Some(Self::Alert),
            _ => None,
        }
    }

    /// Returns true if this is a PLI subtype.
    pub fn is_pli(&self) -> bool {
        matches!(
            self,
            Self::FriendlyPli | Self::HostilePli | Self::NeutralPli | Self::UnknownPli
        )
    }
}

/// Team enumeration matching ATAK team colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Team {
    Blue = 0x01,
    Red = 0x02,
    Green = 0x03,
    Orange = 0x04,
    Magenta = 0x05,
    Maroon = 0x06,
    Purple = 0x07,
    Teal = 0x08,
    White = 0x09,
    Yellow = 0x0A,
}

impl Team {
    /// Parse team from byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Blue),
            0x02 => Some(Self::Red),
            0x03 => Some(Self::Green),
            0x04 => Some(Self::Orange),
            0x05 => Some(Self::Magenta),
            0x06 => Some(Self::Maroon),
            0x07 => Some(Self::Purple),
            0x08 => Some(Self::Teal),
            0x09 => Some(Self::White),
            0x0A => Some(Self::Yellow),
            _ => None,
        }
    }
}

/// Chat destination type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestType {
    /// Broadcast to all nodes.
    Broadcast = 0x00,
    /// Send to a specific team.
    Team = 0x01,
    /// Direct message to a specific IID.
    Direct = 0x02,
}

impl DestType {
    /// Parse destination type from byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Broadcast),
            0x01 => Some(Self::Team),
            0x02 => Some(Self::Direct),
            _ => None,
        }
    }

    /// Returns the size of the dest_id field for this destination type.
    pub fn dest_id_size(&self) -> usize {
        match self {
            Self::Broadcast => 0,
            Self::Team => 1,
            Self::Direct => 8,
        }
    }
}

/// Position Location Information payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PliPayload {
    /// Latitude in microdegrees (int32).
    pub lat_microdeg: i32,
    /// Longitude in microdegrees (int32).
    pub lon_microdeg: i32,
    /// Altitude in decimeters (int16).
    pub alt_dm: i16,
    /// Course in centidegrees (uint16, 0-35999).
    pub course_cdeg: u16,
    /// Speed in cm/s (uint16).
    pub speed_cm_s: u16,
    /// Team identifier.
    pub team: u8,
    /// Role identifier.
    pub role: u8,
}

impl PliPayload {
    /// Encode PLI payload to buffer (excluding subtype byte).
    /// Returns number of bytes written (always 16).
    fn encode(&self, buf: &mut [u8]) -> Result<usize, BufferTooSmall> {
        if buf.len() < PLI_PAYLOAD_SIZE {
            return Err(BufferTooSmall::new(PLI_PAYLOAD_SIZE, buf.len()));
        }

        buf[0..4].copy_from_slice(&self.lat_microdeg.to_be_bytes());
        buf[4..8].copy_from_slice(&self.lon_microdeg.to_be_bytes());
        buf[8..10].copy_from_slice(&self.alt_dm.to_be_bytes());
        buf[10..12].copy_from_slice(&self.course_cdeg.to_be_bytes());
        buf[12..14].copy_from_slice(&self.speed_cm_s.to_be_bytes());
        buf[14] = self.team;
        buf[15] = self.role;

        Ok(PLI_PAYLOAD_SIZE)
    }

    /// Decode PLI payload from buffer (excluding subtype byte).
    fn decode(data: &[u8]) -> Result<Self, TooShort> {
        if data.len() < PLI_PAYLOAD_SIZE {
            return Err(TooShort::new(PLI_PAYLOAD_SIZE, data.len()));
        }

        Ok(Self {
            lat_microdeg: i32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            lon_microdeg: i32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            alt_dm: i16::from_be_bytes([data[8], data[9]]),
            course_cdeg: u16::from_be_bytes([data[10], data[11]]),
            speed_cm_s: u16::from_be_bytes([data[12], data[13]]),
            team: data[14],
            role: data[15],
        })
    }
}

/// Chat destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatDest {
    /// Broadcast to all nodes.
    Broadcast,
    /// Send to a specific team.
    Team(u8),
    /// Direct message to a specific IID (8 bytes).
    Direct([u8; 8]),
}

impl ChatDest {
    /// Get the destination type.
    pub fn dest_type(&self) -> DestType {
        match self {
            Self::Broadcast => DestType::Broadcast,
            Self::Team(_) => DestType::Team,
            Self::Direct(_) => DestType::Direct,
        }
    }
}

/// Maximum message length for chat (single byte length field).
pub const MAX_CHAT_MESSAGE_LEN: usize = 255;

/// Chat message payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatPayload {
    /// Destination.
    pub dest: ChatDest,
    /// UTF-8 message text.
    message: heapless::Vec<u8, 255>,
}

impl ChatPayload {
    /// Create a new chat payload.
    pub fn new(dest: ChatDest, message: &[u8]) -> Option<Self> {
        let mut msg = heapless::Vec::new();
        msg.extend_from_slice(message).ok()?;
        Some(Self { dest, message: msg })
    }

    /// Get the message bytes.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Calculate encoded size.
    fn encoded_size(&self) -> usize {
        // subtype + dest_type + dest_id + length + message
        1 + 1 + self.dest.dest_type().dest_id_size() + 1 + self.message.len()
    }

    /// Encode chat payload to buffer.
    fn encode(&self, buf: &mut [u8]) -> Result<usize, BufferTooSmall> {
        let required = self.encoded_size();
        if buf.len() < required {
            return Err(BufferTooSmall::new(required, buf.len()));
        }

        let mut pos = 0;
        buf[pos] = CompactCotType::Chat as u8;
        pos += 1;
        buf[pos] = self.dest.dest_type() as u8;
        pos += 1;

        match &self.dest {
            ChatDest::Broadcast => {}
            ChatDest::Team(team) => {
                buf[pos] = *team;
                pos += 1;
            }
            ChatDest::Direct(iid) => {
                buf[pos..pos + 8].copy_from_slice(iid);
                pos += 8;
            }
        }

        buf[pos] = self.message.len() as u8;
        pos += 1;
        buf[pos..pos + self.message.len()].copy_from_slice(&self.message);
        pos += self.message.len();

        Ok(pos)
    }

    /// Decode chat payload from buffer (including subtype byte).
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        // Minimum: subtype + dest_type + length = 3 bytes
        if data.len() < 3 {
            return Err(DecodeError::TooShort(TooShort::new(3, data.len())));
        }

        // data[0] is subtype (0x01), should be verified by caller but assert for defense-in-depth
        debug_assert_eq!(
            data[0],
            CompactCotType::Chat as u8,
            "ChatPayload::decode called with non-Chat subtype"
        );
        let dest_type =
            DestType::from_byte(data[1]).ok_or(DecodeError::InvalidDestType(data[1]))?;

        let dest_id_size = dest_type.dest_id_size();
        let header_size = 2 + dest_id_size + 1; // subtype + dest_type + dest_id + length

        if data.len() < header_size {
            return Err(DecodeError::TooShort(TooShort::new(
                header_size,
                data.len(),
            )));
        }

        let dest = match dest_type {
            DestType::Broadcast => ChatDest::Broadcast,
            DestType::Team => ChatDest::Team(data[2]),
            DestType::Direct => {
                let mut iid = [0u8; 8];
                iid.copy_from_slice(&data[2..10]);
                ChatDest::Direct(iid)
            }
        };

        let len_pos = 2 + dest_id_size;
        let msg_len = data[len_pos] as usize;
        let total_size = header_size + msg_len;

        if data.len() < total_size {
            return Err(DecodeError::TooShort(TooShort::new(total_size, data.len())));
        }

        let msg_start = len_pos + 1;
        let msg_bytes = &data[msg_start..msg_start + msg_len];

        let payload = ChatPayload::new(dest, msg_bytes).ok_or(DecodeError::MessageTooLong)?;
        Ok(payload)
    }
}

/// Compact CoT message.
///
/// The Chat variant is larger than PLI due to the message buffer. Boxing is not
/// available in `no_std`. The size difference is acceptable given that chat
/// messages are the primary use case and PLI messages are typically short-lived.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum CompactCot {
    /// Chat message.
    Chat(ChatPayload),
    /// Friendly ground PLI.
    FriendlyPli(PliPayload),
    /// Hostile ground PLI.
    HostilePli(PliPayload),
    /// Neutral ground PLI.
    NeutralPli(PliPayload),
    /// Unknown ground PLI.
    UnknownPli(PliPayload),
    /// Point marker (payload TBD per spec).
    Marker,
    /// Alert (payload TBD per spec).
    Alert,
}

impl CompactCot {
    /// Get the subtype for this message.
    pub fn subtype(&self) -> CompactCotType {
        match self {
            Self::Chat(_) => CompactCotType::Chat,
            Self::FriendlyPli(_) => CompactCotType::FriendlyPli,
            Self::HostilePli(_) => CompactCotType::HostilePli,
            Self::NeutralPli(_) => CompactCotType::NeutralPli,
            Self::UnknownPli(_) => CompactCotType::UnknownPli,
            Self::Marker => CompactCotType::Marker,
            Self::Alert => CompactCotType::Alert,
        }
    }

    /// Calculate encoded size.
    pub fn encoded_size(&self) -> usize {
        match self {
            Self::Chat(c) => c.encoded_size(),
            Self::FriendlyPli(_)
            | Self::HostilePli(_)
            | Self::NeutralPli(_)
            | Self::UnknownPli(_) => PLI_TOTAL_SIZE,
            Self::Marker | Self::Alert => 1, // Just subtype byte for now
        }
    }
}

/// Decoding error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// Input buffer too short.
    TooShort(TooShort),
    /// Unknown subtype byte.
    UnknownSubtype(u8),
    /// Invalid destination type.
    InvalidDestType(u8),
    /// Message too long for internal buffer.
    MessageTooLong,
    /// Expected a PLI subtype but got a different subtype.
    NotPliSubtype(u8),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(e) => write!(f, "{}", e),
            Self::UnknownSubtype(b) => write!(f, "unknown compact CoT subtype: 0x{:02x}", b),
            Self::InvalidDestType(b) => write!(f, "invalid chat destination type: 0x{:02x}", b),
            Self::MessageTooLong => write!(f, "chat message exceeds 255 bytes"),
            Self::NotPliSubtype(b) => write!(f, "expected PLI subtype, got: 0x{:02x}", b),
        }
    }
}

impl core::error::Error for DecodeError {}

/// Encoding error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// Output buffer too small.
    BufferTooSmall(BufferTooSmall),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall(e) => write!(f, "{}", e),
        }
    }
}

impl core::error::Error for EncodeError {}

/// Encode a PLI payload with its subtype byte.
fn encode_pli(
    subtype: CompactCotType,
    payload: &PliPayload,
    buf: &mut [u8],
) -> Result<usize, EncodeError> {
    if buf.is_empty() {
        return Err(EncodeError::BufferTooSmall(BufferTooSmall::new(
            PLI_TOTAL_SIZE,
            0,
        )));
    }
    buf[0] = subtype as u8;
    payload
        .encode(&mut buf[1..])
        .map(|n| n + 1)
        .map_err(EncodeError::BufferTooSmall)
}

/// Encode a compact CoT message to a buffer.
///
/// Returns the number of bytes written on success.
pub fn encode(cot: &CompactCot, buf: &mut [u8]) -> Result<usize, EncodeError> {
    let required = cot.encoded_size();
    if buf.len() < required {
        return Err(EncodeError::BufferTooSmall(BufferTooSmall::new(
            required,
            buf.len(),
        )));
    }

    match cot {
        CompactCot::Chat(c) => c.encode(buf).map_err(EncodeError::BufferTooSmall),
        CompactCot::FriendlyPli(p) => encode_pli(CompactCotType::FriendlyPli, p, buf),
        CompactCot::HostilePli(p) => encode_pli(CompactCotType::HostilePli, p, buf),
        CompactCot::NeutralPli(p) => encode_pli(CompactCotType::NeutralPli, p, buf),
        CompactCot::UnknownPli(p) => encode_pli(CompactCotType::UnknownPli, p, buf),
        CompactCot::Marker => {
            buf[0] = CompactCotType::Marker as u8;
            Ok(1)
        }
        CompactCot::Alert => {
            buf[0] = CompactCotType::Alert as u8;
            Ok(1)
        }
    }
}

/// Decode a PLI payload from data buffer, constructing the appropriate CompactCot variant.
fn decode_pli(subtype: CompactCotType, data: &[u8]) -> Result<CompactCot, DecodeError> {
    if data.len() < PLI_TOTAL_SIZE {
        return Err(DecodeError::TooShort(TooShort::new(
            PLI_TOTAL_SIZE,
            data.len(),
        )));
    }
    let payload = PliPayload::decode(&data[1..]).map_err(DecodeError::TooShort)?;
    match subtype {
        CompactCotType::FriendlyPli => Ok(CompactCot::FriendlyPli(payload)),
        CompactCotType::HostilePli => Ok(CompactCot::HostilePli(payload)),
        CompactCotType::NeutralPli => Ok(CompactCot::NeutralPli(payload)),
        CompactCotType::UnknownPli => Ok(CompactCot::UnknownPli(payload)),
        // SECURITY: Return error instead of panicking if called with non-PLI subtype.
        // Currently decode() guarantees only PLI subtypes reach here, but this
        // protects against future refactoring that might break that invariant.
        _ => Err(DecodeError::NotPliSubtype(subtype as u8)),
    }
}

/// Decode a compact CoT message from a buffer.
pub fn decode(data: &[u8]) -> Result<CompactCot, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::TooShort(TooShort::new(1, 0)));
    }

    let subtype = CompactCotType::from_byte(data[0]).ok_or(DecodeError::UnknownSubtype(data[0]))?;

    match subtype {
        CompactCotType::Chat => {
            let payload = ChatPayload::decode(data)?;
            Ok(CompactCot::Chat(payload))
        }
        CompactCotType::FriendlyPli
        | CompactCotType::HostilePli
        | CompactCotType::NeutralPli
        | CompactCotType::UnknownPli => decode_pli(subtype, data),
        CompactCotType::Marker => Ok(CompactCot::Marker),
        CompactCotType::Alert => Ok(CompactCot::Alert),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn bytes_to_hex(bytes: &[u8]) -> std::string::String {
        bytes.iter().map(|b| std::format!("{:02x}", b)).collect()
    }

    // Test vectors from test/vectors/compact_cot.json

    #[test]
    fn pli_friendly_ground_origin() {
        let expected_hex = "0200000000000000000000000000000101";
        let expected = hex_to_bytes(expected_hex);

        let pli = PliPayload {
            lat_microdeg: 0,
            lon_microdeg: 0,
            alt_dm: 0,
            course_cdeg: 0,
            speed_cm_s: 0,
            team: 1,
            role: 1,
        };
        let cot = CompactCot::FriendlyPli(pli);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(len, 17);
        assert_eq!(&buf[..len], &expected[..]);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn pli_hostile_ground_negative_coords() {
        let expected_hex = "03fd49b9a0f8b2cc6003e8697801f40201";
        let expected = hex_to_bytes(expected_hex);

        let pli = PliPayload {
            lat_microdeg: -45500000,
            lon_microdeg: -122500000,
            alt_dm: 1000,
            course_cdeg: 27000,
            speed_cm_s: 500,
            team: 2,
            role: 1,
        };
        let cot = CompactCot::HostilePli(pli);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(len, 17);
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn pli_neutral_ground_london() {
        let expected_hex = "040311f0c8fffe0cc8006e119400960301";
        let expected = hex_to_bytes(expected_hex);

        let pli = PliPayload {
            lat_microdeg: 51507400,
            lon_microdeg: -127800,
            alt_dm: 110,
            course_cdeg: 4500,
            speed_cm_s: 150,
            team: 3,
            role: 1,
        };
        let cot = CompactCot::NeutralPli(pli);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn pli_unknown_ground_tokyo() {
        let expected_hex = "05022060280852e4fc0190465000000901";
        let expected = hex_to_bytes(expected_hex);

        let pli = PliPayload {
            lat_microdeg: 35676200,
            lon_microdeg: 139650300,
            alt_dm: 400,
            course_cdeg: 18000,
            speed_cm_s: 0,
            team: 9,
            role: 1,
        };
        let cot = CompactCot::UnknownPli(pli);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn pli_friendly_max_positive_coords() {
        let expected_hex = "02055d4a800aba95007fff8c9fffff0101";
        let expected = hex_to_bytes(expected_hex);

        let pli = PliPayload {
            lat_microdeg: 90000000,
            lon_microdeg: 180000000,
            alt_dm: 32767,
            course_cdeg: 35999,
            speed_cm_s: 65535,
            team: 1,
            role: 1,
        };
        let cot = CompactCot::FriendlyPli(pli);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn pli_friendly_max_negative_coords() {
        let expected_hex = "02faa2b580f5456b008000000000000101";
        let expected = hex_to_bytes(expected_hex);

        let pli = PliPayload {
            lat_microdeg: -90000000,
            lon_microdeg: -180000000,
            alt_dm: -32768,
            course_cdeg: 0,
            speed_cm_s: 0,
            team: 1,
            role: 1,
        };
        let cot = CompactCot::FriendlyPli(pli);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn pli_friendly_zero_altitude() {
        let expected_hex = "020311f0c8fffe0cc80000000000000101";
        let expected = hex_to_bytes(expected_hex);

        let pli = PliPayload {
            lat_microdeg: 51507400,
            lon_microdeg: -127800,
            alt_dm: 0,
            course_cdeg: 0,
            speed_cm_s: 0,
            team: 1,
            role: 1,
        };
        let cot = CompactCot::FriendlyPli(pli);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn pli_friendly_max_speed() {
        let expected_hex = "02000000000000000000000000ffff0101";
        let expected = hex_to_bytes(expected_hex);

        let pli = PliPayload {
            lat_microdeg: 0,
            lon_microdeg: 0,
            alt_dm: 0,
            course_cdeg: 0,
            speed_cm_s: 65535,
            team: 1,
            role: 1,
        };
        let cot = CompactCot::FriendlyPli(pli);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn chat_broadcast_hello() {
        let expected_hex = "01000548656c6c6f";
        let expected = hex_to_bytes(expected_hex);

        let chat = ChatPayload::new(ChatDest::Broadcast, b"Hello").unwrap();
        let cot = CompactCot::Chat(chat);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn chat_team_blue_move() {
        let expected_hex = "010101084d6f7665206f7574";
        let expected = hex_to_bytes(expected_hex);

        let chat = ChatPayload::new(ChatDest::Team(1), b"Move out").unwrap();
        let cot = CompactCot::Chat(chat);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn chat_team_red_hold() {
        let expected_hex = "0101020d486f6c6420706f736974696f6e";
        let expected = hex_to_bytes(expected_hex);

        let chat = ChatPayload::new(ChatDest::Team(2), b"Hold position").unwrap();
        let cot = CompactCot::Chat(chat);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn chat_direct_ack() {
        let expected_hex = "010200112233445566770341636b";
        let expected = hex_to_bytes(expected_hex);

        let iid: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let chat = ChatPayload::new(ChatDest::Direct(iid), b"Ack").unwrap();
        let cot = CompactCot::Chat(chat);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn chat_broadcast_empty() {
        let expected_hex = "010000";
        let expected = hex_to_bytes(expected_hex);

        let chat = ChatPayload::new(ChatDest::Broadcast, b"").unwrap();
        let cot = CompactCot::Chat(chat);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn chat_team_yellow() {
        let expected_hex = "01010a08436865636b20696e";
        let expected = hex_to_bytes(expected_hex);

        let chat = ChatPayload::new(ChatDest::Team(10), b"Check in").unwrap();
        let cot = CompactCot::Chat(chat);

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn marker_point() {
        let expected_hex = "10";
        let expected = hex_to_bytes(expected_hex);

        let cot = CompactCot::Marker;

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn alert() {
        let expected_hex = "20";
        let expected = hex_to_bytes(expected_hex);

        let cot = CompactCot::Alert;

        // Encode
        let mut buf = [0u8; 64];
        let len = encode(&cot, &mut buf).unwrap();
        assert_eq!(bytes_to_hex(&buf[..len]), expected_hex);

        // Decode
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, cot);
    }

    #[test]
    fn decode_unknown_subtype() {
        let data = [0xFF];
        let result = decode(&data);
        assert!(matches!(result, Err(DecodeError::UnknownSubtype(0xFF))));
    }

    #[test]
    fn decode_empty_buffer() {
        let data: [u8; 0] = [];
        let result = decode(&data);
        assert!(matches!(result, Err(DecodeError::TooShort(_))));
    }

    #[test]
    fn decode_pli_too_short() {
        // Only 10 bytes when 17 required
        let data = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = decode(&data);
        assert!(matches!(result, Err(DecodeError::TooShort(_))));
    }

    #[test]
    fn encode_buffer_too_small() {
        let pli = PliPayload {
            lat_microdeg: 0,
            lon_microdeg: 0,
            alt_dm: 0,
            course_cdeg: 0,
            speed_cm_s: 0,
            team: 1,
            role: 1,
        };
        let cot = CompactCot::FriendlyPli(pli);

        let mut buf = [0u8; 5]; // Too small
        let result = encode(&cot, &mut buf);
        assert!(matches!(result, Err(EncodeError::BufferTooSmall(_))));
    }
}
