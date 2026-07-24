//! CoAP message codec (RFC 7252, no_std).
//!
//! Zero-copy parsing and building of CoAP messages. Options are parsed lazily
//! via an iterator to avoid allocation.

use crate::message::{MessageCode, MessageType};
use crate::option::OptionNumber;
use lichen_core::error::{BufferTooSmall, TooShort};

/// CoAP version (always 1 for RFC 7252).
pub const COAP_VERSION: u8 = 1;

/// Minimum CoAP header length (4 bytes).
pub const MIN_HEADER_LEN: usize = 4;

/// Maximum token length (8 bytes per RFC 7252).
pub const MAX_TOKEN_LEN: usize = 8;

/// Payload marker byte (0xFF per RFC 7252 §4.1).
pub const PAYLOAD_MARKER: u8 = 0xFF;

/// Common header bytes for test vectors (RFC 7252 §3).
/// CON GET with TKL=0: Ver=1, Type=0 (CON), TKL=0.
pub const CON_GET_HEADER: u8 = 0x40;
/// ACK with TKL=0: Ver=1, Type=2 (ACK), TKL=0.
pub const ACK_HEADER: u8 = 0x60;

/// CoAP parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoapError {
    /// Message too short.
    TooShort(TooShort),
    /// Wrong CoAP version (expected 1).
    WrongVersion(u8),
    /// Token length > 8.
    TokenTooLong(u8),
    /// Invalid option delta (15).
    InvalidOptionDelta,
    /// Invalid option length (15).
    InvalidOptionLength,
    /// Option runs past end of message.
    TruncatedOption,
    /// Payload marker (0xFF) present but followed by zero-length payload
    /// (RFC 7252 §4.1: MUST treat as malformed).
    InvalidPayloadMarker,
    /// Output buffer too small.
    BufferTooSmall(BufferTooSmall),
    /// Invalid Block option value.
    InvalidBlockOption,
    /// Integer option value longer than 4 bytes (u32 limit).
    UintOptionTooLong,
    /// Payload exceeds maximum size.
    PayloadTooLarge,
    /// Block received out of order during blockwise transfer.
    BlockOutOfOrder,
    /// Option number overflow (cumulative delta exceeds u16::MAX).
    OptionNumberOverflow,
}

impl core::fmt::Display for CoapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => write!(f, "CoAP {}", e),
            Self::WrongVersion(v) => write!(f, "wrong CoAP version: {}", v),
            Self::TokenTooLong(n) => write!(f, "token length {} > 8", n),
            Self::InvalidOptionDelta => write!(f, "invalid option delta 15"),
            Self::InvalidOptionLength => write!(f, "invalid option length 15"),
            Self::TruncatedOption => write!(f, "option runs past end of message"),
            Self::InvalidPayloadMarker => {
                write!(f, "payload marker followed by zero-length payload")
            }
            Self::BufferTooSmall(e) => write!(f, "CoAP {}", e),
            Self::InvalidBlockOption => write!(f, "invalid Block option value"),
            Self::UintOptionTooLong => write!(f, "uint option value too long (>4 bytes)"),
            Self::PayloadTooLarge => write!(f, "payload exceeds maximum size"),
            Self::BlockOutOfOrder => write!(f, "block received out of order"),
            Self::OptionNumberOverflow => write!(f, "option number overflow"),
        }
    }
}

impl core::error::Error for CoapError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TooShort(e) => Some(e),
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TooShort> for CoapError {
    fn from(e: TooShort) -> Self {
        Self::TooShort(e)
    }
}

impl From<BufferTooSmall> for CoapError {
    fn from(e: BufferTooSmall) -> Self {
        Self::BufferTooSmall(e)
    }
}

/// A parsed CoAP message (zero-copy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoapPacket<'a> {
    /// Raw message bytes.
    data: &'a [u8],
    /// Offset where options start (after token).
    options_start: usize,
    /// Offset where options end (at the payload marker, or data.len() if none).
    options_end: usize,
    /// Offset where payload starts (after 0xFF marker), or data.len() if none.
    payload_start: usize,
}

impl<'a> CoapPacket<'a> {
    /// Parse a CoAP message from bytes.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, CoapError> {
        if data.len() < MIN_HEADER_LEN {
            return Err(TooShort::new(MIN_HEADER_LEN, data.len()).into());
        }

        let ver = data[0] >> 6;
        if ver != COAP_VERSION {
            return Err(CoapError::WrongVersion(ver));
        }

        let tkl = (data[0] & 0x0F) as usize;
        if tkl > MAX_TOKEN_LEN {
            return Err(CoapError::TokenTooLong(tkl as u8));
        }

        let options_start = MIN_HEADER_LEN + tkl;
        if data.len() < options_start {
            return Err(TooShort::new(options_start, data.len()).into());
        }

        let (options_end, payload_start) = match find_payload_marker(&data[options_start..])? {
            Some(off) => {
                let payload_start = options_start + off + 1;
                if payload_start == data.len() {
                    return Err(CoapError::InvalidPayloadMarker);
                }
                (options_start + off, payload_start)
            }
            None => (data.len(), data.len()),
        };

        Ok(Self {
            data,
            options_start,
            options_end,
            payload_start,
        })
    }

    /// Message type (CON, NON, ACK, RST).
    pub fn msg_type(&self) -> MessageType {
        match (self.data[0] >> 4) & 0x03 {
            0 => MessageType::Confirmable,
            1 => MessageType::NonConfirmable,
            2 => MessageType::Acknowledgement,
            _ => MessageType::Reset,
        }
    }

    /// Message code.
    pub fn code(&self) -> MessageCode {
        MessageCode(self.data[1])
    }

    /// Message ID.
    pub fn message_id(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Token bytes (0-8 bytes).
    pub fn token(&self) -> &'a [u8] {
        &self.data[MIN_HEADER_LEN..self.options_start]
    }

    /// Iterator over options.
    pub fn options(&self) -> OptionIterator<'a> {
        OptionIterator {
            data: &self.data[self.options_start..self.options_end],
            offset: 0,
            current_number: 0,
        }
    }

    /// Payload bytes (empty if no payload marker).
    pub fn payload(&self) -> &'a [u8] {
        if self.payload_start < self.data.len() {
            &self.data[self.payload_start..]
        } else {
            &[]
        }
    }

    /// Raw message bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// True if this is a request (code class 0, detail > 0).
    pub fn is_request(&self) -> bool {
        self.code().class() == 0 && self.code().detail() > 0
    }

    /// True if this is a success response (code class 2).
    pub fn is_success(&self) -> bool {
        self.code().class() == 2
    }
}

/// Validate options and find the payload marker (0xFF) in the options section.
/// Returns offset relative to start of slice, or None if no marker.
/// Also validates that cumulative option numbers do not overflow u16.
fn find_payload_marker(data: &[u8]) -> Result<Option<usize>, CoapError> {
    let mut i = 0;
    let mut current_number: u16 = 0;
    while i < data.len() {
        if data[i] == PAYLOAD_MARKER {
            return Ok(Some(i));
        }
        // Skip option
        let delta_nibble = (data[i] >> 4) & 0x0F;
        let len_nibble = data[i] & 0x0F;
        i += 1;

        // Handle extended delta and compute actual delta value
        let delta: u16 = match delta_nibble {
            13 => {
                if i >= data.len() {
                    return Err(CoapError::TruncatedOption);
                }
                let d = data[i] as u16 + 13;
                i += 1;
                d
            }
            14 => {
                if i + 1 >= data.len() {
                    return Err(CoapError::TruncatedOption);
                }
                let d = ((data[i] as u16) << 8 | data[i + 1] as u16) + 269;
                i += 2;
                d
            }
            15 => return Err(CoapError::InvalidOptionDelta),
            n => n as u16,
        };

        // SECURITY: Detect option number overflow during initial parsing.
        // This fails fast before any options are returned to the caller.
        current_number = current_number
            .checked_add(delta)
            .ok_or(CoapError::OptionNumberOverflow)?;

        // Handle extended length
        let opt_len = match len_nibble {
            13 => {
                if i >= data.len() {
                    return Err(CoapError::TruncatedOption);
                }
                let v = data[i] as usize + 13;
                i += 1;
                v
            }
            14 => {
                if i + 1 >= data.len() {
                    return Err(CoapError::TruncatedOption);
                }
                let v = ((data[i] as usize) << 8 | data[i + 1] as usize) + 269;
                i += 2;
                v
            }
            15 => return Err(CoapError::InvalidOptionLength),
            n => n as usize,
        };

        i = i.saturating_add(opt_len);
        if i > data.len() {
            return Err(CoapError::TruncatedOption);
        }
    }
    Ok(None)
}

/// A single CoAP option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoapOption<'a> {
    /// Option number (cumulative from delta).
    pub number: u16,
    /// Option value.
    pub value: &'a [u8],
}

impl<'a> CoapOption<'a> {
    /// Interpret value as u32 (for integer options like Max-Age, Content-Format).
    ///
    /// Returns `Err(CoapError::UintOptionTooLong)` if value >4 bytes.
    /// Per RFC 7252, these fit in 32 bits; longer values indicate malformed
    /// messages.
    pub fn as_uint(&self) -> Result<u32, CoapError> {
        if self.value.len() > 4 {
            return Err(CoapError::UintOptionTooLong);
        }
        let mut val = 0u32;
        for &b in self.value {
            val = (val << 8) | b as u32;
        }
        Ok(val)
    }

    /// True if this is a Uri-Path option.
    pub fn is_uri_path(&self) -> bool {
        self.number == OptionNumber::UriPath as u16
    }

    /// True if this is a Content-Format option.
    pub fn is_content_format(&self) -> bool {
        self.number == OptionNumber::ContentFormat as u16
    }
}

/// Iterator over CoAP options.
#[derive(Debug, Clone)]
pub struct OptionIterator<'a> {
    data: &'a [u8],
    offset: usize,
    current_number: u16,
}

impl<'a> Iterator for OptionIterator<'a> {
    type Item = Result<CoapOption<'a>, CoapError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        let first = self.data[self.offset];
        if first == PAYLOAD_MARKER {
            return None;
        }

        let delta_nibble = (first >> 4) & 0x0F;
        let len_nibble = first & 0x0F;
        self.offset += 1;

        // Extended delta
        let delta = match delta_nibble {
            13 => {
                if self.offset >= self.data.len() {
                    return Some(Err(CoapError::TruncatedOption));
                }
                let d = self.data[self.offset] as u16 + 13;
                self.offset += 1;
                d
            }
            14 => {
                if self.offset + 1 >= self.data.len() {
                    return Some(Err(CoapError::TruncatedOption));
                }
                let d = ((self.data[self.offset] as u16) << 8 | self.data[self.offset + 1] as u16)
                    + 269;
                self.offset += 2;
                d
            }
            15 => return Some(Err(CoapError::InvalidOptionDelta)),
            n => n as u16,
        };

        // Extended length
        let len = match len_nibble {
            13 => {
                if self.offset >= self.data.len() {
                    return Some(Err(CoapError::TruncatedOption));
                }
                let l = self.data[self.offset] as usize + 13;
                self.offset += 1;
                l
            }
            14 => {
                if self.offset + 1 >= self.data.len() {
                    return Some(Err(CoapError::TruncatedOption));
                }
                let l = ((self.data[self.offset] as usize) << 8
                    | self.data[self.offset + 1] as usize)
                    + 269;
                self.offset += 2;
                l
            }
            15 => return Some(Err(CoapError::InvalidOptionLength)),
            n => n as usize,
        };

        if self.offset + len > self.data.len() {
            return Some(Err(CoapError::TruncatedOption));
        }

        // SECURITY: Reject overflow instead of saturating to prevent protocol violations.
        // Saturating would allow malformed inputs to produce identical parsed output,
        // break round-trip invariants, and potentially bypass URI-based authorization.
        let Some(new_number) = self.current_number.checked_add(delta) else {
            return Some(Err(CoapError::OptionNumberOverflow));
        };
        self.current_number = new_number;
        let value = &self.data[self.offset..self.offset + len];
        self.offset += len;

        Some(Ok(CoapOption {
            number: self.current_number,
            value,
        }))
    }
}

// ── Message Building ────────────────────────────────────────────────────────

/// Builder for CoAP messages.
#[derive(Debug)]
pub struct CoapBuilder<'a> {
    out: &'a mut [u8],
    pos: usize,
    last_option_number: u16,
    options_done: bool,
}

impl<'a> CoapBuilder<'a> {
    /// Start building a CoAP message into `out`.
    ///
    /// Writes the 4-byte header and token immediately.
    pub fn new(
        out: &'a mut [u8],
        msg_type: MessageType,
        code: MessageCode,
        message_id: u16,
        token: &[u8],
    ) -> Result<Self, CoapError> {
        let tkl = token.len();
        if tkl > MAX_TOKEN_LEN {
            return Err(CoapError::TokenTooLong(tkl as u8));
        }
        let header_len = MIN_HEADER_LEN + tkl;
        if out.len() < header_len {
            return Err(BufferTooSmall::new(header_len, out.len()).into());
        }

        out[0] = (COAP_VERSION << 6) | ((msg_type as u8) << 4) | (tkl as u8);
        out[1] = code.0;
        out[2..4].copy_from_slice(&message_id.to_be_bytes());
        out[MIN_HEADER_LEN..header_len].copy_from_slice(token);

        Ok(Self {
            out,
            pos: header_len,
            last_option_number: 0,
            options_done: false,
        })
    }

    /// Add an option. Options must be added in increasing number order.
    pub fn option(&mut self, number: u16, value: &[u8]) -> Result<&mut Self, CoapError> {
        if self.options_done {
            // Can't add options after payload marker
            return Err(CoapError::InvalidOptionDelta);
        }
        if number < self.last_option_number {
            // Options must be in order
            return Err(CoapError::InvalidOptionDelta);
        }

        let delta = number - self.last_option_number;
        let needed = option_encoding_len(delta, value.len());
        if self.pos + needed > self.out.len() {
            return Err(BufferTooSmall::new(self.pos + needed, self.out.len()).into());
        }

        self.pos += write_option(&mut self.out[self.pos..], delta, value);
        self.last_option_number = number;
        Ok(self)
    }

    /// Add a Uri-Path option.
    pub fn uri_path(&mut self, segment: &str) -> Result<&mut Self, CoapError> {
        self.option(OptionNumber::UriPath as u16, segment.as_bytes())
    }

    /// Add a Content-Format option.
    pub fn content_format(&mut self, format: u16) -> Result<&mut Self, CoapError> {
        // Encode as minimal-length uint (CoAP spec Section 3.2)
        // format.to_be_bytes() returns [u8; 2] where [0] is high byte, [1] is low byte
        let bytes = format.to_be_bytes();
        let value: &[u8] = match format {
            0 => &[],                 // Empty for zero
            1..=0xFF => &bytes[1..2], // Low byte only for 1-255
            _ => &bytes[0..2],        // Both bytes for 256+
        };
        self.option(OptionNumber::ContentFormat as u16, value)
    }

    /// Add payload. This finalizes the options section.
    pub fn payload(&mut self, data: &[u8]) -> Result<&mut Self, CoapError> {
        if !data.is_empty() {
            let needed = self.pos + 1 + data.len();
            if needed > self.out.len() {
                return Err(BufferTooSmall::new(needed, self.out.len()).into());
            }
            self.out[self.pos] = PAYLOAD_MARKER;
            self.pos += 1;
            self.out[self.pos..self.pos + data.len()].copy_from_slice(data);
            self.pos += data.len();
        }
        self.options_done = true;
        Ok(self)
    }

    /// Finalize and return the number of bytes written.
    pub fn finish(self) -> usize {
        self.pos
    }

    /// Finalize and return the message slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.out[..self.pos]
    }
}

/// Calculate encoding length for an option.
fn option_encoding_len(delta: u16, value_len: usize) -> usize {
    let delta_ext = if delta < 13 {
        0
    } else if delta < 269 {
        1
    } else {
        2
    };
    let len_ext = if value_len < 13 {
        0
    } else if value_len < 269 {
        1
    } else {
        2
    };
    1 + delta_ext + len_ext + value_len
}

/// Write an option, returning bytes written.
fn write_option(out: &mut [u8], delta: u16, value: &[u8]) -> usize {
    let mut pos = 0;

    // First byte: delta nibble | length nibble
    let (delta_nibble, delta_ext) = if delta < 13 {
        (delta as u8, None)
    } else if delta < 269 {
        (13, Some((delta - 13) as u8))
    } else {
        (14, None) // Will write 2 bytes
    };

    let len = value.len();
    let (len_nibble, len_ext) = if len < 13 {
        (len as u8, None)
    } else if len < 269 {
        (13, Some((len - 13) as u8))
    } else {
        (14, None) // Will write 2 bytes
    };

    out[pos] = (delta_nibble << 4) | len_nibble;
    pos += 1;

    // Extended delta
    if delta_nibble == 13 {
        out[pos] = delta_ext.unwrap();
        pos += 1;
    } else if delta_nibble == 14 {
        let ext = delta - 269;
        out[pos] = (ext >> 8) as u8;
        out[pos + 1] = ext as u8;
        pos += 2;
    }

    // Extended length
    if len_nibble == 13 {
        out[pos] = len_ext.unwrap();
        pos += 1;
    } else if len_nibble == 14 {
        let ext = len - 269;
        out[pos] = (ext >> 8) as u8;
        out[pos + 1] = ext as u8;
        pos += 2;
    }

    // Value
    out[pos..pos + len].copy_from_slice(value);
    pos + len
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;
    use crate::option::content_format;
    use std::vec::Vec;

    #[test]
    fn parse_minimal_message() {
        // CON GET with empty token, no options, no payload (RFC 7252 §3)
        let data = [CON_GET_HEADER, MessageCode::GET.0, 0x00, 0x01];
        let pkt = CoapPacket::from_bytes(&data).unwrap();
        assert_eq!(pkt.msg_type(), MessageType::Confirmable);
        assert_eq!(pkt.code(), MessageCode::GET);
        assert_eq!(pkt.message_id(), 1);
        assert_eq!(pkt.token(), &[]);
        assert_eq!(pkt.payload(), &[]);
        assert!(pkt.is_request());
    }

    #[test]
    fn parse_with_token() {
        // NON POST with 4-byte token
        let data = [0x54, 0x02, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF];
        let pkt = CoapPacket::from_bytes(&data).unwrap();
        assert_eq!(pkt.msg_type(), MessageType::NonConfirmable);
        assert_eq!(pkt.code(), MessageCode::POST);
        assert_eq!(pkt.message_id(), 0x1234);
        assert_eq!(pkt.token(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_with_payload() {
        // ACK 2.05 Content with payload (RFC 7252 §3, §5.2)
        let data = [
            ACK_HEADER,
            MessageCode::CONTENT.0,
            0x00,
            0x01,
            0xFF,
            0x48,
            0x65,
            0x6C,
            0x6C,
            0x6F,
        ];
        let pkt = CoapPacket::from_bytes(&data).unwrap();
        assert_eq!(pkt.msg_type(), MessageType::Acknowledgement);
        assert_eq!(pkt.code(), MessageCode::CONTENT);
        assert!(pkt.is_success());
        assert_eq!(pkt.payload(), b"Hello");
    }

    #[test]
    fn parse_with_options() {
        // GET /test with Uri-Path option (11) (RFC 7252 §5.4)
        // Option: delta=11, len=4, value="test"
        let data = [
            CON_GET_HEADER,
            MessageCode::GET.0,
            0x00,
            0x01, // header
            0xB4,
            b't',
            b'e',
            b's',
            b't', // Uri-Path "test"
        ];
        let pkt = CoapPacket::from_bytes(&data).unwrap();
        let opts: Vec<_> = pkt.options().collect();
        assert_eq!(opts.len(), 1);
        let opt = opts[0].as_ref().unwrap();
        assert_eq!(opt.number, 11);
        assert_eq!(opt.value, b"test");
        assert!(opt.is_uri_path());
    }

    #[test]
    fn parse_extended_delta() {
        // Option with delta=13 (extended 1 byte): delta nibble=13, ext=0 => delta=13 (RFC 7252 §5.4)
        let data = [
            CON_GET_HEADER,
            MessageCode::GET.0,
            0x00,
            0x01, // header
            0xD0,
            0x00, // delta=13, len=0
        ];
        let pkt = CoapPacket::from_bytes(&data).unwrap();
        let opts: Vec<_> = pkt.options().collect();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].as_ref().unwrap().number, 13);
    }

    #[test]
    fn build_simple_get() {
        let mut buf = [0u8; 32];
        let mut builder = CoapBuilder::new(
            &mut buf,
            MessageType::Confirmable,
            MessageCode::GET,
            0x1234,
            &[0xAB, 0xCD],
        )
        .unwrap();
        builder.uri_path("test").unwrap();
        let n = builder.finish();

        let pkt = CoapPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(pkt.msg_type(), MessageType::Confirmable);
        assert_eq!(pkt.code(), MessageCode::GET);
        assert_eq!(pkt.message_id(), 0x1234);
        assert_eq!(pkt.token(), &[0xAB, 0xCD]);

        let paths: Vec<_> = pkt
            .options()
            .filter_map(|o| o.ok())
            .filter(|o| o.is_uri_path())
            .collect();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].value, b"test");
    }

    #[test]
    fn build_post_with_payload() {
        let mut buf = [0u8; 64];
        let mut builder = CoapBuilder::new(
            &mut buf,
            MessageType::NonConfirmable,
            MessageCode::POST,
            0x5678,
            &[],
        )
        .unwrap();
        builder.uri_path("sensors").unwrap();
        builder.uri_path("temp").unwrap();
        builder.content_format(content_format::CBOR).unwrap(); // RFC 7252 §12.3
        builder.payload(b"{\"v\":25}").unwrap();
        let n = builder.finish();

        let pkt = CoapPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(pkt.code(), MessageCode::POST);
        assert_eq!(pkt.payload(), b"{\"v\":25}");

        let opts: Vec<_> = pkt.options().filter_map(|o| o.ok()).collect();
        assert_eq!(opts.len(), 3);
        assert_eq!(opts[0].value, b"sensors");
        assert_eq!(opts[1].value, b"temp");
        assert_eq!(opts[2].number, OptionNumber::ContentFormat as u16);
        assert_eq!(opts[2].as_uint().unwrap(), content_format::CBOR);
    }

    #[test]
    fn roundtrip() {
        let mut buf = [0u8; 64];
        let mut builder = CoapBuilder::new(
            &mut buf,
            MessageType::Confirmable,
            MessageCode::PUT,
            0xABCD,
            &[1, 2, 3, 4],
        )
        .unwrap();
        builder.uri_path("a").unwrap();
        builder.uri_path("b").unwrap();
        builder.payload(b"hello world").unwrap();
        let n = builder.finish();

        let pkt = CoapPacket::from_bytes(&buf[..n]).unwrap();
        assert_eq!(pkt.msg_type(), MessageType::Confirmable);
        assert_eq!(pkt.code(), MessageCode::PUT);
        assert_eq!(pkt.message_id(), 0xABCD);
        assert_eq!(pkt.token(), &[1, 2, 3, 4]);
        assert_eq!(pkt.payload(), b"hello world");
    }

    #[test]
    fn token_too_long() {
        let data = [0x49, 0x01, 0x00, 0x01]; // TKL=9
        assert_eq!(
            CoapPacket::from_bytes(&data),
            Err(CoapError::TokenTooLong(9))
        );
    }

    #[test]
    fn wrong_version() {
        let data = [0x80, 0x01, 0x00, 0x01]; // Ver=2
        assert_eq!(
            CoapPacket::from_bytes(&data),
            Err(CoapError::WrongVersion(2))
        );
    }

    #[test]
    fn too_short() {
        assert!(matches!(
            CoapPacket::from_bytes(&[0x40, 0x01]),
            Err(CoapError::TooShort(_))
        ));
    }

    #[test]
    fn invalid_payload_marker() {
        // Payload marker (0xFF) with no bytes after it per RFC 7252 §4.1
        // MUST be rejected as malformed.
        let data = [CON_GET_HEADER, MessageCode::GET.0, 0x00, 0x01, 0xFF];
        assert_eq!(
            CoapPacket::from_bytes(&data),
            Err(CoapError::InvalidPayloadMarker)
        );
    }

    #[test]
    fn option_number_overflow_fails_fast() {
        // Build a message with two large deltas that would overflow u16.
        // First option: delta = 60000 (uses extended 2-byte delta: nibble 14, ext = 60000-269 = 59731)
        // Second option: delta = 10000 (uses extended 2-byte delta: nibble 14, ext = 10000-269 = 9731)
        // Total would be 70000, which exceeds u16::MAX (65535).
        //
        // The overflow is detected during packet parsing (from_bytes), not during
        // option iteration. This prevents any options from being returned before
        // the overflow is detected.
        let mut data = Vec::new();
        // Header: CON GET, TKL=0, MID=1 (RFC 7252 §3)
        data.extend_from_slice(&[CON_GET_HEADER, MessageCode::GET.0, 0x00, 0x01]);
        // Option 1: delta=60000 (nibble 14), length=0
        // Extended delta = 60000 - 269 = 59731 = 0xE953
        data.push(0xE0); // delta nibble=14, len nibble=0
        data.push(0xE9); // hi byte of 59731
        data.push(0x53); // lo byte of 59731
                         // Option 2: delta=10000 (nibble 14), length=0
                         // Extended delta = 10000 - 269 = 9731 = 0x2603
        data.push(0xE0); // delta nibble=14, len nibble=0
        data.push(0x26); // hi byte of 9731
        data.push(0x03); // lo byte of 9731

        // Overflow is detected at parse time - no options are returned
        assert_eq!(
            CoapPacket::from_bytes(&data),
            Err(CoapError::OptionNumberOverflow)
        );
    }

    #[test]
    fn option_near_max_valid() {
        // Verify that option numbers up to u16::MAX are still valid (RFC 7252 §5.4)
        let mut data = Vec::new();
        // Header: CON GET, TKL=0, MID=1
        data.extend_from_slice(&[CON_GET_HEADER, MessageCode::GET.0, 0x00, 0x01]);
        // Option with delta=65535 (u16::MAX)
        // Extended delta = 65535 - 269 = 65266 = 0xFEF2
        data.push(0xE0); // delta nibble=14, len nibble=0
        data.push(0xFE); // hi byte of 65266
        data.push(0xF2); // lo byte of 65266

        let pkt = CoapPacket::from_bytes(&data).unwrap();
        let opts: Vec<_> = pkt.options().collect();
        assert_eq!(opts.len(), 1);
        assert!(opts[0].is_ok());
        assert_eq!(opts[0].as_ref().unwrap().number, 65535);
    }

    #[test]
    fn option_overflow_at_exact_boundary() {
        // Two options that overflow exactly at u16::MAX + 1 (RFC 7252 §5.4)
        let mut data = Vec::new();
        // Header: CON GET, TKL=0, MID=1
        data.extend_from_slice(&[CON_GET_HEADER, MessageCode::GET.0, 0x00, 0x01]);
        // Option 1: delta=65535 (u16::MAX)
        // Extended delta = 65535 - 269 = 65266 = 0xFEF2
        data.push(0xE0); // delta nibble=14, len nibble=0
        data.push(0xFE); // hi byte of 65266
        data.push(0xF2); // lo byte of 65266
                         // Option 2: delta=1 (overflow: 65535 + 1 = 65536)
        data.push(0x10); // delta nibble=1, len nibble=0

        // Overflow is detected at parse time
        assert_eq!(
            CoapPacket::from_bytes(&data),
            Err(CoapError::OptionNumberOverflow)
        );
    }
}
