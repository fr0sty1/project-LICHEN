//! CoAP message types and codes (RFC 7252 §3).

use lichen_core::constants::PORT_COAP;

/// CoAP message type (RFC 7252 §3, 2-bit field).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageType {
    Confirmable = 0,
    NonConfirmable = 1,
    Acknowledgement = 2,
    Reset = 3,
}

/// CoAP message code: class (3 bits) + detail (5 bits), written as `c.dd`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MessageCode(pub u8);

impl MessageCode {
    pub const EMPTY: Self = Self(0x00); // 0.00
    pub const GET: Self = Self(0x01); // 0.01
    pub const POST: Self = Self(0x02); // 0.02
    pub const PUT: Self = Self(0x03); // 0.03
    pub const DELETE: Self = Self(0x04); // 0.04

    // 2.xx Success
    pub const CREATED: Self = Self(0x41); // 2.01
    pub const DELETED: Self = Self(0x42); // 2.02
    pub const VALID: Self = Self(0x43); // 2.03
    pub const CHANGED: Self = Self(0x44); // 2.04
    pub const CONTENT: Self = Self(0x45); // 2.05

    // 4.xx Client Error
    pub const BAD_REQUEST: Self = Self(0x80); // 4.00
    pub const UNAUTHORIZED: Self = Self(0x81); // 4.01
    pub const NOT_FOUND: Self = Self(0x84); // 4.04
    pub const METHOD_NOT_ALLOWED: Self = Self(0x85); // 4.05

    // 5.xx Server Error
    pub const INTERNAL_ERROR: Self = Self(0xA0); // 5.00
    pub const NOT_IMPLEMENTED: Self = Self(0xA1); // 5.01

    pub fn class(self) -> u8 {
        self.0 >> 5
    }
    pub fn detail(self) -> u8 {
        self.0 & 0x1f
    }
}

/// A minimal CoAP message header (wire layout: Ver|T|TKL | Code | Message ID).
pub struct CoapMessage<'a> {
    pub msg_type: MessageType,
    pub code: MessageCode,
    pub message_id: u16,
    pub token: &'a [u8],
    pub payload: &'a [u8],
}

/// Default CoAP port, re-exported for convenience.
pub const COAP_PORT: u16 = PORT_COAP;
