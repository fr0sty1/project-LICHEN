//! CoAP option stubs (RFC 7252 §5.4).

/// Well-known CoAP option numbers.
#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OptionNumber {
    IfMatch = 1,
    UriHost = 3,
    ETag = 4,
    IfNoneMatch = 5,
    Observe = 6,
    UriPort = 7,
    LocationPath = 8,
    UriPath = 11,
    ContentFormat = 12,
    MaxAge = 14,
    UriQuery = 15,
    Accept = 17,
    LocationQuery = 20,
    Block2 = 23,
    Block1 = 27,
    Size2 = 28,
    ProxyUri = 35,
    ProxyScheme = 39,
    Size1 = 60,
}

/// Content-Format numbers used in LICHEN (RFC 7252 §12.3 + RFC 8428).
pub mod content_format {
    /// `application/cbor` — used for SenML-CBOR (RFC 7049).
    pub const CBOR: u16 = 60;
    /// `application/senml+cbor` — SenML records (RFC 8428).
    pub const SENML_CBOR: u16 = 112;
    /// `application/octet-stream`.
    pub const OCTET_STREAM: u16 = 42;
}
