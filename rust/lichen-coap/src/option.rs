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
    Oscore = 9,
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
    /// `text/plain; charset=utf-8`.
    pub const TEXT_PLAIN: u16 = 0;
    /// `application/link-format` (RFC 6690).
    pub const APPLICATION_LINK_FORMAT: u16 = 40;
    /// `application/octet-stream`.
    pub const OCTET_STREAM: u16 = 42;
    /// `application/json`.
    pub const APPLICATION_JSON: u16 = 50;
    /// `application/cbor` — used for SenML-CBOR (RFC 7049).
    pub const CBOR: u16 = 60;
    /// `application/senml+json` (RFC 8428).
    pub const APPLICATION_SENML_JSON: u16 = 110;
    /// `application/senml+cbor` — SenML records (RFC 8428).
    pub const SENML_CBOR: u16 = 112;
}
