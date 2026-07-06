//! UDP port dispatch for application protocols.
//!
//! LICHEN uses UDP port numbers to distinguish application protocols (spec Section 9.1).
//! Ports 5681-5687 share the same upper 12 bits as port 5683 (CoAP), enabling SCHC
//! compression of the 4-byte source+destination port pair to a single byte.
//!
//! Port 10883 (MQTT-SN) requires a dedicated SCHC rule but preserves IANA compliance.

use lichen_core::constants::{
    PORT_APRS_IS, PORT_CAYENNE_LPP, PORT_COAP, PORT_COMPACT_COT, PORT_MQTT_SN, PORT_NMEA,
    PORT_SENML,
};

/// Application protocol identified by UDP destination port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppProtocol {
    /// Compact CoT (Cursor on Target) binary encoding (port 5681).
    CompactCot,
    /// SenML sensor data in CBOR (port 5682, RFC 8428).
    SenML,
    /// CoAP (port 5683, RFC 7252).
    CoAP,
    /// Cayenne Low Power Payload (port 5685).
    CayenneLPP,
    /// APRS-IS ASCII position/message format (port 5686).
    AprsIs,
    /// NMEA 0183 ASCII sentences (port 5687).
    Nmea,
    /// MQTT-SN pub/sub messaging (port 10883, OASIS).
    MqttSn,
}

impl AppProtocol {
    /// Get the standard UDP port for this protocol.
    pub const fn port(self) -> u16 {
        match self {
            Self::CompactCot => PORT_COMPACT_COT,
            Self::SenML => PORT_SENML,
            Self::CoAP => PORT_COAP,
            Self::CayenneLPP => PORT_CAYENNE_LPP,
            Self::AprsIs => PORT_APRS_IS,
            Self::Nmea => PORT_NMEA,
            Self::MqttSn => PORT_MQTT_SN,
        }
    }
}

/// Error returned when port dispatch fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DispatchError {
    /// Port is not a recognized application protocol.
    UnknownPort(u16),
    /// Payload is too short for the protocol.
    PayloadTooShort,
    /// Port 5684 is reserved (CoAPS/DTLS not used, OSCORE instead).
    ReservedPort,
}

impl core::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownPort(p) => write!(f, "unknown application port {}", p),
            Self::PayloadTooShort => write!(f, "payload too short"),
            Self::ReservedPort => write!(f, "port 5684 reserved (use OSCORE, not DTLS)"),
        }
    }
}

/// Result of dispatching a UDP payload by port.
#[derive(Debug)]
pub struct Dispatched<'a> {
    /// Identified application protocol.
    pub protocol: AppProtocol,
    /// Application payload (UDP payload bytes).
    pub payload: &'a [u8],
}

/// Dispatch UDP payload to an application protocol based on destination port.
///
/// Returns the identified protocol and payload reference, or an error if the
/// port is unknown or reserved.
///
/// # Example
///
/// ```
/// use lichen_node::port_dispatch::{dispatch_by_port, AppProtocol};
///
/// let payload = b"\x44\x01\x00\x01\xab"; // CoAP GET
/// let result = dispatch_by_port(5683, payload).unwrap();
/// assert_eq!(result.protocol, AppProtocol::CoAP);
/// ```
pub fn dispatch_by_port(port: u16, payload: &[u8]) -> Result<Dispatched<'_>, DispatchError> {
    let protocol = match port {
        PORT_COMPACT_COT => AppProtocol::CompactCot,
        PORT_SENML => AppProtocol::SenML,
        PORT_COAP => AppProtocol::CoAP,
        5684 => return Err(DispatchError::ReservedPort),
        PORT_CAYENNE_LPP => AppProtocol::CayenneLPP,
        PORT_APRS_IS => AppProtocol::AprsIs,
        PORT_NMEA => AppProtocol::Nmea,
        PORT_MQTT_SN => AppProtocol::MqttSn,
        _ => return Err(DispatchError::UnknownPort(port)),
    };

    Ok(Dispatched { protocol, payload })
}

/// Check if a port is in the SCHC-compressible 568x range.
///
/// Ports 5680-5695 share the same upper 12 bits, allowing SCHC to compress
/// the 4-byte source+destination port pair to a single byte via MSB(12)
/// matching with LSB(4) residue.
#[inline]
pub const fn is_schc_compressible_port(port: u16) -> bool {
    port >= 5680 && port <= 5695
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_coap() {
        let payload = &[0x44, 0x01, 0x00, 0x01, 0xAB];
        let result = dispatch_by_port(PORT_COAP, payload).unwrap();
        assert_eq!(result.protocol, AppProtocol::CoAP);
        assert_eq!(result.payload, payload);
    }

    #[test]
    fn dispatch_compact_cot() {
        let payload = &[0x02, 0x00, 0x00, 0x01]; // PLI subtype
        let result = dispatch_by_port(PORT_COMPACT_COT, payload).unwrap();
        assert_eq!(result.protocol, AppProtocol::CompactCot);
    }

    #[test]
    fn dispatch_senml() {
        // Minimal CBOR array
        let payload = &[0x81, 0xA2];
        let result = dispatch_by_port(PORT_SENML, payload).unwrap();
        assert_eq!(result.protocol, AppProtocol::SenML);
    }

    #[test]
    fn dispatch_cayenne() {
        // Channel 1, temperature type
        let payload = &[0x01, 0x67, 0x00, 0xFA];
        let result = dispatch_by_port(PORT_CAYENNE_LPP, payload).unwrap();
        assert_eq!(result.protocol, AppProtocol::CayenneLPP);
    }

    #[test]
    fn dispatch_aprs_is() {
        let payload = b"!4903.50N/07201.75W-";
        let result = dispatch_by_port(PORT_APRS_IS, payload).unwrap();
        assert_eq!(result.protocol, AppProtocol::AprsIs);
    }

    #[test]
    fn dispatch_nmea() {
        let payload = b"$GPGGA,123519,";
        let result = dispatch_by_port(PORT_NMEA, payload).unwrap();
        assert_eq!(result.protocol, AppProtocol::Nmea);
    }

    #[test]
    fn dispatch_mqtt_sn() {
        // CONNECT message type
        let payload = &[0x04, 0x04, 0x00, 0x01];
        let result = dispatch_by_port(PORT_MQTT_SN, payload).unwrap();
        assert_eq!(result.protocol, AppProtocol::MqttSn);
    }

    #[test]
    fn dispatch_reserved_port_5684() {
        let result = dispatch_by_port(5684, &[]);
        assert_eq!(result.unwrap_err(), DispatchError::ReservedPort);
    }

    #[test]
    fn dispatch_unknown_port() {
        let result = dispatch_by_port(8080, &[]);
        assert_eq!(result.unwrap_err(), DispatchError::UnknownPort(8080));
    }

    #[test]
    fn protocol_port_roundtrip() {
        assert_eq!(AppProtocol::CompactCot.port(), PORT_COMPACT_COT);
        assert_eq!(AppProtocol::SenML.port(), PORT_SENML);
        assert_eq!(AppProtocol::CoAP.port(), PORT_COAP);
        assert_eq!(AppProtocol::CayenneLPP.port(), PORT_CAYENNE_LPP);
        assert_eq!(AppProtocol::AprsIs.port(), PORT_APRS_IS);
        assert_eq!(AppProtocol::Nmea.port(), PORT_NMEA);
        assert_eq!(AppProtocol::MqttSn.port(), PORT_MQTT_SN);
    }

    #[test]
    fn schc_compressible_port_range() {
        // In range
        assert!(is_schc_compressible_port(5680));
        assert!(is_schc_compressible_port(5683));
        assert!(is_schc_compressible_port(5695));

        // Out of range
        assert!(!is_schc_compressible_port(5679));
        assert!(!is_schc_compressible_port(5696));
        assert!(!is_schc_compressible_port(PORT_MQTT_SN));
    }

    #[test]
    fn empty_payload_accepted() {
        // Empty payloads are valid (protocol might reject later)
        let result = dispatch_by_port(PORT_COAP, &[]).unwrap();
        assert_eq!(result.protocol, AppProtocol::CoAP);
        assert!(result.payload.is_empty());
    }
}
