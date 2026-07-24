// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//
//! KISS to LICHEN link layer bridge.
//!
//! Connects KISS framing to the LICHEN link layer, enabling TNC app
//! compatibility (APRSDroid, aprs.fi).
//!
//! Port routing:
//! - Port 0 (AX25): AX.25/APRS wrapped frames (rejected here)
//! - Port 1 (RAW): Raw LICHEN link frames (supported by handle_kiss_frame)
//! - Port 2 (LCI_IPV6): IPv6 for Local Client Interface
//! - Port 3 (LCI_CTRL): Control for Local Client Interface
//! - Ports 4-15: unsupported (rejected with UnsupportedPort)
//!
//! Available with feature `bridge`.

use core::fmt;

use lichen_link::frame::{
    AddrMode, Encryption, FrameError, LichenFrame, MicLength, Signature, MAX_FRAME_LEN,
};
use lichen_link::seqnum::LinkSeqNum;

use crate::framing::{kiss_decode, kiss_encode, kiss_unescape, KissCommand, KissError, FEND};

pub const PORT_AX25: u8 = 0;
pub const PORT_RAW: u8 = 1;
pub const PORT_LCI_IPV6: u8 = 2;
pub const PORT_LCI_CTRL: u8 = 3;

/// Maximum LoRa wire frame size accepted by the bridge.
pub const MAX_PAYLOAD: usize = MAX_FRAME_LEN;

/// Bridge error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BridgeError {
    /// KISS framing error.
    Kiss(KissError),
    /// Link frame error.
    Frame(FrameError),
    /// Unsupported KISS port.
    UnsupportedPort(u8),
    /// Non-data KISS command (config commands are handled separately).
    NotDataFrame(u8),
    /// Payload too large.
    PayloadTooLarge,
    /// Buffer too small.
    BufferTooSmall,
    /// Invalid address length (must be 0, 2, or 8 bytes).
    InvalidAddressLength(usize),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kiss(e) => write!(f, "KISS error: {}", e),
            Self::Frame(e) => write!(f, "frame error: {}", e),
            Self::UnsupportedPort(p) => write!(f, "unsupported KISS port: {}", p),
            Self::NotDataFrame(cmd) => write!(f, "not a data frame: cmd={}", cmd),
            Self::PayloadTooLarge => write!(f, "payload too large"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::InvalidAddressLength(len) => {
                write!(f, "invalid address length: {} (must be 0, 2, or 8)", len)
            }
        }
    }
}

impl core::error::Error for BridgeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Kiss(e) => Some(e),
            Self::Frame(e) => Some(e),
            _ => None,
        }
    }
}

impl From<KissError> for BridgeError {
    fn from(e: KissError) -> Self {
        Self::Kiss(e)
    }
}

impl From<FrameError> for BridgeError {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::FrameTooLarge => Self::PayloadTooLarge,
            FrameError::BufferTooSmall(_) => Self::BufferTooSmall,
            _ => Self::Frame(e),
        }
    }
}

/// Result of decoding a KISS frame for the link layer.
#[derive(Debug, Clone)]
pub struct DecodedKissFrame<'a> {
    /// KISS port the frame arrived on.
    pub port: u8,
    /// Payload extracted from KISS frame (for link layer).
    pub payload: &'a [u8],
}

/// KISS to LICHEN link layer bridge.
///
/// Handles bidirectional conversion between KISS frames and LICHEN link frames.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "bridge")]
/// # {
/// use lichen_kiss::bridge::{KissBridge, PORT_RAW};
///
/// let bridge = KissBridge::default();
///
/// // Encode a link frame payload as KISS
/// let payload = b"Hello";
/// let mut kiss_buf = [0u8; 64];
/// let len = bridge.encode_payload(payload, PORT_RAW, &mut kiss_buf).unwrap();
///
/// // Decode KISS frame back to payload
/// let mut payload_buf = [0u8; 64];
/// let decoded = bridge.decode_kiss_frame(&kiss_buf[..len], &mut payload_buf).unwrap();
/// assert_eq!(decoded.payload, payload);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct KissBridge {
    /// Epoch for outgoing frames.
    ///
    /// SECURITY: Per spec section 4.4, when no persisted epoch is available,
    /// this MUST be initialized to a random value in [128, 255]. The upper-half
    /// initialization ensures half-space replay arithmetic treats new frames
    /// as "ahead" of any stale receiver windows.
    ///
    /// Use [`KissBridge::with_epoch`] to construct with a specific epoch value.
    default_epoch: u8,
    /// Sequence number (incremented on each TX).
    seqnum: LinkSeqNum,
}

impl Default for KissBridge {
    /// Creates a bridge with epoch=128 (minimum compliant value).
    ///
    /// SECURITY: For production use, prefer [`KissBridge::with_epoch`] with
    /// a random value from the platform's RNG in range [128, 255].
    fn default() -> Self {
        Self {
            default_epoch: 128,
            seqnum: LinkSeqNum::new(0),
        }
    }
}

impl KissBridge {
    /// Create a new bridge with the specified epoch.
    ///
    /// SECURITY: Per spec section 4.4, `epoch` MUST be:
    /// - Read from persisted storage (if available), OR
    /// - A random value uniformly distributed in [128, 255]
    ///
    /// # Panics
    ///
    /// Panics if `epoch < 128` to enforce spec-compliant initialization.
    pub fn with_epoch(epoch: u8) -> Self {
        assert!(
            epoch >= 128,
            "SECURITY: epoch MUST be in [128, 255] per spec section 4.4"
        );
        Self {
            default_epoch: epoch,
            seqnum: LinkSeqNum::new(0),
        }
    }

    /// Create a new bridge with default settings.
    ///
    /// DEPRECATED: Use [`KissBridge::with_epoch`] for spec-compliant initialization.
    #[deprecated(
        since = "0.2.0",
        note = "use KissBridge::with_epoch for spec-compliant initialization"
    )]
    pub const fn new() -> Self {
        Self {
            default_epoch: 128,
            seqnum: LinkSeqNum::new(0),
        }
    }

    /// Get the current epoch.
    pub fn epoch(&self) -> u8 {
        self.default_epoch
    }

    /// Set the epoch (for reboot or epoch advance).
    ///
    /// # Panics
    ///
    /// Panics if `epoch < 128` to enforce spec section 4.4 compliance.
    pub fn set_epoch(&mut self, epoch: u8) {
        assert!(
            epoch >= 128,
            "SECURITY: epoch MUST be in [128, 255] per spec section 4.4"
        );
        self.default_epoch = epoch;
    }

    /// Get the current sequence number.
    pub fn seqnum(&self) -> LinkSeqNum {
        self.seqnum
    }

    /// Set the sequence number (for testing or state restore).
    pub fn set_seqnum(&mut self, seqnum: LinkSeqNum) {
        self.seqnum = seqnum;
    }

    /// Decode a KISS frame and extract payload for the link layer.
    ///
    /// # Arguments
    ///
    /// * `kiss_frame` - Complete KISS frame bytes (with FEND delimiters)
    /// * `payload_buf` - Buffer for unescaped payload
    ///
    /// # Returns
    ///
    /// `DecodedKissFrame` containing port and payload reference, or error.
    pub fn decode_kiss_frame<'a>(
        &self,
        kiss_frame: &[u8],
        payload_buf: &'a mut [u8],
    ) -> Result<DecodedKissFrame<'a>, BridgeError> {
        let frame = kiss_decode(kiss_frame)?;

        // Only handle data frames
        if frame.command != KissCommand::Data as u8 {
            return Err(BridgeError::NotDataFrame(frame.command));
        }

        // Unescape the payload
        let payload_len = kiss_unescape(frame.data, payload_buf)?;
        if payload_len > MAX_PAYLOAD {
            return Err(BridgeError::PayloadTooLarge);
        }

        Ok(DecodedKissFrame {
            port: frame.port,
            payload: &payload_buf[..payload_len],
        })
    }

    /// Encode a payload as a KISS data frame.
    ///
    /// # Arguments
    ///
    /// * `payload` - Raw payload bytes
    /// * `port` - KISS port (0-15)
    /// * `out` - Output buffer for KISS frame
    ///
    /// # Returns
    ///
    /// Number of bytes written to `out`, or error.
    pub fn encode_payload(
        &self,
        payload: &[u8],
        port: u8,
        out: &mut [u8],
    ) -> Result<usize, BridgeError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(BridgeError::PayloadTooLarge);
        }
        Ok(kiss_encode(port, KissCommand::Data, payload, out)?)
    }

    /// Decode a KISS frame and parse as a LICHEN link frame.
    ///
    /// This is the full decode path: KISS frame -> unescape -> LICHEN frame parse.
    ///
    /// # Arguments
    ///
    /// * `kiss_frame` - Complete KISS frame bytes
    /// * `work_buf` - Working buffer for unescaped data (must be >= MAX_PAYLOAD)
    ///
    /// # Returns
    ///
    /// Parsed `LichenFrame` referencing data in `work_buf`, or error.
    pub fn handle_kiss_frame<'a>(
        &self,
        kiss_frame: &[u8],
        work_buf: &'a mut [u8],
    ) -> Result<LichenFrame<'a>, BridgeError> {
        let decoded = self.decode_kiss_frame(kiss_frame, work_buf)?;

        if decoded.port != PORT_RAW {
            return Err(BridgeError::UnsupportedPort(decoded.port));
        }

        let frame = LichenFrame::from_bytes(decoded.payload)?;
        Ok(frame)
    }

    /// Encode a LICHEN link frame as a KISS data frame.
    ///
    /// # Arguments
    ///
    /// * `frame` - LICHEN link frame to encode
    /// * `port` - KISS port (use PORT_RAW for raw, PORT_AX25 for AX.25 wrapped)
    /// * `work_buf` - Working buffer for serialized frame (must be >= MAX_PAYLOAD)
    /// * `out` - Output buffer for KISS frame
    ///
    /// # Returns
    ///
    /// Number of bytes written to `out`, or error.
    pub fn encode_link_frame(
        &self,
        frame: &LichenFrame<'_>,
        port: u8,
        work_buf: &mut [u8],
        out: &mut [u8],
    ) -> Result<usize, BridgeError> {
        // Serialize LICHEN frame to work buffer
        let frame_len = frame.write_to(work_buf)?;

        // Encode as KISS frame
        self.encode_payload(&work_buf[..frame_len], port, out)
    }

    /// Create a minimal LICHEN frame from payload and encode as KISS.
    ///
    /// # SECURITY: Creates UNSIGNED frames
    ///
    /// This method produces frames with `Signature::Absent`, violating spec 8.3
    /// which requires "Every originated frame carries a Schnorr signature."
    ///
    /// **Use only for:**
    /// - Loopback testing where signature verification is disabled
    /// - Debugging with a known-permissive receiver
    ///
    /// **For production TX:** Use `lichen_link::LinkLayer::build_frame` (which
    /// signs with the node's identity), then pass the result to `encode_link_frame`.
    ///
    /// # Arguments
    ///
    /// * `payload` - Application payload bytes
    /// * `dst_addr` - Destination address (empty for broadcast)
    /// * `port` - KISS port
    /// * `work_buf` - Working buffer for frame serialization
    /// * `out` - Output buffer for KISS frame
    ///
    /// # Returns
    ///
    /// Number of bytes written to `out`, or error.
    pub fn encode_payload_as_frame(
        &mut self,
        payload: &[u8],
        dst_addr: &[u8],
        port: u8,
        work_buf: &mut [u8],
        out: &mut [u8],
    ) -> Result<usize, BridgeError> {
        // Determine address mode from dst_addr length
        let addr_mode = match dst_addr.len() {
            0 => AddrMode::None,
            2 => AddrMode::Short,
            8 => AddrMode::Extended,
            len => return Err(BridgeError::InvalidAddressLength(len)),
        };

        // Unsigned frames have no MIC; signed frames are built by the security layer.
        let mic = [];

        let seqnum = self.seqnum.fetch_increment();

        let frame = LichenFrame {
            epoch: self.default_epoch,
            seqnum,
            dst_addr,
            payload,
            mic: &mic,
            addr_mode,
            mic_length: MicLength::Bits32,
            signature: Signature::Absent,
            encryption: Encryption::Plaintext,
        };

        self.encode_link_frame(&frame, port, work_buf, out)
    }
}

/// Check if a byte slice starts with a KISS frame delimiter.
///
/// Useful for stream synchronization.
#[inline]
pub fn starts_with_fend(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == FEND
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_kiss_data_frame() {
        let bridge = KissBridge::default();

        // Create a KISS data frame with "Hello" payload on port 0
        let mut kiss_buf = [0u8; 64];
        let len = kiss_encode(0, KissCommand::Data, b"Hello", &mut kiss_buf).unwrap();

        let mut payload_buf = [0u8; 64];
        let decoded = bridge
            .decode_kiss_frame(&kiss_buf[..len], &mut payload_buf)
            .unwrap();

        assert_eq!(decoded.port, 0);
        assert_eq!(decoded.payload, b"Hello");
    }

    #[test]
    fn test_decode_kiss_port_1() {
        let bridge = KissBridge::default();

        let mut kiss_buf = [0u8; 64];
        let len = kiss_encode(1, KissCommand::Data, b"Raw", &mut kiss_buf).unwrap();

        let mut payload_buf = [0u8; 64];
        let decoded = bridge
            .decode_kiss_frame(&kiss_buf[..len], &mut payload_buf)
            .unwrap();

        assert_eq!(decoded.port, 1);
        assert_eq!(decoded.payload, b"Raw");
    }

    #[test]
    fn test_reject_non_data_frame() {
        let bridge = KissBridge::default();

        // TXDELAY command
        let mut kiss_buf = [0u8; 64];
        let len = kiss_encode(0, KissCommand::TxDelay, &[50], &mut kiss_buf).unwrap();

        let mut payload_buf = [0u8; 64];
        let result = bridge.decode_kiss_frame(&kiss_buf[..len], &mut payload_buf);

        assert!(matches!(result, Err(BridgeError::NotDataFrame(1))));
    }

    #[test]
    fn test_encode_payload() {
        let bridge = KissBridge::default();

        let mut out = [0u8; 64];
        let len = bridge.encode_payload(b"Test", PORT_RAW, &mut out).unwrap();

        // Decode it back
        let mut payload_buf = [0u8; 64];
        let decoded = bridge
            .decode_kiss_frame(&out[..len], &mut payload_buf)
            .unwrap();

        assert_eq!(decoded.port, PORT_RAW);
        assert_eq!(decoded.payload, b"Test");
    }

    #[test]
    fn test_wire_frame_size_boundary() {
        let bridge = KissBridge::default();
        let mut kiss_buf = [0u8; 520];
        let accepted = [0u8; MAX_PAYLOAD];

        let kiss_len = bridge
            .encode_payload(&accepted, PORT_RAW, &mut kiss_buf)
            .unwrap();
        let mut decoded = [0u8; MAX_PAYLOAD + 1];
        assert_eq!(
            bridge
                .decode_kiss_frame(&kiss_buf[..kiss_len], &mut decoded)
                .unwrap()
                .payload,
            accepted
        );

        let oversized = [0u8; MAX_PAYLOAD + 1];
        assert_eq!(
            bridge.encode_payload(&oversized, PORT_RAW, &mut kiss_buf),
            Err(BridgeError::PayloadTooLarge)
        );

        let kiss_len = kiss_encode(PORT_RAW, KissCommand::Data, &oversized, &mut kiss_buf).unwrap();
        assert!(matches!(
            bridge.decode_kiss_frame(&kiss_buf[..kiss_len], &mut decoded),
            Err(BridgeError::PayloadTooLarge)
        ));
    }

    #[test]
    fn test_handle_kiss_frame_raw_lichen() {
        let bridge = KissBridge::default();

        // Wire format: Length(0x07) | LLSec(0x00) | Epoch(0x01) | SeqNum(0x0002) | Payload("abc")
        let lichen_bytes: &[u8] = &[0x07, 0x00, 0x01, 0x00, 0x02, b'a', b'b', b'c'];

        // Wrap in KISS frame on port 1 (raw)
        let mut kiss_buf = [0u8; 64];
        let kiss_len =
            kiss_encode(PORT_RAW, KissCommand::Data, lichen_bytes, &mut kiss_buf).unwrap();

        // Decode through bridge
        let mut work_buf = [0u8; 256];
        let frame = bridge
            .handle_kiss_frame(&kiss_buf[..kiss_len], &mut work_buf)
            .unwrap();

        assert_eq!(frame.epoch, 1);
        assert_eq!(frame.seqnum.get(), 2);
        assert_eq!(frame.payload, b"abc");
        assert_eq!(frame.addr_mode, AddrMode::None);
    }

    #[test]
    fn test_encode_link_frame() {
        let bridge = KissBridge::default();

        let mic = [];
        let frame = LichenFrame {
            epoch: 5,
            seqnum: LinkSeqNum::new(100),
            dst_addr: &[],
            payload: b"test",
            mic: &mic,
            addr_mode: AddrMode::None,
            mic_length: MicLength::Bits32,
            signature: Signature::Absent,
            encryption: Encryption::Plaintext,
        };

        let mut work_buf = [0u8; 256];
        let mut out = [0u8; 64];
        let len = bridge
            .encode_link_frame(&frame, PORT_RAW, &mut work_buf, &mut out)
            .unwrap();

        // Decode it back
        let mut decode_buf = [0u8; 256];
        let decoded_frame = bridge
            .handle_kiss_frame(&out[..len], &mut decode_buf)
            .unwrap();

        assert_eq!(decoded_frame.epoch, 5);
        assert_eq!(decoded_frame.seqnum.get(), 100);
        assert_eq!(decoded_frame.payload, b"test");
    }

    #[test]
    fn test_encode_payload_as_frame_broadcast() {
        let mut bridge = KissBridge::with_epoch(200);
        bridge.set_epoch(130); // Valid epoch in [128, 255] per spec section 4.4
        bridge.set_seqnum(LinkSeqNum::new(10));

        let mut work_buf = [0u8; 256];
        let mut out = [0u8; 128];
        let len = bridge
            .encode_payload_as_frame(b"hello", &[], PORT_RAW, &mut work_buf, &mut out)
            .unwrap();

        // Verify seqnum incremented
        assert_eq!(bridge.seqnum().get(), 11);

        // Decode and verify
        let mut decode_buf = [0u8; 256];
        let frame = bridge
            .handle_kiss_frame(&out[..len], &mut decode_buf)
            .unwrap();

        assert_eq!(frame.epoch, 130);
        assert_eq!(frame.seqnum.get(), 10);
        assert_eq!(frame.payload, b"hello");
        assert_eq!(frame.addr_mode, AddrMode::None);
    }

    #[test]
    fn test_encode_payload_as_frame_short_addr() {
        let mut bridge = KissBridge::default();

        let dst_addr = [0xAB, 0xCD];
        let mut work_buf = [0u8; 256];
        let mut out = [0u8; 128];
        let len = bridge
            .encode_payload_as_frame(b"hi", &dst_addr, PORT_RAW, &mut work_buf, &mut out)
            .unwrap();

        let mut decode_buf = [0u8; 256];
        let frame = bridge
            .handle_kiss_frame(&out[..len], &mut decode_buf)
            .unwrap();

        assert_eq!(frame.dst_addr, &[0xAB, 0xCD]);
        assert_eq!(frame.addr_mode, AddrMode::Short);
        assert_eq!(frame.payload, b"hi");
    }

    #[test]
    fn test_roundtrip_with_escaping() {
        let bridge = KissBridge::default();

        // Payload containing bytes that need escaping (0xC0 = FEND, 0xDB = FESC)
        let payload_with_specials: &[u8] = &[0x41, 0xC0, 0xDB, 0x42];

        let mut out = [0u8; 64];
        let len = bridge
            .encode_payload(payload_with_specials, PORT_RAW, &mut out)
            .unwrap();

        let mut decode_buf = [0u8; 64];
        let decoded = bridge
            .decode_kiss_frame(&out[..len], &mut decode_buf)
            .unwrap();

        assert_eq!(decoded.payload, payload_with_specials);
    }

    #[test]
    fn test_starts_with_fend() {
        assert!(starts_with_fend(&[FEND, 0x00, 0x41]));
        assert!(!starts_with_fend(&[0x00, FEND, 0x41]));
        assert!(!starts_with_fend(&[]));
    }

    #[test]
    fn test_bridge_default() {
        let bridge = KissBridge::default();
        // Default epoch is 128 (minimum spec-compliant value)
        assert_eq!(bridge.epoch(), 128);
        assert_eq!(bridge.seqnum().get(), 0);
    }

    #[test]
    fn test_bridge_with_epoch() {
        let bridge = KissBridge::with_epoch(200);
        assert_eq!(bridge.epoch(), 200);
        assert_eq!(bridge.seqnum().get(), 0);
    }

    #[test]
    fn test_bridge_with_epoch_boundary_valid() {
        // SECURITY: Test boundary values per spec section 4.4
        let bridge_min = KissBridge::with_epoch(128);
        assert_eq!(bridge_min.epoch(), 128);

        let bridge_max = KissBridge::with_epoch(255);
        assert_eq!(bridge_max.epoch(), 255);
    }

    #[test]
    #[should_panic(expected = "SECURITY: epoch MUST be in [128, 255]")]
    fn test_bridge_with_epoch_rejects_invalid() {
        // SECURITY: Epoch 127 is invalid per spec section 4.4
        let _ = KissBridge::with_epoch(127);
    }

    #[test]
    #[should_panic(expected = "SECURITY: epoch MUST be in [128, 255]")]
    fn test_bridge_with_epoch_rejects_zero() {
        // SECURITY: Epoch 0 is invalid per spec section 4.4
        let _ = KissBridge::with_epoch(0);
    }

    #[test]
    #[should_panic(expected = "SECURITY: epoch MUST be in [128, 255]")]
    fn test_set_epoch_rejects_invalid() {
        // SECURITY: set_epoch must also validate
        let mut bridge = KissBridge::default();
        bridge.set_epoch(100);
    }

    #[test]
    fn test_set_epoch_accepts_valid() {
        let mut bridge = KissBridge::default();
        bridge.set_epoch(200);
        assert_eq!(bridge.epoch(), 200);

        bridge.set_epoch(128);
        assert_eq!(bridge.epoch(), 128);

        bridge.set_epoch(255);
        assert_eq!(bridge.epoch(), 255);
    }

    #[test]
    fn test_handle_kiss_frame_rejects_port_ax25() {
        let bridge = KissBridge::default();

        let mut kiss_buf = [0u8; 64];
        let len = kiss_encode(PORT_AX25, KissCommand::Data, b"some data", &mut kiss_buf).unwrap();

        let mut work_buf = [0u8; 256];
        let result = bridge.handle_kiss_frame(&kiss_buf[..len], &mut work_buf);

        assert!(matches!(
            result,
            Err(BridgeError::UnsupportedPort(PORT_AX25))
        ));
    }

    #[test]
    fn test_cross_port_injection_rejected() {
        let bridge = KissBridge::default();
        let lichen_bytes = &[0x07, 0x00, 0x01, 0x00, 0x02, b'a', b'b', b'c'];
        let mut kiss_buf = [0u8; 64];
        let len = kiss_encode(2, KissCommand::Data, lichen_bytes, &mut kiss_buf).unwrap();
        let mut work_buf = [0u8; 256];
        let result = bridge.handle_kiss_frame(&kiss_buf[..len], &mut work_buf);
        assert!(matches!(result, Err(BridgeError::UnsupportedPort(2))));
    }
}
