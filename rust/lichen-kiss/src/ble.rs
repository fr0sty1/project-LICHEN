//! BLE GATT service for KISS transport.
//!
//! Provides a BLE GATT service for KISS frame transport, enabling
//! wireless connection to TNC applications like APRSDroid.
//!
//! Service UUID: 00000001-ba2a-46c9-ae49-01b0961f68bb
//!
//! # Characteristics
//!
//! - **TX** (write): App writes KISS frames to send over radio
//! - **RX** (notify): TNC notifies app with received KISS frames
//!
//! Available with feature `kiss-ble`.

use crate::framing::{KissCommand, KissError, KissReader, KissWriter};

/// KISS BLE service UUID.
pub const SERVICE_UUID: &str = "00000001-ba2a-46c9-ae49-01b0961f68bb";

/// TX characteristic UUID (write to device).
pub const TX_CHAR_UUID: &str = "00000002-ba2a-46c9-ae49-01b0961f68bb";

/// RX characteristic UUID (notify from device).
pub const RX_CHAR_UUID: &str = "00000003-ba2a-46c9-ae49-01b0961f68bb";

/// Decoded frame from the app (via TX characteristic write).
#[derive(Debug, Clone)]
pub struct AppFrame {
    /// KISS port (0-15).
    pub port: u8,
    /// KISS command type.
    pub command: u8,
    /// Unescaped payload data.
    pub data: heapless::Vec<u8, 512>,
}

/// BLE KISS TNC handler.
///
/// Manages KISS framing for a BLE GATT connection. Combines a reader for
/// processing incoming TX writes from the app, and a writer for queuing
/// outgoing RX notifications to the app.
///
/// # Example
///
/// ```
/// use lichen_kiss::ble::KissBleTnc;
///
/// let mut tnc = KissBleTnc::new();
///
/// // App writes to TX characteristic (KISS-framed data)
/// tnc.on_tx_write(&[0xC0, 0x00, b'H', b'i', 0xC0]);
///
/// // Process complete frames from app. Distinguishes `Ok(Some)` (valid frame),
/// // `Ok(None)` (no frame ready), and `Err` (parse error).
/// let mut buf = [0u8; 256];
/// match tnc.try_get_app_frame(&mut buf) {
///     Ok(Some(frame)) => {
///         // frame.data contains "Hi", forward to radio
///     }
///     Ok(None) => {
///         // waiting for more data
///     }
///     Err(e) => {
///         // handle parse error (e.g. for debugging or metrics)
///     }
/// }
///
/// // Queue a frame received from radio to send to app
/// tnc.queue_to_app(0, b"Hello from radio").unwrap();
///
/// // Get KISS-encoded frame to notify to app
/// let mut notify_buf = [0u8; 256];
/// if let Some(len) = tnc.try_get_rx_notify(&mut notify_buf) {
///     // Send notify_buf[..len] to RX characteristic
/// }
/// ```
#[derive(Debug)]
pub struct KissBleTnc {
    reader: KissReader,
    writer: KissWriter,
}

impl Default for KissBleTnc {
    fn default() -> Self {
        Self::new()
    }
}

impl KissBleTnc {
    /// Create a new BLE KISS TNC handler.
    pub const fn new() -> Self {
        Self {
            reader: KissReader::new(),
            writer: KissWriter::new(),
        }
    }

    /// Process data written to the TX characteristic by the app.
    ///
    /// The data may contain partial or multiple KISS frames. Use
    /// `try_get_app_frame()` to retrieve complete frames.
    pub fn on_tx_write(&mut self, data: &[u8]) {
        self.reader.feed(data);
    }

    /// Try to get the next complete frame from the app.
    ///
    /// Returns `Ok(Some(AppFrame))` for a valid parsed frame,
    /// `Ok(None)` if no complete frame available yet, or `Err(KissError)`
    /// on parse failure (bad frame is consumed to prevent reader stall).
    /// The `buf` parameter provides scratch space for unescaping.
    pub fn try_get_app_frame(&mut self, buf: &mut [u8]) -> Result<Option<AppFrame>, KissError> {
        let frame = match self.reader.try_read_frame(buf) {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut data: heapless::Vec<u8, 512> = heapless::Vec::new();
        if data.extend_from_slice(frame.data).is_err() {
            return Err(KissError::BufferTooSmall);
        }
        Ok(Some(AppFrame {
            port: frame.port,
            command: frame.command,
            data,
        }))
    }

    /// Queue a frame to send to the app (via RX notify).
    ///
    /// The frame will be KISS-encoded and queued for notification.
    pub fn queue_to_app(&mut self, port: u8, data: &[u8]) -> Result<(), KissError> {
        self.writer.queue_frame(port, KissCommand::Data, data)
    }

    /// Queue a frame with a specific command to send to the app.
    pub fn queue_to_app_cmd(
        &mut self,
        port: u8,
        cmd: KissCommand,
        data: &[u8],
    ) -> Result<(), KissError> {
        self.writer.queue_frame(port, cmd, data)
    }

    /// Try to get the next KISS-encoded frame to notify to the app.
    ///
    /// Returns the number of bytes written to `out`, or `None` if queue is empty.
    pub fn try_get_rx_notify(&mut self, out: &mut [u8]) -> Option<usize> {
        self.writer.try_get_frame(out)
    }

    /// Number of frames pending notification to app.
    pub fn rx_pending(&self) -> usize {
        self.writer.pending_count()
    }

    /// Check if there are frames pending notification.
    pub fn has_rx_pending(&self) -> bool {
        !self.writer.is_empty()
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.reader.clear();
        self.writer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::FEND;

    #[test]
    fn roundtrip_frame() {
        let mut tnc = KissBleTnc::new();
        let mut buf = [0u8; 256];

        // Simulate app writing KISS frame to TX characteristic
        tnc.on_tx_write(&[FEND, 0x00, b'H', b'i', FEND]);

        let frame = tnc.try_get_app_frame(&mut buf).unwrap().unwrap();
        assert_eq!(frame.port, 0);
        assert_eq!(frame.command, 0);
        assert_eq!(&frame.data[..], b"Hi");

        assert!(tnc.try_get_app_frame(&mut buf).unwrap().is_none());
    }

    #[test]
    fn queue_to_app() {
        let mut tnc = KissBleTnc::new();
        let mut buf = [0u8; 256];

        // Queue frame for app
        tnc.queue_to_app(0, b"Hello").unwrap();
        assert_eq!(tnc.rx_pending(), 1);

        // Get encoded frame
        let len = tnc.try_get_rx_notify(&mut buf).unwrap();
        assert_eq!(
            &buf[..len],
            &[FEND, 0x00, b'H', b'e', b'l', b'l', b'o', FEND]
        );
        assert!(!tnc.has_rx_pending());
    }

    #[test]
    fn partial_writes() {
        let mut tnc = KissBleTnc::new();
        let mut buf = [0u8; 256];

        tnc.on_tx_write(&[FEND, 0x00, b'H']);
        assert!(tnc.try_get_app_frame(&mut buf).unwrap().is_none());

        tnc.on_tx_write(&[b'i', FEND]);
        let frame = tnc.try_get_app_frame(&mut buf).unwrap().unwrap();
        assert_eq!(&frame.data[..], b"Hi");
    }
}
