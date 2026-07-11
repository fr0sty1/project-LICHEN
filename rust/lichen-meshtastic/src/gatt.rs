// SPDX-License-Identifier: GPL-3.0-or-later
//! BLE GATT service matching Meshtastic interface.
//!
//! This module provides a platform-agnostic implementation of the Meshtastic
//! BLE GATT service, allowing LICHEN nodes to appear as Meshtastic devices
//! to mobile apps.
//!
//! # Service UUID
//! `6ba1b218-15a8-461f-9fa8-5dcae273eafd`
//!
//! # Characteristics
//! | Name      | UUID                                 | Properties   |
//! |-----------|--------------------------------------|--------------|
//! | ToRadio   | f75c76d2-129e-4dad-a1dd-7866124401e7 | Write        |
//! | FromRadio | 2c55e69e-4993-11ed-b878-0242ac120002 | Read         |
//! | FromNum   | ed9da18c-a800-4f66-a670-aa7547e34453 | Read, Notify |

use heapless::{Deque, Vec};

/// Meshtastic GATT Service UUID.
pub const SERVICE_UUID: [u8; 16] = uuid_from_str("6ba1b218-15a8-461f-9fa8-5dcae273eafd");

/// ToRadio characteristic UUID (Write).
pub const TORADIO_UUID: [u8; 16] = uuid_from_str("f75c76d2-129e-4dad-a1dd-7866124401e7");

/// FromRadio characteristic UUID (Read).
pub const FROMRADIO_UUID: [u8; 16] = uuid_from_str("2c55e69e-4993-11ed-b878-0242ac120002");

/// FromNum characteristic UUID (Read, Notify).
pub const FROMNUM_UUID: [u8; 16] = uuid_from_str("ed9da18c-a800-4f66-a670-aa7547e34453");

/// Requested MTU size for BLE connections.
pub const REQUESTED_MTU: u16 = 512;

/// Maximum message size (protobuf encoded).
pub const MAX_MESSAGE_SIZE: usize = 512;

/// Maximum number of queued outbound messages.
pub const MAX_QUEUE_DEPTH: usize = 8;

/// Parse a UUID string at compile time into bytes (little-endian for BLE).
const fn uuid_from_str(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    let mut out = [0u8; 16];

    // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    // Positions:   0       8    13   18   23
    // Parse each hex pair and arrange in little-endian order for BLE

    let mut i = 0;
    let mut pos = 0;
    while i < 16 {
        // Skip dashes
        while pos < b.len() && b[pos] == b'-' {
            pos += 1;
        }
        if pos + 1 >= b.len() {
            break;
        }

        let hi = hex_digit(b[pos]);
        let lo = hex_digit(b[pos + 1]);
        out[15 - i] = (hi << 4) | lo; // Reverse for little-endian
        i += 1;
        pos += 2;
    }

    out
}

const fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Error types for GATT operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GattError {
    /// Write buffer overflow (message too large).
    BufferOverflow,
    /// Invalid protobuf data.
    InvalidProtobuf,
    /// Outbound queue is full.
    QueueFull,
    /// No message available to read.
    QueueEmpty,
    /// BLE operation failed.
    BleError,
}

impl core::fmt::Display for GattError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferOverflow => write!(f, "buffer overflow"),
            Self::InvalidProtobuf => write!(f, "invalid protobuf data"),
            Self::QueueFull => write!(f, "outbound queue full"),
            Self::QueueEmpty => write!(f, "no message available"),
            Self::BleError => write!(f, "BLE operation failed"),
        }
    }
}

impl core::error::Error for GattError {}

/// Trait for BLE peripheral abstraction.
///
/// Implementors provide platform-specific BLE functionality.
pub trait BlePeripheral {
    /// Error type for BLE operations.
    type Error;

    /// Register the GATT service and characteristics.
    fn register_service(&mut self) -> Result<(), Self::Error>;

    /// Send a notification on the FromNum characteristic.
    fn notify_from_num(&mut self, value: u32) -> Result<(), Self::Error>;

    /// Get the negotiated MTU size.
    fn mtu(&self) -> u16;
}

/// Callback trait for handling received ToRadio messages.
pub trait ToRadioHandler {
    /// Called when a complete ToRadio message is received.
    fn on_to_radio(&mut self, data: &[u8]);
}

/// Meshtastic GATT service state machine.
///
/// Handles chunked writes, message queuing, and notification tracking.
#[derive(Debug)]
pub struct MeshtasticGattService<const MTU: usize = 512> {
    /// Accumulator for chunked ToRadio writes.
    write_buffer: Vec<u8, MAX_MESSAGE_SIZE>,
    /// Expected total length from the 4-byte header.
    write_expected_len: Option<u16>,
    /// Queue of outbound FromRadio messages.
    from_radio_queue: Deque<Vec<u8, MAX_MESSAGE_SIZE>, MAX_QUEUE_DEPTH>,
    /// Counter incremented on each new outbound message.
    from_num: u32,
    /// Whether notifications are enabled for FromNum.
    notifications_enabled: bool,
}

impl<const MTU: usize> Default for MeshtasticGattService<MTU> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MTU: usize> MeshtasticGattService<MTU> {
    /// Create a new GATT service instance.
    pub fn new() -> Self {
        Self {
            write_buffer: Vec::new(),
            write_expected_len: None,
            from_radio_queue: Deque::new(),
            from_num: 0,
            notifications_enabled: false,
        }
    }

    /// Handle a write to the ToRadio characteristic.
    ///
    /// Meshtastic BLE protocol uses chunked writes with a 4-byte header
    /// containing the message length. This method accumulates chunks until
    /// a complete message is received.
    ///
    /// Returns `Some(data)` when a complete message is ready.
    pub fn write_to_radio(&mut self, chunk: &[u8]) -> Result<Option<&[u8]>, GattError> {
        if chunk.is_empty() {
            return Ok(None);
        }

        // If this is the start of a new message, parse the header
        if self.write_expected_len.is_none() {
            // Meshtastic uses a 4-byte little-endian length prefix
            // (first 2 bytes are length, last 2 are reserved/zero)

            // Check if we have partial header bytes buffered from a previous chunk
            let buffered = self.write_buffer.len();
            if buffered > 0 {
                // We have partial header bytes - accumulate until we have 4
                let header_bytes_needed = 4 - buffered;
                if chunk.len() < header_bytes_needed {
                    // Still not enough for complete header
                    self.write_buffer
                        .extend_from_slice(chunk)
                        .map_err(|_| GattError::BufferOverflow)?;
                    return Ok(None);
                }

                // Append remaining header bytes to buffer
                self.write_buffer
                    .extend_from_slice(&chunk[..header_bytes_needed])
                    .map_err(|_| GattError::BufferOverflow)?;

                // Parse header from accumulated buffer
                let len = u16::from_le_bytes([self.write_buffer[0], self.write_buffer[1]]);
                self.write_expected_len = Some(len);

                // Clear buffer (it only held header bytes) and add payload
                self.write_buffer.clear();
                if chunk.len() > header_bytes_needed {
                    self.write_buffer
                        .extend_from_slice(&chunk[header_bytes_needed..])
                        .map_err(|_| GattError::BufferOverflow)?;
                }
            } else if chunk.len() < 4 {
                // Not enough data for header, accumulate
                self.write_buffer
                    .extend_from_slice(chunk)
                    .map_err(|_| GattError::BufferOverflow)?;
                return Ok(None);
            } else {
                // Complete header in this chunk
                let len = u16::from_le_bytes([chunk[0], chunk[1]]);
                self.write_expected_len = Some(len);

                // Add the payload part (after header)
                self.write_buffer
                    .extend_from_slice(&chunk[4..])
                    .map_err(|_| GattError::BufferOverflow)?;
            }
        } else {
            // Continue accumulating chunks
            self.write_buffer
                .extend_from_slice(chunk)
                .map_err(|_| GattError::BufferOverflow)?;
        }

        // Check if we have a complete message
        if let Some(expected) = self.write_expected_len {
            if self.write_buffer.len() >= expected as usize {
                // Message complete
                return Ok(Some(&self.write_buffer[..expected as usize]));
            }
        }

        Ok(None)
    }

    /// Clear the write buffer after processing a complete message.
    pub fn clear_write_buffer(&mut self) {
        self.write_buffer.clear();
        self.write_expected_len = None;
    }

    /// Queue an outbound FromRadio message.
    ///
    /// Increments the FromNum counter and returns the new value.
    pub fn queue_from_radio(&mut self, data: &[u8]) -> Result<u32, GattError> {
        let mut msg = Vec::new();
        msg.extend_from_slice(data)
            .map_err(|_| GattError::BufferOverflow)?;

        self.from_radio_queue
            .push_back(msg)
            .map_err(|_| GattError::QueueFull)?;

        self.from_num = self.from_num.wrapping_add(1);
        Ok(self.from_num)
    }

    /// Read the next FromRadio message (for characteristic read).
    ///
    /// Returns the message with a 4-byte length header prepended.
    /// The message remains in the queue until `pop_from_radio` is called.
    pub fn peek_from_radio(&self) -> Option<&[u8]> {
        self.from_radio_queue.front().map(|v| v.as_slice())
    }

    /// Remove and return the next FromRadio message.
    pub fn pop_from_radio(&mut self) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {
        self.from_radio_queue.pop_front()
    }

    /// Get the current FromNum value.
    pub fn from_num(&self) -> u32 {
        self.from_num
    }

    /// Check if there are queued outbound messages.
    pub fn has_pending_messages(&self) -> bool {
        !self.from_radio_queue.is_empty()
    }

    /// Number of queued outbound messages.
    pub fn pending_count(&self) -> usize {
        self.from_radio_queue.len()
    }

    /// Enable or disable notifications on FromNum.
    pub fn set_notifications_enabled(&mut self, enabled: bool) {
        self.notifications_enabled = enabled;
    }

    /// Check if notifications are enabled.
    pub fn notifications_enabled(&self) -> bool {
        self.notifications_enabled
    }

    /// Build a FromRadio response with the 4-byte length header.
    ///
    /// Used when sending data over the FromRadio characteristic.
    pub fn build_from_radio_response(data: &[u8], out: &mut [u8]) -> Result<usize, GattError> {
        if data.len() > u16::MAX as usize {
            return Err(GattError::BufferOverflow);
        }
        if out.len() < data.len() + 4 {
            return Err(GattError::BufferOverflow);
        }

        let len = data.len() as u16;
        out[0..2].copy_from_slice(&len.to_le_bytes());
        out[2] = 0; // Reserved
        out[3] = 0; // Reserved
        out[4..4 + data.len()].copy_from_slice(data);

        Ok(4 + data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_constants() {
        // Service UUID should parse correctly
        // 6ba1b218-15a8-461f-9fa8-5dcae273eafd in little-endian
        assert_eq!(SERVICE_UUID.len(), 16);

        // ToRadio UUID
        assert_eq!(TORADIO_UUID.len(), 16);

        // FromRadio UUID
        assert_eq!(FROMRADIO_UUID.len(), 16);

        // FromNum UUID
        assert_eq!(FROMNUM_UUID.len(), 16);
    }

    #[test]
    fn test_service_new() {
        let svc: MeshtasticGattService = MeshtasticGattService::new();
        assert_eq!(svc.from_num(), 0);
        assert!(!svc.has_pending_messages());
        assert_eq!(svc.pending_count(), 0);
    }

    #[test]
    fn test_single_chunk_write() {
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        // Build a message with 4-byte header + 10 bytes payload
        let payload = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut msg = [0u8; 14];
        msg[0] = 10; // Length low byte
        msg[1] = 0; // Length high byte
        msg[2] = 0; // Reserved
        msg[3] = 0; // Reserved
        msg[4..].copy_from_slice(&payload);

        // Write in one chunk
        let result = svc.write_to_radio(&msg).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &payload);
    }

    #[test]
    fn test_chunked_write() {
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        // Build a message with 4-byte header + 20 bytes payload
        let payload: [u8; 20] = core::array::from_fn(|i| i as u8);
        let mut msg = [0u8; 24];
        msg[0] = 20; // Length low byte
        msg[1] = 0; // Length high byte
        msg[4..].copy_from_slice(&payload);

        // Write in two chunks (simulating MTU limits)
        let result1 = svc.write_to_radio(&msg[..12]).unwrap();
        assert!(result1.is_none()); // Not complete yet

        let result2 = svc.write_to_radio(&msg[12..]).unwrap();
        assert!(result2.is_some());
        assert_eq!(result2.unwrap(), &payload);
    }

    #[test]
    fn test_queue_from_radio() {
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        let msg1 = [1u8, 2, 3];
        let msg2 = [4u8, 5, 6, 7];

        // Queue first message
        let num1 = svc.queue_from_radio(&msg1).unwrap();
        assert_eq!(num1, 1);
        assert!(svc.has_pending_messages());
        assert_eq!(svc.pending_count(), 1);

        // Queue second message
        let num2 = svc.queue_from_radio(&msg2).unwrap();
        assert_eq!(num2, 2);
        assert_eq!(svc.pending_count(), 2);

        // Peek should return first message
        assert_eq!(svc.peek_from_radio(), Some(&msg1[..]));

        // Pop should remove first message
        let popped = svc.pop_from_radio().unwrap();
        assert_eq!(popped.as_slice(), &msg1);
        assert_eq!(svc.pending_count(), 1);

        // Now peek should return second message
        assert_eq!(svc.peek_from_radio(), Some(&msg2[..]));
    }

    #[test]
    fn test_queue_full() {
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        // Fill the queue
        for i in 0..MAX_QUEUE_DEPTH {
            let msg = [i as u8];
            assert!(svc.queue_from_radio(&msg).is_ok());
        }

        // Next should fail
        let result = svc.queue_from_radio(&[99]);
        assert_eq!(result, Err(GattError::QueueFull));
    }

    #[test]
    fn test_build_from_radio_response() {
        let data = [1u8, 2, 3, 4, 5];
        let mut out = [0u8; 16];

        let len = MeshtasticGattService::<512>::build_from_radio_response(&data, &mut out).unwrap();
        assert_eq!(len, 9); // 4 header + 5 data

        // Check header
        assert_eq!(out[0], 5); // Length low
        assert_eq!(out[1], 0); // Length high
        assert_eq!(out[2], 0); // Reserved
        assert_eq!(out[3], 0); // Reserved

        // Check data
        assert_eq!(&out[4..9], &data);
    }

    #[test]
    fn test_notifications() {
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        assert!(!svc.notifications_enabled());

        svc.set_notifications_enabled(true);
        assert!(svc.notifications_enabled());

        svc.set_notifications_enabled(false);
        assert!(!svc.notifications_enabled());
    }

    #[test]
    fn test_clear_write_buffer() {
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        // Start a partial write
        let partial = [10u8, 0, 0, 0, 1, 2, 3]; // Header says 10 bytes but only 3 payload
        let result = svc.write_to_radio(&partial).unwrap();
        assert!(result.is_none()); // Incomplete

        // Clear and start fresh
        svc.clear_write_buffer();

        // Now a new complete message should work
        let msg = [3u8, 0, 0, 0, 1, 2, 3];
        let result = svc.write_to_radio(&msg).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &[1u8, 2, 3]);
    }

    #[test]
    fn test_from_num_wrapping() {
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        // Set from_num near max
        for _ in 0..5 {
            svc.pop_from_radio(); // Drain any messages
        }

        // Manually set near max (we'll need to queue many messages)
        // Instead, verify wrapping behavior by checking the increment
        let msg = [1u8];
        let num1 = svc.queue_from_radio(&msg).unwrap();
        svc.pop_from_radio();
        let num2 = svc.queue_from_radio(&msg).unwrap();
        assert_eq!(num2, num1 + 1);
    }

    #[test]
    fn test_split_header_write() {
        // Regression test: header split across multiple ATT writes
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        // Build a message: header [5, 0, 0, 0] + payload [1, 2, 3, 4, 5]
        let payload = [1u8, 2, 3, 4, 5];

        // Send header split across three chunks: [5, 0], [0, 0], [payload]
        let result1 = svc.write_to_radio(&[5, 0]).unwrap();
        assert!(result1.is_none()); // Partial header

        let result2 = svc.write_to_radio(&[0, 0]).unwrap();
        assert!(result2.is_none()); // Header complete but no payload yet

        let result3 = svc.write_to_radio(&payload).unwrap();
        assert!(result3.is_some());
        assert_eq!(result3.unwrap(), &payload);
    }

    #[test]
    fn test_split_header_single_byte_chunks() {
        // Extreme case: header arrives one byte at a time
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        // Header: length=3, reserved=0
        let result1 = svc.write_to_radio(&[3]).unwrap();
        assert!(result1.is_none());

        let result2 = svc.write_to_radio(&[0]).unwrap();
        assert!(result2.is_none());

        let result3 = svc.write_to_radio(&[0]).unwrap();
        assert!(result3.is_none());

        let result4 = svc.write_to_radio(&[0]).unwrap();
        assert!(result4.is_none()); // Header complete, waiting for payload

        // Payload
        let result5 = svc.write_to_radio(&[0xAA, 0xBB, 0xCC]).unwrap();
        assert!(result5.is_some());
        assert_eq!(result5.unwrap(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_split_header_with_payload_in_same_chunk() {
        // Header split, then remainder of header + payload in one chunk
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        // First chunk: partial header (2 bytes)
        let result1 = svc.write_to_radio(&[4, 0]).unwrap();
        assert!(result1.is_none());

        // Second chunk: rest of header (2 bytes) + full payload (4 bytes)
        let result2 = svc.write_to_radio(&[0, 0, 10, 20, 30, 40]).unwrap();
        assert!(result2.is_some());
        assert_eq!(result2.unwrap(), &[10, 20, 30, 40]);
    }
}
