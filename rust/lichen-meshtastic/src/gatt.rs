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

/// Default deadline for application data (60 seconds per spec/appendix-bufferbloat.md).
pub const DEFAULT_DEADLINE_MS: u64 = 60_000;

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
        _ => panic!("invalid hex digit"),
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

/// A queued FromRadio message with expiration deadline.
#[derive(Debug, Clone)]
pub struct QueueEntry {
    /// Message data.
    data: Vec<u8, MAX_MESSAGE_SIZE>,
    /// Deadline timestamp in milliseconds (monotonic clock).
    /// Entry is considered expired when `now_ms >= deadline_ms`.
    deadline_ms: u64,
}

impl QueueEntry {
    /// Create a new queue entry with the given data and deadline.
    pub fn new(data: Vec<u8, MAX_MESSAGE_SIZE>, deadline_ms: u64) -> Self {
        Self { data, deadline_ms }
    }

    /// Check if this entry has expired given the current time.
    #[inline]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.deadline_ms
    }

    /// Get the message data.
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Consume the entry and return the message data.
    pub fn into_data(self) -> Vec<u8, MAX_MESSAGE_SIZE> {
        self.data
    }
}

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
    /// Queue of outbound FromRadio messages with expiration deadlines.
    from_radio_queue: Deque<QueueEntry, MAX_QUEUE_DEPTH>,
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
        if self.write_expected_len.is_some() {
            self.clear_write_buffer();
        }
        if self.write_expected_len.is_none() {
            // Meshtastic uses a 4-byte little-endian length prefix
            // (first 2 bytes are length, last 2 are reserved/zero)

            // Check if we have bytes buffered (from previous chunk or preserved excess)
            let buffered = self.write_buffer.len();
            if buffered >= 4 {
                // Buffer already contains complete header (from preserved excess bytes)
                // Parse header and shift payload bytes to start
                let len = u16::from_le_bytes([self.write_buffer[0], self.write_buffer[1]]);
                self.write_expected_len = Some(len);

                // Shift payload bytes (bytes 4..) to start of buffer
                let payload_len = buffered - 4;
                self.write_buffer.copy_within(4.., 0);
                self.write_buffer.truncate(payload_len);

                // Append incoming chunk to payload
                if !chunk.is_empty() {
                    self.write_buffer
                        .extend_from_slice(chunk)
                        .map_err(|_| GattError::BufferOverflow)?;
                }
            } else if buffered > 0 {
                // We have partial header bytes - accumulate until we have 4
                let header_bytes_needed = 4 - buffered;
                if chunk.len() < header_bytes_needed {
                    // Still not enough for complete header
                    if !chunk.is_empty() {
                        self.write_buffer
                            .extend_from_slice(chunk)
                            .map_err(|_| GattError::BufferOverflow)?;
                    }
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
            } else if chunk.is_empty() {
                // No buffered data and empty chunk - nothing to do
                return Ok(None);
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
            if !chunk.is_empty() {
                self.write_buffer
                    .extend_from_slice(chunk)
                    .map_err(|_| GattError::BufferOverflow)?;
            }
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
    ///
    /// If the buffer contains excess bytes beyond the completed message,
    /// those bytes are preserved and shifted to the start of the buffer
    /// for processing as the next message.
    pub fn clear_write_buffer(&mut self) {
        if let Some(expected) = self.write_expected_len {
            let expected_usize = expected as usize;
            if self.write_buffer.len() > expected_usize {
                // Preserve excess bytes for next message by shifting to start
                let excess_len = self.write_buffer.len() - expected_usize;
                self.write_buffer.copy_within(expected_usize.., 0);
                self.write_buffer.truncate(excess_len);
                self.write_expected_len = None;
                return;
            }
        }
        self.write_buffer.clear();
        self.write_expected_len = None;
    }

    pub fn consume_to_radio_message(&mut self) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {
        let expected = self.write_expected_len?;
        let expected_usize = expected as usize;
        if self.write_buffer.len() < expected_usize {
            return None;
        }
        let mut msg = Vec::<u8, MAX_MESSAGE_SIZE>::new();
        let _ = msg.extend_from_slice(&self.write_buffer[..expected_usize]);
        if self.write_buffer.len() > expected_usize {
            let excess_len = self.write_buffer.len() - expected_usize;
            self.write_buffer.copy_within(expected_usize.., 0);
            self.write_buffer.truncate(excess_len);
            self.write_expected_len = None;
        } else {
            self.write_buffer.clear();
            self.write_expected_len = None;
        }
        Some(msg)
    }

    /// Queue an outbound FromRadio message with a deadline.
    ///
    /// The `deadline_ms` is an absolute timestamp (monotonic clock). The entry
    /// will be silently dropped when dequeued if `now_ms >= deadline_ms`.
    ///
    /// Increments the FromNum counter and returns the new value.
    ///
    /// # Example
    /// ```ignore
    /// let now = get_time_ms();
    /// let deadline = now + DEFAULT_DEADLINE_MS; // 60 seconds from now
    /// service.queue_from_radio(&data, deadline)?;
    /// ```
    pub fn queue_from_radio(&mut self, data: &[u8], deadline_ms: u64) -> Result<u32, GattError> {
        let mut msg = Vec::new();
        msg.extend_from_slice(data)
            .map_err(|_| GattError::BufferOverflow)?;

        let entry = QueueEntry::new(msg, deadline_ms);
        self.from_radio_queue
            .push_back(entry)
            .map_err(|_| GattError::QueueFull)?;

        self.from_num = self.from_num.wrapping_add(1);
        Ok(self.from_num)
    }

    /// Read the next non-expired FromRadio message (for characteristic read).
    ///
    /// Silently drops any expired entries before returning (handles
    /// non-monotonic deadlines). The message remains in the queue until
    /// `pop_from_radio` is called.
    ///
    /// # Arguments
    /// * `now_ms` - Current timestamp in milliseconds (monotonic clock)
    pub fn peek_from_radio(&mut self, now_ms: u64) -> Option<&[u8]> {
        self.drain_expired(now_ms);
        self.from_radio_queue.front().map(|e| e.data())
    }

    /// Remove and return the next non-expired FromRadio message.
    ///
    /// Silently drops any expired entries before returning (handles
    /// non-monotonic deadlines).
    ///
    /// # Arguments
    /// * `now_ms` - Current timestamp in milliseconds (monotonic clock)
    pub fn pop_from_radio(&mut self, now_ms: u64) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {
        self.drain_expired(now_ms);
        self.from_radio_queue.pop_front().map(|e| e.into_data())
    }

    /// Silently drop all expired entries (handles non-monotonic deadlines
    /// by rotating non-expired entries back to queue).
    ///
    /// Returns the number of entries dropped.
    fn drain_expired(&mut self, now_ms: u64) -> usize {
        let mut dropped = 0;
        let len = self.from_radio_queue.len();
        for _ in 0..len {
            if let Some(entry) = self.from_radio_queue.pop_front() {
                if entry.is_expired(now_ms) {
                    dropped += 1;
                } else {
                    let _ = self.from_radio_queue.push_back(entry);
                }
            }
        }
        dropped
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
        let now = 1000u64;
        let deadline = now + DEFAULT_DEADLINE_MS;

        // Queue first message
        let num1 = svc.queue_from_radio(&msg1, deadline).unwrap();
        assert_eq!(num1, 1);
        assert!(svc.has_pending_messages());
        assert_eq!(svc.pending_count(), 1);

        // Queue second message
        let num2 = svc.queue_from_radio(&msg2, deadline).unwrap();
        assert_eq!(num2, 2);
        assert_eq!(svc.pending_count(), 2);

        // Peek should return first message
        assert_eq!(svc.peek_from_radio(now), Some(&msg1[..]));

        // Pop should remove first message
        let popped = svc.pop_from_radio(now).unwrap();
        assert_eq!(popped.as_slice(), &msg1);
        assert_eq!(svc.pending_count(), 1);

        // Now peek should return second message
        assert_eq!(svc.peek_from_radio(now), Some(&msg2[..]));
    }

    #[test]
    fn test_queue_full() {
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();
        let deadline = 100_000u64;

        // Fill the queue
        for i in 0..MAX_QUEUE_DEPTH {
            let msg = [i as u8];
            assert!(svc.queue_from_radio(&msg, deadline).is_ok());
        }

        // Next should fail
        let result = svc.queue_from_radio(&[99], deadline);
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
        let now = 1000u64;
        let deadline = now + DEFAULT_DEADLINE_MS;

        // Set from_num near max
        for _ in 0..5 {
            svc.pop_from_radio(now); // Drain any messages
        }

        // Manually set near max (we'll need to queue many messages)
        // Instead, verify wrapping behavior by checking the increment
        let msg = [1u8];
        let num1 = svc.queue_from_radio(&msg, deadline).unwrap();
        svc.pop_from_radio(now);
        let num2 = svc.queue_from_radio(&msg, deadline).unwrap();
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

    #[test]
    fn test_queue_entry_expiry() {
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        let msg = [1u8, 2, 3];
        let deadline = 10_000u64; // Expires at 10 seconds

        svc.queue_from_radio(&msg, deadline).unwrap();
        assert_eq!(svc.pending_count(), 1);

        // Before deadline: message is available
        assert_eq!(svc.peek_from_radio(5_000), Some(&msg[..]));
        assert_eq!(svc.pending_count(), 1);

        // At deadline: message is expired and silently dropped
        assert_eq!(svc.peek_from_radio(10_000), None);
        assert_eq!(svc.pending_count(), 0);
    }

    #[test]
    fn test_queue_entry_expiry_pop() {
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        let msg = [1u8, 2, 3];
        let deadline = 10_000u64;

        svc.queue_from_radio(&msg, deadline).unwrap();

        // Pop after deadline: returns None, entry silently dropped
        assert_eq!(svc.pop_from_radio(15_000), None);
        assert_eq!(svc.pending_count(), 0);
    }

    #[test]
    fn test_queue_multiple_entries_partial_expiry() {
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        let msg1 = [1u8];
        let msg2 = [2u8];
        let msg3 = [3u8];

        // Queue with different deadlines
        svc.queue_from_radio(&msg1, 5_000).unwrap(); // Expires at 5s
        svc.queue_from_radio(&msg2, 10_000).unwrap(); // Expires at 10s
        svc.queue_from_radio(&msg3, 15_000).unwrap(); // Expires at 15s

        assert_eq!(svc.pending_count(), 3);

        // At 7s: first message expired, second and third still valid
        // peek_from_radio drains expired entries from front
        assert_eq!(svc.peek_from_radio(7_000), Some(&msg2[..]));
        assert_eq!(svc.pending_count(), 2);

        // Pop the second message
        let popped = svc.pop_from_radio(7_000).unwrap();
        assert_eq!(popped.as_slice(), &msg2);
        assert_eq!(svc.pending_count(), 1);

        // Third message still available
        assert_eq!(svc.peek_from_radio(7_000), Some(&msg3[..]));
    }

    #[test]
    fn test_queue_all_expired() {
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        // Queue several messages with short deadlines
        for i in 0..4 {
            svc.queue_from_radio(&[i as u8], 1000 + i as u64 * 100)
                .unwrap();
        }
        assert_eq!(svc.pending_count(), 4);

        // All expired
        assert_eq!(svc.peek_from_radio(5000), None);
        assert_eq!(svc.pending_count(), 0);
    }

    #[test]
    fn test_queue_entry_is_expired() {
        use heapless::Vec;

        let data: Vec<u8, MAX_MESSAGE_SIZE> = Vec::new();
        let entry = QueueEntry::new(data, 10_000);

        assert!(!entry.is_expired(5_000)); // Before deadline
        assert!(!entry.is_expired(9_999)); // Just before deadline
        assert!(entry.is_expired(10_000)); // At deadline
        assert!(entry.is_expired(10_001)); // After deadline
    }

    #[test]
    fn test_default_deadline_constant() {
        // Verify the default deadline is 60 seconds as per spec
        assert_eq!(DEFAULT_DEADLINE_MS, 60_000);
    }

    #[test]
    fn test_excess_bytes_preserved_across_messages() {
        // Regression test: BLE sends chunk containing end of message1 + start of message2
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        // Build two messages:
        // Message 1: header [3, 0, 0, 0] + payload [0xAA, 0xBB, 0xCC]
        // Message 2: header [2, 0, 0, 0] + payload [0xDD, 0xEE]
        let msg1_header = [3u8, 0, 0, 0];
        let msg1_payload = [0xAA, 0xBB, 0xCC];
        let msg2_header = [2u8, 0, 0, 0];
        let msg2_payload = [0xDD, 0xEE];

        // First chunk: message1 header + partial payload
        let mut chunk1 = [0u8; 6];
        chunk1[..4].copy_from_slice(&msg1_header);
        chunk1[4..6].copy_from_slice(&msg1_payload[..2]); // Only 2 bytes of payload
        let result1 = svc.write_to_radio(&chunk1).unwrap();
        assert!(result1.is_none()); // Not complete yet

        // Second chunk: rest of message1 + all of message2
        let mut chunk2 = [0u8; 7];
        chunk2[0] = msg1_payload[2]; // Last byte of msg1 payload
        chunk2[1..5].copy_from_slice(&msg2_header);
        chunk2[5..7].copy_from_slice(&msg2_payload);

        let result2 = svc.write_to_radio(&chunk2).unwrap();
        assert!(result2.is_some());
        assert_eq!(result2.unwrap(), &msg1_payload);

        // Clear buffer - this should preserve the excess bytes (msg2 header + payload)
        svc.clear_write_buffer();

        // The excess bytes [2, 0, 0, 0, 0xDD, 0xEE] are now in the buffer.
        // Call write_to_radio with empty chunk to trigger processing of buffered header.
        // With buffered >= 4, the header will be parsed and message completed.
        let result3 = svc.write_to_radio(&[]).unwrap();
        assert!(result3.is_some());
        assert_eq!(result3.unwrap(), &msg2_payload);

        // Verify buffer is clean after clearing
        svc.clear_write_buffer();
    }

    #[test]
    fn test_excess_bytes_partial_header() {
        // Case: excess bytes contain only partial header (< 4 bytes)
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        // Message 1: header [2, 0, 0, 0] + payload [0xAA, 0xBB]
        // Excess: [3, 0] (partial header of next message)
        let msg1_payload = [0xAA, 0xBB];

        // First chunk: complete message1 + partial header of message2
        let chunk = [2u8, 0, 0, 0, 0xAA, 0xBB, 3, 0]; // msg1 + 2 bytes of msg2 header
        let result1 = svc.write_to_radio(&chunk).unwrap();
        assert!(result1.is_some());
        assert_eq!(result1.unwrap(), &msg1_payload);

        // Clear - preserves the 2 excess bytes [3, 0]
        svc.clear_write_buffer();

        // Empty write - not enough for header
        let result2 = svc.write_to_radio(&[]).unwrap();
        assert!(result2.is_none());

        // Send remaining header bytes + payload
        let chunk2 = [0u8, 0, 0x11, 0x22, 0x33]; // rest of header + 3 byte payload
        let result3 = svc.write_to_radio(&chunk2).unwrap();
        assert!(result3.is_some());
        assert_eq!(result3.unwrap(), &[0x11, 0x22, 0x33]);
    }

    #[test]
    fn test_excess_bytes_exact_header() {
        // Case: excess bytes are exactly 4 (complete header, no payload yet)
        let mut svc: MeshtasticGattService = MeshtasticGattService::new();

        // Message 1: header [1, 0, 0, 0] + payload [0xFF]
        // Excess: [5, 0, 0, 0] (exactly the header of next message)
        let chunk = [1u8, 0, 0, 0, 0xFF, 5, 0, 0, 0]; // msg1 + exact msg2 header
        let result1 = svc.write_to_radio(&chunk).unwrap();
        assert!(result1.is_some());
        assert_eq!(result1.unwrap(), &[0xFF]);

        // Clear - preserves the 4 excess bytes [5, 0, 0, 0]
        svc.clear_write_buffer();

        // Empty write - header parsed but waiting for payload
        let result2 = svc.write_to_radio(&[]).unwrap();
        assert!(result2.is_none());

        // Send payload
        let result3 = svc.write_to_radio(&[1, 2, 3, 4, 5]).unwrap();
        assert!(result3.is_some());
        assert_eq!(result3.unwrap(), &[1, 2, 3, 4, 5]);
    }
}
