//! DTN store-and-forward buffer (spec 9.8).

extern crate std;
use std::collections::{HashSet, VecDeque};
use std::vec::Vec;

/// Default DTN buffer size: 64KB per spec 9.8
pub const DTN_BUFFER_MAX_BYTES: usize = 65536;

/// A message buffered for DTN store-and-forward (spec 9.8).
#[derive(Clone, Debug)]
pub struct DtnMessage {
    /// Raw IPv6 packet data.
    pub packet: Vec<u8>,
    /// 8-byte IID of destination.
    pub destination_iid: [u8; 8],
    /// Unix timestamp when message expires.
    pub expiry_unix: u32,
    /// When message was buffered (monotonic ms for eviction ordering).
    pub buffered_at_ms: u32,
}

impl DtnMessage {
    /// Approximate size in bytes for buffer accounting.
    pub fn size(&self) -> usize {
        self.packet.len() + std::mem::size_of::<Self>()
    }
}

/// DTN store-and-forward buffer (spec 9.8).
///
/// Buffers messages for unreachable destinations until a path appears.
/// Uses oldest-first eviction when the buffer exceeds max_bytes.
#[derive(Debug)]
pub struct DtnBuffer {
    buffer: VecDeque<DtnMessage>,
    max_bytes: usize,
    current_bytes: usize,
}

impl DtnBuffer {
    /// Create a new DTN buffer with default capacity (64KB).
    pub fn new() -> Self {
        Self {
            buffer: VecDeque::new(),
            max_bytes: DTN_BUFFER_MAX_BYTES,
            current_bytes: 0,
        }
    }

    /// Create a new DTN buffer with custom capacity.
    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            buffer: VecDeque::new(),
            max_bytes,
            current_bytes: 0,
        }
    }

    /// Buffer a message for DTN store-and-forward.
    ///
    /// Returns `true` if buffered, `false` if rejected (expired or oversized).
    pub fn buffer_message(
        &mut self,
        packet: Vec<u8>,
        destination_iid: [u8; 8],
        expiry_unix: u32,
        now_unix: u32,
        now_ms: u32,
    ) -> bool {
        // Reject already-expired messages
        if expiry_unix <= now_unix {
            return false;
        }

        let msg = DtnMessage {
            packet,
            destination_iid,
            expiry_unix,
            buffered_at_ms: now_ms,
        };

        // Reject messages that exceed the maximum buffer size
        let msg_size = msg.size();
        if msg_size > self.max_bytes {
            return false;
        }

        // Evict oldest messages until we have space
        self.evict_if_needed(msg_size);

        self.current_bytes += msg_size;
        self.buffer.push_back(msg);
        true
    }

    /// Get list of destination IIDs with buffered messages.
    pub fn get_pending_iids(&self) -> Vec<[u8; 8]> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for msg in &self.buffer {
            if seen.insert(msg.destination_iid) {
                result.push(msg.destination_iid);
            }
        }
        result
    }

    /// Retrieve and remove all messages for a destination IID.
    pub fn retrieve_for(&mut self, destination_iid: &[u8; 8]) -> Vec<DtnMessage> {
        let mut matching = Vec::new();
        let mut remaining = VecDeque::new();

        for msg in self.buffer.drain(..) {
            if msg.destination_iid == *destination_iid {
                self.current_bytes -= msg.size();
                matching.push(msg);
            } else {
                remaining.push_back(msg);
            }
        }
        self.buffer = remaining;
        matching
    }

    /// Remove expired messages from buffer. Returns count removed.
    pub fn expire_old(&mut self, now_unix: u32) -> usize {
        let mut expired = 0;
        let mut remaining = VecDeque::new();

        for msg in self.buffer.drain(..) {
            if msg.expiry_unix > now_unix {
                remaining.push_back(msg);
            } else {
                self.current_bytes -= msg.size();
                expired += 1;
            }
        }
        self.buffer = remaining;
        expired
    }

    /// Current buffer size in bytes.
    pub fn current_size(&self) -> usize {
        self.current_bytes
    }

    /// Number of messages in the buffer.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Evict oldest messages to make room for new_msg_size bytes.
    fn evict_if_needed(&mut self, new_msg_size: usize) -> usize {
        let mut evicted = 0;
        while self.current_bytes + new_msg_size > self.max_bytes {
            if let Some(oldest) = self.buffer.pop_front() {
                self.current_bytes -= oldest.size();
                evicted += 1;
            } else {
                break;
            }
        }
        evicted
    }
}

impl Default for DtnBuffer {
    fn default() -> Self {
        Self::new()
    }
}
