//! KISS protocol framing (encode/decode).
//!
//! KISS (Keep It Simple, Stupid) is a TNC interface standard from 1986.
//! LICHEN uses it for compatibility with ham radio apps (aprs.fi, APRSDroid).
//!
//! Frame format: FEND | CMD | DATA... | FEND
//! Escaping: 0xC0 -> 0xDB 0xDC, 0xDB -> 0xDB 0xDD

use core::fmt;

/// Frame delimiter byte.
pub const FEND: u8 = 0xC0;

/// Escape prefix byte.
pub const FESC: u8 = 0xDB;

/// Transposed FEND (after FESC).
pub const TFEND: u8 = 0xDC;

/// Transposed FESC (after FESC).
pub const TFESC: u8 = 0xDD;

/// Maximum frame size (escaped).
pub const MAX_FRAME_SIZE: usize = 2048;

/// KISS command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KissCommand {
    /// Data frame (bidirectional).
    Data = 0x00,
    /// TX key-up delay (host->TNC).
    TxDelay = 0x01,
    /// CSMA p-value (host->TNC).
    Persistence = 0x02,
    /// CSMA slot interval (host->TNC).
    SlotTime = 0x03,
    /// TX tail time (host->TNC).
    TxTail = 0x04,
    /// Half/full duplex (host->TNC).
    FullDuplex = 0x05,
    /// SetHardware (TNC-specific).
    SetHardware = 0x06,
    /// Exit KISS mode (host->TNC).
    Return = 0x0F,
}

impl KissCommand {
    /// Try to convert a u8 to a KissCommand.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::TxDelay),
            0x02 => Some(Self::Persistence),
            0x03 => Some(Self::SlotTime),
            0x04 => Some(Self::TxTail),
            0x05 => Some(Self::FullDuplex),
            0x06 => Some(Self::SetHardware),
            0x0F => Some(Self::Return),
            _ => None,
        }
    }
}

/// KISS protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KissError {
    /// Frame is too short.
    TooShort,
    /// Frame does not start with FEND.
    MissingStartFend,
    /// Frame does not end with FEND.
    MissingEndFend,
    /// Frame is empty (only FENDs).
    EmptyFrame,
    /// Truncated escape sequence at end of data.
    TruncatedEscape,
    /// Invalid escape sequence (0xDB followed by invalid byte).
    InvalidEscape(u8),
    /// Port number out of range (must be 0-15).
    PortOutOfRange(u8),
    /// Command value out of range (must be 0-15).
    CommandOutOfRange(u8),
    /// Output buffer too small.
    BufferTooSmall,
}

impl fmt::Display for KissError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "frame too short"),
            Self::MissingStartFend => write!(f, "frame must start with FEND (0xC0)"),
            Self::MissingEndFend => write!(f, "frame must end with FEND (0xC0)"),
            Self::EmptyFrame => write!(f, "empty frame"),
            Self::TruncatedEscape => write!(f, "truncated escape sequence"),
            Self::InvalidEscape(b) => write!(f, "invalid escape sequence: 0xDB 0x{:02X}", b),
            Self::PortOutOfRange(p) => write!(f, "port must be 0-15, got {}", p),
            Self::CommandOutOfRange(c) => write!(f, "command must be 0-15, got {}", c),
            Self::BufferTooSmall => write!(f, "output buffer too small"),
        }
    }
}

impl core::error::Error for KissError {}

/// Decoded KISS frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KissFrame<'a> {
    /// Port number (0-15).
    pub port: u8,
    /// Command type (0-15).
    pub command: u8,
    /// Unescaped payload data.
    pub data: &'a [u8],
}

impl<'a> KissFrame<'a> {
    /// Get the command as a typed enum, if recognized.
    pub fn command_type(&self) -> Option<KissCommand> {
        KissCommand::from_u8(self.command)
    }
}

/// Escape special bytes in payload.
///
/// 0xC0 (FEND) -> 0xDB 0xDC
/// 0xDB (FESC) -> 0xDB 0xDD
///
/// Returns the number of bytes written, or an error if the buffer is too small.
pub fn kiss_escape(data: &[u8], out: &mut [u8]) -> Result<usize, KissError> {
    let mut pos = 0;

    for &b in data {
        match b {
            FEND => {
                if pos + 2 > out.len() {
                    return Err(KissError::BufferTooSmall);
                }
                out[pos] = FESC;
                out[pos + 1] = TFEND;
                pos += 2;
            }
            FESC => {
                if pos + 2 > out.len() {
                    return Err(KissError::BufferTooSmall);
                }
                out[pos] = FESC;
                out[pos + 1] = TFESC;
                pos += 2;
            }
            _ => {
                if pos >= out.len() {
                    return Err(KissError::BufferTooSmall);
                }
                out[pos] = b;
                pos += 1;
            }
        }
    }

    Ok(pos)
}

/// Unescape payload data.
///
/// 0xDB 0xDC -> 0xC0 (FEND)
/// 0xDB 0xDD -> 0xDB (FESC)
///
/// Returns the number of bytes written, or an error if the escape sequence is invalid.
pub fn kiss_unescape(data: &[u8], out: &mut [u8]) -> Result<usize, KissError> {
    let mut pos = 0;
    let mut i = 0;

    while i < data.len() {
        if data[i] == FESC {
            if i + 1 >= data.len() {
                return Err(KissError::TruncatedEscape);
            }
            let next = data[i + 1];
            let unescaped = match next {
                TFEND => FEND,
                TFESC => FESC,
                _ => return Err(KissError::InvalidEscape(next)),
            };
            if pos >= out.len() {
                return Err(KissError::BufferTooSmall);
            }
            out[pos] = unescaped;
            pos += 1;
            i += 2;
        } else {
            if pos >= out.len() {
                return Err(KissError::BufferTooSmall);
            }
            out[pos] = data[i];
            pos += 1;
            i += 1;
        }
    }

    Ok(pos)
}

/// Encode a KISS frame.
///
/// # Arguments
///
/// * `port` - Port number 0-15
/// * `command` - Command type (KissCommand value)
/// * `data` - Payload data (will be escaped)
/// * `out` - Output buffer for the complete frame
///
/// # Returns
///
/// The number of bytes written to `out`, or an error.
pub fn kiss_encode(port: u8, command: KissCommand, data: &[u8], out: &mut [u8]) -> Result<usize, KissError> {
    kiss_encode_raw(port, command as u8, data, out)
}

/// Encode a KISS frame with raw command byte.
///
/// Use this for non-standard command values. Most callers should use `kiss_encode`.
pub fn kiss_encode_raw(port: u8, command: u8, data: &[u8], out: &mut [u8]) -> Result<usize, KissError> {
    if port > 15 {
        return Err(KissError::PortOutOfRange(port));
    }
    if command > 15 {
        return Err(KissError::CommandOutOfRange(command));
    }

    // Minimum frame: FEND + CMD + FEND = 3 bytes
    if out.len() < 3 {
        return Err(KissError::BufferTooSmall);
    }

    let cmd_byte = (port << 4) | command;

    out[0] = FEND;
    out[1] = cmd_byte;

    // Escape data into remaining buffer (after FEND + CMD, before final FEND)
    let escaped_len = kiss_escape(data, &mut out[2..])?;

    // Check we have room for final FEND
    if 2 + escaped_len >= out.len() {
        return Err(KissError::BufferTooSmall);
    }

    out[2 + escaped_len] = FEND;

    Ok(3 + escaped_len)
}

/// Decode a KISS frame.
///
/// # Arguments
///
/// * `frame` - Complete KISS frame (with FEND delimiters)
///
/// # Returns
///
/// A `KissFrame` with port, command, and a reference to the escaped data.
/// The data is NOT unescaped - use `kiss_unescape` to get the raw payload.
pub fn kiss_decode(frame: &[u8]) -> Result<KissFrame<'_>, KissError> {
    if frame.len() < 3 {
        return Err(KissError::TooShort);
    }

    if frame[0] != FEND {
        return Err(KissError::MissingStartFend);
    }

    if frame[frame.len() - 1] != FEND {
        return Err(KissError::MissingEndFend);
    }

    // Find actual end (skip consecutive FENDs at end)
    let mut end = frame.len() - 1;
    while end > 1 && frame[end - 1] == FEND {
        end -= 1;
    }

    if end < 2 {
        return Err(KissError::EmptyFrame);
    }

    let cmd_byte = frame[1];
    let port = (cmd_byte >> 4) & 0x0F;
    let command = cmd_byte & 0x0F;

    // Data is between CMD and final FEND (still escaped)
    let data = &frame[2..end];

    Ok(KissFrame { port, command, data })
}

/// Incremental KISS frame reader for stream transports.
///
/// Feed bytes with `feed()`, then call `try_read_frame()` to extract complete frames.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "kiss")]
/// # {
/// use lichen_kiss::KissReader;
///
/// let mut reader = KissReader::new();
/// let mut frame_buf = [0u8; 256];
///
/// // Feed some data
/// reader.feed(&[0xC0, 0x00, 0x48, 0x69, 0xC0]);
///
/// // Extract frame
/// if let Some(frame) = reader.try_read_frame(&mut frame_buf).unwrap() {
///     assert_eq!(frame.data, b"Hi");
/// }
/// # }
/// ```
#[derive(Debug)]
pub struct KissReader {
    buffer: [u8; MAX_FRAME_SIZE * 2],
    len: usize,
}

impl Default for KissReader {
    fn default() -> Self {
        Self::new()
    }
}

impl KissReader {
    /// Create a new reader.
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; MAX_FRAME_SIZE * 2],
            len: 0,
        }
    }

    /// Add bytes to the buffer.
    ///
    /// If the buffer is full, old data is discarded from the last FEND.
    pub fn feed(&mut self, data: &[u8]) {
        // Append what we can
        let space = self.buffer.len() - self.len;
        let to_copy = data.len().min(space);
        self.buffer[self.len..self.len + to_copy].copy_from_slice(&data[..to_copy]);
        self.len += to_copy;

        // If we couldn't fit it all, we need to drop old data
        if to_copy < data.len() {
            // Find last FEND to keep sync
            let last_fend = self.buffer[..self.len]
                .iter()
                .rposition(|&b| b == FEND)
                .unwrap_or(0);

            if last_fend > 0 {
                // Shift buffer
                self.buffer.copy_within(last_fend..self.len, 0);
                self.len -= last_fend;
            } else {
                self.len = 0;
            }

            // Now add remaining input
            let remaining = &data[to_copy..];
            let to_copy2 = remaining.len().min(self.buffer.len() - self.len);
            self.buffer[self.len..self.len + to_copy2].copy_from_slice(&remaining[..to_copy2]);
            self.len += to_copy2;
        }
    }

    /// Try to extract one complete frame from buffer.
    ///
    /// Returns the unescaped frame data in `out`, or `None` if no complete frame is available.
    pub fn try_read_frame<'a>(&mut self, out: &'a mut [u8]) -> Result<Option<KissFrame<'a>>, KissError> {
        // Skip leading non-FEND bytes (sync)
        while self.len > 0 && self.buffer[0] != FEND {
            self.buffer.copy_within(1..self.len, 0);
            self.len -= 1;
        }

        if self.len < 3 {
            return Ok(None);
        }

        // Skip inter-frame FEND padding to find CMD byte
        let mut start = 0;
        while start < self.len && self.buffer[start] == FEND {
            start += 1;
        }

        if start >= self.len {
            return Ok(None);
        }

        // Find end FEND
        let mut end = start;
        while end < self.len && self.buffer[end] != FEND {
            end += 1;
        }

        if end >= self.len {
            return Ok(None);
        }

        // We have a complete frame: buffer[start-1..=end] (CMD at start, FEND at end)
        // But we need to include the opening FEND

        let cmd_byte = self.buffer[start];
        let port = (cmd_byte >> 4) & 0x0F;
        let command = cmd_byte & 0x0F;

        // Escaped data is between CMD and closing FEND
        let escaped_data = &self.buffer[start + 1..end];

        // Unescape into output buffer
        let unescaped_len = kiss_unescape(escaped_data, out)?;

        // Remove frame from buffer (including trailing FEND)
        self.buffer.copy_within(end + 1..self.len, 0);
        self.len -= end + 1;

        Ok(Some(KissFrame {
            port,
            command,
            data: &out[..unescaped_len],
        }))
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Get current buffer length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Incremental KISS frame writer with output queue.
///
/// Queue frames with `queue_frame()`, then drain encoded bytes with `try_get_frame()`.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "kiss")]
/// # {
/// use lichen_kiss::{KissWriter, KissCommand};
///
/// let mut writer = KissWriter::new();
/// let mut out = [0u8; 64];
///
/// // Queue a frame
/// writer.queue_frame(0, KissCommand::Data, b"Hi").unwrap();
///
/// // Get encoded frame
/// if let Some(len) = writer.try_get_frame(&mut out) {
///     // out[..len] contains: FEND, CMD, escaped data, FEND
/// }
/// # }
/// ```
#[derive(Debug)]
pub struct KissWriter {
    // ponytail: 8 frames × 512 bytes each = 4KB max, sufficient for typical TNC traffic
    queue: heapless::Deque<heapless::Vec<u8, 512>, 8>,
}

impl Default for KissWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl KissWriter {
    /// Create a new writer.
    pub const fn new() -> Self {
        Self {
            queue: heapless::Deque::new(),
        }
    }

    /// Queue a frame for transmission.
    ///
    /// The frame is pre-encoded (FEND delimiters + escaping) and stored in the queue.
    /// Returns an error if the queue is full or the frame is too large.
    pub fn queue_frame(&mut self, port: u8, cmd: KissCommand, data: &[u8]) -> Result<(), KissError> {
        self.queue_frame_raw(port, cmd as u8, data)
    }

    /// Queue a frame with raw command byte.
    pub fn queue_frame_raw(&mut self, port: u8, cmd: u8, data: &[u8]) -> Result<(), KissError> {
        let mut frame: heapless::Vec<u8, 512> = heapless::Vec::new();
        let mut tmp = [0u8; 512];
        let len = kiss_encode_raw(port, cmd, data, &mut tmp)?;
        frame.extend_from_slice(&tmp[..len]).map_err(|_| KissError::BufferTooSmall)?;
        self.queue.push_back(frame).map_err(|_| KissError::BufferTooSmall)?;
        Ok(())
    }

    /// Try to get the next encoded frame from the queue.
    ///
    /// Returns the number of bytes written to `out`, or `None` if queue is empty.
    pub fn try_get_frame(&mut self, out: &mut [u8]) -> Option<usize> {
        let frame = self.queue.pop_front()?;
        let len = frame.len().min(out.len());
        out[..len].copy_from_slice(&frame[..len]);
        Some(len)
    }

    /// Number of frames waiting in queue.
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Check if queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Clear all pending frames.
    pub fn clear(&mut self) {
        self.queue.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_no_special() {
        let data = b"hello";
        let mut out = [0u8; 16];
        let len = kiss_escape(data, &mut out).unwrap();
        assert_eq!(&out[..len], b"hello");
    }

    #[test]
    fn test_escape_fend() {
        let data = &[0xC0];
        let mut out = [0u8; 16];
        let len = kiss_escape(data, &mut out).unwrap();
        assert_eq!(&out[..len], &[FESC, TFEND]);
    }

    #[test]
    fn test_escape_fesc() {
        let data = &[0xDB];
        let mut out = [0u8; 16];
        let len = kiss_escape(data, &mut out).unwrap();
        assert_eq!(&out[..len], &[FESC, TFESC]);
    }

    #[test]
    fn test_escape_mixed() {
        let data = &[0x41, 0xC0, 0x42, 0xDB, 0x43];
        let mut out = [0u8; 16];
        let len = kiss_escape(data, &mut out).unwrap();
        assert_eq!(&out[..len], &[0x41, FESC, TFEND, 0x42, FESC, TFESC, 0x43]);
    }

    #[test]
    fn test_unescape_no_special() {
        let data = b"hello";
        let mut out = [0u8; 16];
        let len = kiss_unescape(data, &mut out).unwrap();
        assert_eq!(&out[..len], b"hello");
    }

    #[test]
    fn test_unescape_fend() {
        let data = &[FESC, TFEND];
        let mut out = [0u8; 16];
        let len = kiss_unescape(data, &mut out).unwrap();
        assert_eq!(&out[..len], &[FEND]);
    }

    #[test]
    fn test_unescape_fesc() {
        let data = &[FESC, TFESC];
        let mut out = [0u8; 16];
        let len = kiss_unescape(data, &mut out).unwrap();
        assert_eq!(&out[..len], &[FESC]);
    }

    #[test]
    fn test_unescape_truncated() {
        let data = &[FESC];
        let mut out = [0u8; 16];
        assert_eq!(kiss_unescape(data, &mut out), Err(KissError::TruncatedEscape));
    }

    #[test]
    fn test_unescape_invalid() {
        let data = &[FESC, 0x00];
        let mut out = [0u8; 16];
        assert_eq!(kiss_unescape(data, &mut out), Err(KissError::InvalidEscape(0x00)));
    }

    #[test]
    fn test_roundtrip_escape() {
        let original = &[0x00, 0xC0, 0xDB, 0xFF, 0xC0, 0xC0, 0xDB, 0xDB];
        let mut escaped = [0u8; 32];
        let escaped_len = kiss_escape(original, &mut escaped).unwrap();

        let mut unescaped = [0u8; 32];
        let unescaped_len = kiss_unescape(&escaped[..escaped_len], &mut unescaped).unwrap();

        assert_eq!(&unescaped[..unescaped_len], original);
    }

    #[test]
    fn test_encode_simple() {
        let mut out = [0u8; 64];
        let len = kiss_encode(0, KissCommand::Data, b"Hi", &mut out).unwrap();

        assert_eq!(out[0], FEND);
        assert_eq!(out[1], 0x00); // port 0, cmd 0
        assert_eq!(&out[2..4], b"Hi");
        assert_eq!(out[4], FEND);
        assert_eq!(len, 5);
    }

    #[test]
    fn test_encode_port_1() {
        let mut out = [0u8; 64];
        let len = kiss_encode(1, KissCommand::Data, b"X", &mut out).unwrap();

        assert_eq!(out[1], 0x10); // port 1, cmd 0
        assert_eq!(len, 4);
    }

    #[test]
    fn test_encode_txdelay() {
        let mut out = [0u8; 64];
        let len = kiss_encode(0, KissCommand::TxDelay, &[50], &mut out).unwrap();

        assert_eq!(out[1], 0x01); // port 0, cmd 1
        assert_eq!(out[2], 50);
        assert_eq!(len, 4);
    }

    #[test]
    fn test_encode_with_escaping() {
        let mut out = [0u8; 64];
        let data = &[0x41, 0xC0, 0xDB, 0x42]; // A, FEND, FESC, B
        let len = kiss_encode(0, KissCommand::Data, data, &mut out).unwrap();

        // FEND, CMD, A, ESC, TFEND, ESC, TFESC, B, FEND
        assert_eq!(&out[..len], &[FEND, 0x00, 0x41, FESC, TFEND, FESC, TFESC, 0x42, FEND]);
    }

    #[test]
    fn test_encode_port_out_of_range() {
        let mut out = [0u8; 64];
        assert_eq!(kiss_encode(16, KissCommand::Data, b"", &mut out), Err(KissError::PortOutOfRange(16)));
    }

    #[test]
    fn test_decode_simple() {
        let frame = &[FEND, 0x00, 0x48, 0x69, FEND]; // "Hi"
        let decoded = kiss_decode(frame).unwrap();

        assert_eq!(decoded.port, 0);
        assert_eq!(decoded.command, 0);
        assert_eq!(decoded.data, b"Hi");
    }

    #[test]
    fn test_decode_port_1() {
        let frame = &[FEND, 0x10, 0x58, FEND]; // "X" on port 1
        let decoded = kiss_decode(frame).unwrap();

        assert_eq!(decoded.port, 1);
        assert_eq!(decoded.command, 0);
    }

    #[test]
    fn test_decode_with_escaped() {
        // "A" + escaped FEND + "B"
        let frame = &[FEND, 0x00, 0x41, FESC, TFEND, 0x42, FEND];
        let decoded = kiss_decode(frame).unwrap();

        // Data is still escaped at this point
        assert_eq!(decoded.data, &[0x41, FESC, TFEND, 0x42]);

        // Unescape it
        let mut out = [0u8; 16];
        let len = kiss_unescape(decoded.data, &mut out).unwrap();
        assert_eq!(&out[..len], &[0x41, FEND, 0x42]);
    }

    #[test]
    fn test_decode_trailing_fends() {
        let frame = &[FEND, 0x00, 0x41, FEND, FEND, FEND];
        let decoded = kiss_decode(frame).unwrap();
        assert_eq!(decoded.data, b"A");
    }

    #[test]
    fn test_decode_too_short() {
        assert_eq!(kiss_decode(&[FEND, FEND]), Err(KissError::TooShort));
    }

    #[test]
    fn test_decode_missing_start() {
        assert_eq!(kiss_decode(&[0x00, 0x00, FEND]), Err(KissError::MissingStartFend));
    }

    #[test]
    fn test_decode_missing_end() {
        assert_eq!(kiss_decode(&[FEND, 0x00, 0x41]), Err(KissError::MissingEndFend));
    }

    #[test]
    fn test_roundtrip_frame() {
        let original_data = b"Hello, KISS!";
        let mut encoded = [0u8; 64];
        let enc_len = kiss_encode(2, KissCommand::Data, original_data, &mut encoded).unwrap();

        let decoded = kiss_decode(&encoded[..enc_len]).unwrap();
        assert_eq!(decoded.port, 2);
        assert_eq!(decoded.command, 0);

        let mut unescaped = [0u8; 64];
        let unesc_len = kiss_unescape(decoded.data, &mut unescaped).unwrap();
        assert_eq!(&unescaped[..unesc_len], original_data);
    }

    #[test]
    fn test_reader_simple() {
        let mut reader = KissReader::new();
        let mut out = [0u8; 64];

        reader.feed(&[FEND, 0x00, 0x48, 0x69, FEND]);

        let frame = reader.try_read_frame(&mut out).unwrap().unwrap();
        assert_eq!(frame.port, 0);
        assert_eq!(frame.command, 0);
        assert_eq!(frame.data, b"Hi");
    }

    #[test]
    fn test_reader_partial() {
        let mut reader = KissReader::new();
        let mut out = [0u8; 64];

        // Feed partial frame
        reader.feed(&[FEND, 0x00, 0x48]);
        assert!(reader.try_read_frame(&mut out).unwrap().is_none());

        // Complete it
        reader.feed(&[0x69, FEND]);
        let frame = reader.try_read_frame(&mut out).unwrap().unwrap();
        assert_eq!(frame.data, b"Hi");
    }

    #[test]
    fn test_reader_multiple_frames() {
        let mut reader = KissReader::new();
        let mut out = [0u8; 64];

        reader.feed(&[FEND, 0x00, 0x41, FEND, FEND, 0x00, 0x42, FEND]);

        let frame1 = reader.try_read_frame(&mut out).unwrap().unwrap();
        assert_eq!(frame1.data, b"A");

        let frame2 = reader.try_read_frame(&mut out).unwrap().unwrap();
        assert_eq!(frame2.data, b"B");

        assert!(reader.try_read_frame(&mut out).unwrap().is_none());
    }

    #[test]
    fn test_reader_skip_garbage() {
        let mut reader = KissReader::new();
        let mut out = [0u8; 64];

        // Garbage before valid frame
        reader.feed(&[0x11, 0x22, 0x33, FEND, 0x00, 0x41, FEND]);

        let frame = reader.try_read_frame(&mut out).unwrap().unwrap();
        assert_eq!(frame.data, b"A");
    }

    #[test]
    fn test_reader_with_escaping() {
        let mut reader = KissReader::new();
        let mut out = [0u8; 64];

        // Frame with escaped FEND in data
        reader.feed(&[FEND, 0x00, 0x41, FESC, TFEND, 0x42, FEND]);

        let frame = reader.try_read_frame(&mut out).unwrap().unwrap();
        assert_eq!(frame.data, &[0x41, FEND, 0x42]);
    }

    #[test]
    fn test_command_from_u8() {
        assert_eq!(KissCommand::from_u8(0x00), Some(KissCommand::Data));
        assert_eq!(KissCommand::from_u8(0x01), Some(KissCommand::TxDelay));
        assert_eq!(KissCommand::from_u8(0x0F), Some(KissCommand::Return));
        assert_eq!(KissCommand::from_u8(0x07), None);
        assert_eq!(KissCommand::from_u8(0x10), None);
    }

    #[test]
    fn test_writer_simple() {
        let mut writer = KissWriter::new();
        let mut out = [0u8; 64];

        writer.queue_frame(0, KissCommand::Data, b"Hi").unwrap();
        assert_eq!(writer.pending_count(), 1);

        let len = writer.try_get_frame(&mut out).unwrap();
        assert_eq!(&out[..len], &[FEND, 0x00, b'H', b'i', FEND]);
        assert!(writer.is_empty());
    }

    #[test]
    fn test_writer_multiple_frames() {
        let mut writer = KissWriter::new();
        let mut out = [0u8; 64];

        writer.queue_frame(0, KissCommand::Data, b"A").unwrap();
        writer.queue_frame(1, KissCommand::Data, b"B").unwrap();
        assert_eq!(writer.pending_count(), 2);

        let len1 = writer.try_get_frame(&mut out).unwrap();
        assert_eq!(&out[..len1], &[FEND, 0x00, b'A', FEND]);

        let len2 = writer.try_get_frame(&mut out).unwrap();
        assert_eq!(&out[..len2], &[FEND, 0x10, b'B', FEND]); // port 1 = 0x10

        assert!(writer.try_get_frame(&mut out).is_none());
    }

    #[test]
    fn test_writer_with_escaping() {
        let mut writer = KissWriter::new();
        let mut out = [0u8; 64];

        // Data containing FEND byte
        writer.queue_frame(0, KissCommand::Data, &[0x41, FEND, 0x42]).unwrap();

        let len = writer.try_get_frame(&mut out).unwrap();
        assert_eq!(&out[..len], &[FEND, 0x00, 0x41, FESC, TFEND, 0x42, FEND]);
    }

    #[test]
    fn test_writer_clear() {
        let mut writer = KissWriter::new();

        writer.queue_frame(0, KissCommand::Data, b"A").unwrap();
        writer.queue_frame(0, KissCommand::Data, b"B").unwrap();
        assert_eq!(writer.pending_count(), 2);

        writer.clear();
        assert!(writer.is_empty());
    }
}
