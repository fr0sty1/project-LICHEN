//! SCHC fragmentation — ACK-on-Error sender/receiver (RFC 8724 §8).
//!
//! Wire format (per-fragment):
//!   byte 0: rule_id
//!   byte 1: (W<<6) | FCN   — W is 1-bit window, FCN is 6-bit counter
//!   [bytes 2..6: CRC32 MIC — All-1 fragment only]
//!   remaining bytes: tile payload
//!
//! ACK wire format:
//!   byte 0: rule_id
//!   byte 1: (W<<6) | (complete?1:0)
//!   byte 2: n  (bitmap length)
//!   bytes 3..: ceil(n/8) bitmap bytes, MSB-first

use lichen_core::{
    constants::SCHC_MAX_DECOMPRESSED,
    error::{BufferTooSmall, TooShort},
};

pub const FRAGMENT_M: u8 = 1;
pub const FRAGMENT_N: u8 = 6;
pub const FRAGMENT_T: u8 = 0;
pub const ALL_1_FCN: u8 = (1 << FRAGMENT_N) - 1;
pub const MIC_LENGTH: usize = 4;
pub const DEFAULT_WINDOW_SIZE: usize = 32;
pub const MAX_WINDOW_SIZE: usize = 62;
pub const RETRANSMISSION_TIMEOUT_S: u32 = 10;
pub const MAX_ACK_REQUESTS: u32 = 3;
pub const INACTIVITY_TIMEOUT_S: u32 = 60;

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FragmentError {
    TooShort(TooShort),
    InvalidFcn,
    InvalidWindow,
    MicMissing,
    BufferTooSmall(BufferTooSmall),
    InvalidWindowSize,
}

impl core::fmt::Display for FragmentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => write!(f, "fragment {}", e),
            Self::InvalidFcn => write!(f, "invalid FCN"),
            Self::InvalidWindow => write!(f, "invalid window"),
            Self::MicMissing => write!(f, "MIC missing on All-1 fragment"),
            Self::BufferTooSmall(e) => write!(f, "fragment {}", e),
            Self::InvalidWindowSize => write!(f, "invalid window size"),
        }
    }
}

impl core::error::Error for FragmentError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TooShort(e) => Some(e),
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TooShort> for FragmentError {
    fn from(e: TooShort) -> Self {
        Self::TooShort(e)
    }
}

impl From<BufferTooSmall> for FragmentError {
    fn from(e: BufferTooSmall) -> Self {
        Self::BufferTooSmall(e)
    }
}

// ─── CRC32 (ISO 3309 / zlib) ─────────────────────────────────────────────────

/// CRC32 over `data`, matching `zlib.crc32` in Python.
pub fn compute_mic(data: &[u8]) -> [u8; MIC_LENGTH] {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    (!crc).to_be_bytes()
}

// ─── Fragment ─────────────────────────────────────────────────────────────────

/// A single SCHC fragment (borrowed payload).
#[derive(Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub rule_id: u8,
    pub window: u8,
    pub fcn: u8,
    pub payload: &'a [u8],
    /// CRC32 MIC — present only when `is_all_1()`.
    pub mic: [u8; MIC_LENGTH],
}

impl<'a> Fragment<'a> {
    pub fn is_all_1(&self) -> bool {
        self.fcn == ALL_1_FCN
    }

    pub fn is_all_0(&self) -> bool {
        self.fcn == 0
    }

    /// Serialize into `out`. Returns bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, FragmentError> {
        if self.window > 1 {
            return Err(FragmentError::InvalidWindow);
        }
        if self.fcn > ALL_1_FCN {
            return Err(FragmentError::InvalidFcn);
        }
        // Note: We don't validate MIC here because zero is a valid MIC
        // (CRC32 of empty payload). MIC correctness is verified at reassembly.
        let extra = if self.is_all_1() { MIC_LENGTH } else { 0 };
        let needed = 2 + extra + self.payload.len();
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[0] = self.rule_id;
        out[1] = ((self.window & 1) << FRAGMENT_N) | (self.fcn & ((1 << FRAGMENT_N) - 1));
        if self.is_all_1() {
            out[2..6].copy_from_slice(&self.mic);
            out[6..6 + self.payload.len()].copy_from_slice(self.payload);
        } else {
            out[2..2 + self.payload.len()].copy_from_slice(self.payload);
        }
        Ok(needed)
    }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, FragmentError> {
        if data.len() < 2 {
            return Err(TooShort::new(2, data.len()).into());
        }
        let rule_id = data[0];
        let window = (data[1] >> FRAGMENT_N) & 1;
        let fcn = data[1] & ((1 << FRAGMENT_N) - 1);
        let rest = &data[2..];
        if fcn == ALL_1_FCN {
            if rest.len() < MIC_LENGTH {
                return Err(TooShort::new(2 + MIC_LENGTH, data.len()).into());
            }
            let mut mic = [0u8; MIC_LENGTH];
            mic.copy_from_slice(&rest[..MIC_LENGTH]);
            Ok(Fragment {
                rule_id,
                window,
                fcn,
                payload: &rest[MIC_LENGTH..],
                mic,
            })
        } else {
            Ok(Fragment {
                rule_id,
                window,
                fcn,
                payload: rest,
                mic: [0u8; MIC_LENGTH],
            })
        }
    }
}

// ─── Ack ──────────────────────────────────────────────────────────────────────

/// An ACK-on-Error acknowledgement bitmap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    pub rule_id: u8,
    pub window: u8,
    pub bitmap_len: usize,
    pub bitmap: [bool; MAX_WINDOW_SIZE],
    pub complete: bool,
}

impl Ack {
    pub fn new(rule_id: u8, window: u8, received: &[bool], complete: bool) -> Self {
        let mut bitmap = [false; MAX_WINDOW_SIZE];
        let len = received.len().min(MAX_WINDOW_SIZE);
        bitmap[..len].copy_from_slice(&received[..len]);
        Ack {
            rule_id,
            window,
            bitmap_len: len,
            bitmap,
            complete,
        }
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, FragmentError> {
        let n = self.bitmap_len;
        let body_bytes = n.div_ceil(8);
        let needed = 3 + body_bytes;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[0] = self.rule_id;
        out[1] = ((self.window & 1) << FRAGMENT_N) | (if self.complete { 1 } else { 0 });
        out[2] = n as u8;
        for b in out[3..3 + body_bytes].iter_mut() {
            *b = 0;
        }
        for (i, &received) in self.bitmap[..n].iter().enumerate() {
            if received {
                out[3 + i / 8] |= 1 << (7 - (i % 8));
            }
        }
        Ok(needed)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, FragmentError> {
        if data.len() < 3 {
            return Err(TooShort::new(3, data.len()).into());
        }
        let rule_id = data[0];
        let window = (data[1] >> FRAGMENT_N) & 1;
        let complete = (data[1] & 0x01) != 0;
        let n = data[2] as usize;
        let body_bytes = n.div_ceil(8);
        let required = 3 + body_bytes;
        if data.len() < required {
            return Err(TooShort::new(required, data.len()).into());
        }
        let body = &data[3..];
        let mut bitmap = [false; MAX_WINDOW_SIZE];
        for i in 0..n.min(MAX_WINDOW_SIZE) {
            let byte = body[i / 8];
            bitmap[i] = (byte >> (7 - (i % 8))) & 1 != 0;
        }
        Ok(Ack {
            rule_id,
            window,
            bitmap_len: n.min(MAX_WINDOW_SIZE),
            bitmap,
            complete,
        })
    }
}

// ─── FragmentSender ───────────────────────────────────────────────────────────

/// Splits a payload into SCHC fragments with window/FCN scheduling.
///
/// Computes the MIC (CRC32) eagerly; all other data is computed on demand.
#[derive(Debug)]
pub struct FragmentSender<'a> {
    payload: &'a [u8],
    pub rule_id: u8,
    tile_size: usize,
    window_size: usize,
    mic: [u8; MIC_LENGTH],
    count: usize,
}

impl<'a> FragmentSender<'a> {
    pub fn new(
        payload: &'a [u8],
        rule_id: u8,
        tile_size: usize,
        window_size: usize,
    ) -> Result<Self, FragmentError> {
        if tile_size == 0 {
            return Err(BufferTooSmall::new(1, 0).into());
        }
        if window_size == 0 || window_size > MAX_WINDOW_SIZE {
            return Err(FragmentError::InvalidWindowSize);
        }
        if payload.len() > SCHC_MAX_DECOMPRESSED {
            return Err(BufferTooSmall::new(SCHC_MAX_DECOMPRESSED, payload.len()).into());
        }
        let mic = compute_mic(payload);
        let count = if payload.is_empty() {
            1
        } else {
            payload.len().div_ceil(tile_size)
        };
        Ok(FragmentSender {
            payload,
            rule_id,
            tile_size,
            window_size,
            mic,
            count,
        })
    }

    pub fn fragment_count(&self) -> usize {
        self.count
    }

    pub fn window_count(&self) -> usize {
        self.count.div_ceil(self.window_size)
    }

    /// Get the tile payload slice for fragment `index`.
    fn tile(&self, index: usize) -> &'a [u8] {
        let start = index * self.tile_size;
        let end = (start + self.tile_size).min(self.payload.len());
        &self.payload[start..end]
    }

    /// Build the fragment at `index`.
    pub fn get_fragment(&self, index: usize) -> Option<Fragment<'a>> {
        if index >= self.count {
            return None;
        }
        let is_last = index == self.count - 1;
        let abs_window = index / self.window_size;
        let pos = index % self.window_size;
        let wire_window = (abs_window % 2) as u8;
        let fcn = if is_last {
            ALL_1_FCN
        } else {
            (self.window_size - 1 - pos) as u8
        };
        let mic = if is_last { self.mic } else { [0u8; MIC_LENGTH] };
        Some(Fragment {
            rule_id: self.rule_id,
            window: wire_window,
            fcn,
            payload: self.tile(index),
            mic,
        })
    }

    /// Fragments belonging to absolute window `abs_window`.
    pub fn fragments_in_window(&self, abs_window: usize) -> FragmentsInWindow<'_, 'a> {
        let start = abs_window * self.window_size;
        let end = (start + self.window_size).min(self.count);
        FragmentsInWindow {
            sender: self,
            current: start,
            end,
        }
    }

    /// Iterate all fragments in transmission order.
    pub fn iter(&self) -> FragmentIter<'_, 'a> {
        FragmentIter {
            sender: self,
            index: 0,
        }
    }

    /// Fragments that were not acknowledged in `abs_window` (positional bitmap).
    pub fn retransmit<'b>(
        &'a self,
        abs_window: usize,
        bitmap: &'b [bool],
    ) -> RetransmitIter<'a, 'b> {
        let start = abs_window * self.window_size;
        let end = (start + self.window_size).min(self.count);
        RetransmitIter {
            sender: self,
            start,
            end,
            bitmap,
            pos: start,
        }
    }
}

#[derive(Debug)]
pub struct FragmentIter<'s, 'p> {
    sender: &'s FragmentSender<'p>,
    index: usize,
}

impl<'s, 'p> Iterator for FragmentIter<'s, 'p> {
    type Item = Fragment<'p>;
    fn next(&mut self) -> Option<Self::Item> {
        let f = self.sender.get_fragment(self.index)?;
        self.index += 1;
        Some(f)
    }
}

#[derive(Debug)]
pub struct FragmentsInWindow<'s, 'p> {
    sender: &'s FragmentSender<'p>,
    current: usize,
    end: usize,
}

impl<'s, 'p> Iterator for FragmentsInWindow<'s, 'p> {
    type Item = Fragment<'p>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.end {
            return None;
        }
        let f = self.sender.get_fragment(self.current)?;
        self.current += 1;
        Some(f)
    }
}

#[derive(Debug)]
pub struct RetransmitIter<'s, 'b> {
    sender: &'s FragmentSender<'s>,
    start: usize,
    end: usize,
    bitmap: &'b [bool],
    pos: usize,
}

impl<'s, 'b> Iterator for RetransmitIter<'s, 'b> {
    type Item = Fragment<'s>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos >= self.end {
                return None;
            }
            let abs_pos = self.pos;
            let rel_pos = abs_pos - self.start;
            self.pos += 1;
            let received = rel_pos < self.bitmap.len() && self.bitmap[rel_pos];
            if !received {
                return self.sender.get_fragment(abs_pos);
            }
        }
    }
}

// ─── std-only: all_fragments + FragmentReceiver ───────────────────────────────

#[cfg(feature = "std")]
pub use std_ext::*;

#[cfg(feature = "std")]
mod std_ext {
    extern crate std;
    use std::collections::{HashMap, HashSet};
    use std::vec::Vec;

    use super::*;

    impl<'a> FragmentSender<'a> {
        /// Collect all fragments into a Vec (convenience for tests and sim).
        pub fn all_fragments(&self) -> Vec<Fragment<'a>> {
            self.iter().collect()
        }

        pub fn fragments_in_window_vec(&self, abs_window: usize) -> Vec<Fragment<'a>> {
            self.fragments_in_window(abs_window).collect()
        }
    }

    /// Reassembles a single datagram from ACK-on-Error fragments.
    #[derive(Debug)]
    pub struct FragmentReceiver {
        window_size: usize,
        rule_id: u8,
        tiles: HashMap<usize, Vec<u8>>,
        current_window: usize,
        completed_windows: HashSet<usize>,
        all1_seen: bool,
        all1_window: usize,
        all1_payload: Vec<u8>,
        mic: [u8; MIC_LENGTH],
        pub done: bool,
        pub reassembled: Option<Vec<u8>>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ReceiverResult {
        pub ack: Option<Ack>,
        pub reassembled: Option<Vec<u8>>,
        pub mic_ok: Option<bool>,
    }

    impl FragmentReceiver {
        pub fn new(window_size: usize) -> Self {
            FragmentReceiver {
                window_size,
                rule_id: 0,
                tiles: HashMap::new(),
                current_window: 0,
                completed_windows: HashSet::new(),
                all1_seen: false,
                all1_window: 0,
                all1_payload: Vec::new(),
                mic: [0u8; MIC_LENGTH],
                done: false,
                reassembled: None,
            }
        }

        fn abs_window(&self, frag: &Fragment<'_>) -> usize {
            if !frag.is_all_1() {
                let pos = self.window_size - 1 - frag.fcn as usize;
                let parity = frag.window as usize;
                let current_parity = self.current_window % 2;
                let mut older = if parity == current_parity {
                    if self.current_window >= 2 { self.current_window - 2 } else { 0 }
                } else {
                    if self.current_window >= 1 { self.current_window - 1 } else { 0 }
                };
                while older > 0 {
                    if !self.completed_windows.contains(&older) {
                        let older_idx = older * self.window_size + pos;
                        if self.tiles.contains_key(&older_idx) {
                            // duplicate or filled; continue to find gap or treat as current
                        } else {
                            // gap in incomplete older window: likely retransmission
                            return older;
                        }
                    } else if self.tiles.contains_key(&(older * self.window_size + pos)) {
                        return older;
                    }
                    older = older.saturating_sub(2);
                }
            }
            if frag.window == (self.current_window % 2) as u8 {
                self.current_window
            } else {
                self.current_window + 1
            }
        }

        fn window_bitmap(&self, abs_window: usize) -> Vec<bool> {
            let base = abs_window * self.window_size;
            (0..self.window_size)
                .map(|p| self.tiles.contains_key(&(base + p)))
                .collect()
        }

        fn window_full(&self, abs_window: usize) -> bool {
            let base = abs_window * self.window_size;
            (0..self.window_size).all(|p| self.tiles.contains_key(&(base + p)))
        }

        pub fn receive(&mut self, frag: &Fragment<'_>) -> ReceiverResult {
            if self.done {
                return ReceiverResult {
                    ack: None,
                    reassembled: None,
                    mic_ok: None,
                };
            }
            if self.rule_id == 0 {
                self.rule_id = frag.rule_id;
            } else if self.rule_id != frag.rule_id {
                return ReceiverResult {
                    ack: None,
                    reassembled: None,
                    mic_ok: None,
                };
            }
            let abs_window = self.abs_window(frag);
            if abs_window > self.current_window + 1 {
                return ReceiverResult {
                    ack: None,
                    reassembled: None,
                    mic_ok: None,
                };
            }
            self.current_window = abs_window;

            if frag.is_all_1() {
                self.all1_seen = true;
                self.all1_window = abs_window;
                self.all1_payload = frag.payload.to_vec();
                self.mic = frag.mic;
                return self.finalize();
            }

            if frag.fcn as usize >= self.window_size {
                return ReceiverResult {
                    ack: None,
                    reassembled: None,
                    mic_ok: None,
                };
            }
            let pos = self.window_size - 1 - frag.fcn as usize;
            let global_idx = abs_window * self.window_size + pos;
            self.tiles.insert(global_idx, frag.payload.to_vec());

            if self.all1_seen {
                return self.finalize();
            }

            if frag.is_all_0() || self.window_full(abs_window) {
                let bitmap = self.window_bitmap(abs_window);
                if self.window_full(abs_window) {
                    self.current_window = abs_window + 1;
                }
                return ReceiverResult {
                    ack: Some(Ack::new(
                        self.rule_id,
                        (abs_window % 2) as u8,
                        &bitmap,
                        false,
                    )),
                    reassembled: None,
                    mic_ok: None,
                };
            }
            ReceiverResult {
                ack: None,
                reassembled: None,
                mic_ok: None,
            }
        }

        fn finalize(&mut self) -> ReceiverResult {
            let bitmap = self.window_bitmap(self.all1_window);
            let nack = Ack::new(self.rule_id, (self.all1_window % 2) as u8, &bitmap, false);

            // O(n) contiguity check: if we have n tiles and max index is n-1,
            // all indices 0..n must be present (HashMap keys are unique).
            let n = self.tiles.len();
            let contiguous = n > 0 && self.tiles.keys().max() == Some(&(n - 1));
            if !contiguous {
                return ReceiverResult {
                    ack: Some(nack),
                    reassembled: None,
                    mic_ok: None,
                };
            }

            let mut data: Vec<u8> = Vec::new();
            for i in 0..n {
                data.extend_from_slice(self.tiles[&i].as_slice());
            }
            data.extend_from_slice(&self.all1_payload);

            if compute_mic(&data) == self.mic {
                self.done = true;
                self.reassembled = Some(data.clone());
                ReceiverResult {
                    ack: Some(Ack::new(
                        self.rule_id,
                        (self.all1_window % 2) as u8,
                        &bitmap,
                        true,
                    )),
                    reassembled: Some(data),
                    mic_ok: Some(true),
                }
            } else {
                ReceiverResult {
                    ack: Some(nack),
                    reassembled: None,
                    mic_ok: Some(false),
                }
            }
        }
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    use super::*;

    #[test]
    fn compute_mic_crc32_canonical() {
        // crc32("123456789") == 0xCBF43926
        assert_eq!(compute_mic(b"123456789"), [0xCB, 0xF4, 0x39, 0x26]);
    }

    #[test]
    fn fragment_regular_round_trip() {
        let payload = b"tile";
        let frag = Fragment {
            rule_id: 20,
            window: 1,
            fcn: 5,
            payload,
            mic: [0u8; MIC_LENGTH],
        };
        let mut buf = [0u8; 16];
        let n = frag.write_to(&mut buf).unwrap();
        // Header: rule_id=20, then (1<<6)|5 = 0x45
        assert_eq!(buf[0], 20);
        assert_eq!(buf[1], 0x45);
        let restored = Fragment::from_bytes(&buf[..n]).unwrap();
        assert_eq!(restored.rule_id, frag.rule_id);
        assert_eq!(restored.window, frag.window);
        assert_eq!(restored.fcn, frag.fcn);
        assert_eq!(restored.payload, frag.payload);
    }

    #[test]
    fn fragment_all1_carries_mic() {
        let mic = compute_mic(b"payload");
        let frag = Fragment {
            rule_id: 20,
            window: 0,
            fcn: ALL_1_FCN,
            payload: b"end",
            mic,
        };
        let mut buf = [0u8; 16];
        let n = frag.write_to(&mut buf).unwrap();
        // Header byte: (0<<6)|63 = 0x3F
        assert_eq!(buf[0], 20);
        assert_eq!(buf[1], ALL_1_FCN);
        assert_eq!(&buf[2..6], &mic);
        let restored = Fragment::from_bytes(&buf[..n]).unwrap();
        assert!(restored.is_all_1());
        assert_eq!(restored.mic, mic);
        assert_eq!(restored.payload, b"end");
    }

    #[test]
    fn all1_with_zero_mic_succeeds() {
        // Zero MIC is valid (CRC32 of empty payload), must not be rejected.
        let frag = Fragment {
            rule_id: 1,
            window: 0,
            fcn: ALL_1_FCN,
            payload: b"",
            mic: compute_mic(b""), // [0,0,0,0]
        };
        assert_eq!(frag.mic, [0u8; MIC_LENGTH]);
        let mut buf = [0u8; 16];
        assert!(frag.write_to(&mut buf).is_ok());
    }

    #[test]
    fn empty_payload_fragment_round_trip() {
        // Empty datagram -> single All-1 fragment with zero MIC.
        let sender = FragmentSender::new(b"", 20, 10, DEFAULT_WINDOW_SIZE).unwrap();
        let frags: Vec<_> = sender.iter().collect();
        assert_eq!(frags.len(), 1);
        assert!(frags[0].is_all_1());
        assert_eq!(frags[0].payload, b"");
        assert_eq!(frags[0].mic, compute_mic(b""));

        // Serialize and parse back.
        let mut buf = [0u8; 16];
        let n = frags[0].write_to(&mut buf).unwrap();
        let restored = Fragment::from_bytes(&buf[..n]).unwrap();
        assert!(restored.is_all_1());
        assert_eq!(restored.mic, frags[0].mic);
    }

    #[test]
    fn window_fcn_schedule() {
        let payload: Vec<u8> = (0u8..7).collect();
        let sender = FragmentSender::new(&payload, 20, 1, 3).unwrap();
        let frags: Vec<_> = sender.iter().collect();
        assert_eq!(sender.fragment_count(), 7);
        let schedule: Vec<(u8, u8)> = frags.iter().map(|f| (f.window, f.fcn)).collect();
        assert_eq!(
            schedule,
            vec![
                (0, 2),
                (0, 1),
                (0, 0), // window 0
                (1, 2),
                (1, 1),
                (1, 0),         // window 1
                (0, ALL_1_FCN), // window 2 (wire bit 0), final
            ]
        );
        // Only the last fragment carries a MIC.
        assert_eq!(frags.last().unwrap().mic, compute_mic(&payload));
        assert!(frags[..6].iter().all(|f| f.mic == [0u8; MIC_LENGTH]));
    }

    #[test]
    fn single_fragment_datagram() {
        let sender = FragmentSender::new(b"hi", 20, 10, DEFAULT_WINDOW_SIZE).unwrap();
        let frags: Vec<_> = sender.iter().collect();
        assert_eq!(frags.len(), 1);
        assert!(frags[0].is_all_1());
        assert_eq!(frags[0].payload, b"hi");
    }

    #[test]
    fn window_count_and_fragments_in_window() {
        let payload: Vec<u8> = (0u8..7).collect();
        let sender = FragmentSender::new(&payload, 20, 1, 3).unwrap();
        assert_eq!(sender.window_count(), 3);
        assert_eq!(sender.fragments_in_window(0).count(), 3);
        assert_eq!(sender.fragments_in_window(2).count(), 1);
    }

    #[test]
    fn ack_round_trip() {
        let bitmap = [true, false, true, true, false, false, false];
        let ack = Ack::new(20, 0, &bitmap, false);
        let mut buf = [0u8; 16];
        let n = ack.write_to(&mut buf).unwrap();
        let restored = Ack::from_bytes(&buf[..n]).unwrap();
        assert_eq!(restored.rule_id, 20);
        assert_eq!(restored.window, 0);
        assert!(!restored.complete);
        assert_eq!(restored.bitmap_len, 7);
        assert_eq!(&restored.bitmap[..7], &bitmap);
    }

    #[cfg(feature = "std")]
    #[test]
    fn receiver_reassembles_multi_fragment() {
        use super::std_ext::FragmentReceiver;

        let payload: Vec<u8> = (0u8..10).collect();
        let sender = FragmentSender::new(&payload, 20, 3, 4).unwrap();
        let frags: Vec<_> = sender.iter().collect();

        let mut rx = FragmentReceiver::new(4);
        let mut result = None;
        for frag in &frags {
            let r = rx.receive(frag);
            if r.reassembled.is_some() {
                result = r.reassembled;
            }
        }
        assert_eq!(result.as_deref(), Some(payload.as_slice()));
    }

    #[cfg(feature = "std")]
    #[test]
    fn receiver_ignores_fcn_exceeding_window_size() {
        use super::std_ext::FragmentReceiver;

        // Window size 4 means valid FCNs are 0..3. An FCN of 10 exceeds this.
        let mut rx = FragmentReceiver::new(4);
        let bad_frag = Fragment {
            rule_id: 20,
            window: 0,
            fcn: 10, // Invalid: exceeds window_size - 1
            payload: b"bad",
            mic: [0u8; MIC_LENGTH],
        };
        // Should not panic, and should return empty result (fragment ignored).
        let result = rx.receive(&bad_frag);
        assert!(result.ack.is_none());
        assert!(result.reassembled.is_none());
        assert!(result.mic_ok.is_none());
    }
}
