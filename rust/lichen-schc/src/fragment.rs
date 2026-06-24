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

/// 6-bit all-ones FCN, marks the last fragment of a datagram.
pub const ALL_1_FCN: u8 = 63;
/// CRC32 MIC length in bytes.
pub const MIC_LENGTH: usize = 4;
/// Default window size (fragment count per window, excluding the All-1).
pub const DEFAULT_WINDOW_SIZE: usize = 7;
/// Maximum window size (62 regular FCNs, since 63 = ALL_1).
pub const MAX_WINDOW_SIZE: usize = 62;

#[derive(Debug, PartialEq, Eq)]
pub enum FragmentError {
    TooShort,
    InvalidFcn,
    InvalidWindow,
    MicMissing,
    BufferTooSmall,
    InvalidWindowSize,
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
    pub fn to_bytes(&self, out: &mut [u8]) -> Result<usize, FragmentError> {
        if self.window > 1 {
            return Err(FragmentError::InvalidWindow);
        }
        if self.fcn > ALL_1_FCN {
            return Err(FragmentError::InvalidFcn);
        }
        if self.is_all_1() && self.mic == [0u8; MIC_LENGTH] {
            return Err(FragmentError::MicMissing);
        }
        let extra = if self.is_all_1() { MIC_LENGTH } else { 0 };
        let needed = 2 + extra + self.payload.len();
        if out.len() < needed {
            return Err(FragmentError::BufferTooSmall);
        }
        out[0] = self.rule_id;
        out[1] = ((self.window & 1) << 6) | (self.fcn & 0x3F);
        if self.is_all_1() {
            out[2..6].copy_from_slice(&self.mic);
            out[6..6 + self.payload.len()].copy_from_slice(self.payload);
        } else {
            out[2..2 + self.payload.len()].copy_from_slice(self.payload);
        }
        Ok(needed)
    }

    /// Parse a fragment from `data`, borrowing the payload slice.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, FragmentError> {
        if data.len() < 2 {
            return Err(FragmentError::TooShort);
        }
        let rule_id = data[0];
        let window = (data[1] >> 6) & 1;
        let fcn = data[1] & 0x3F;
        let rest = &data[2..];
        if fcn == ALL_1_FCN {
            if rest.len() < MIC_LENGTH {
                return Err(FragmentError::TooShort);
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
#[derive(Debug, PartialEq, Eq)]
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

    pub fn to_bytes(&self, out: &mut [u8]) -> Result<usize, FragmentError> {
        let n = self.bitmap_len;
        let body_bytes = n.div_ceil(8);
        let needed = 3 + body_bytes;
        if out.len() < needed {
            return Err(FragmentError::BufferTooSmall);
        }
        out[0] = self.rule_id;
        out[1] = ((self.window & 1) << 6) | (if self.complete { 1 } else { 0 });
        out[2] = n as u8;
        // Pack bitmap MSB-first
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
            return Err(FragmentError::TooShort);
        }
        let rule_id = data[0];
        let window = (data[1] >> 6) & 1;
        let complete = (data[1] & 0x01) != 0;
        let n = data[2] as usize;
        let body = &data[3..];
        let mut bitmap = [false; MAX_WINDOW_SIZE];
        for i in 0..n.min(MAX_WINDOW_SIZE) {
            let byte = if i / 8 < body.len() { body[i / 8] } else { 0 };
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
            return Err(FragmentError::BufferTooSmall);
        }
        if window_size == 0 || window_size > MAX_WINDOW_SIZE {
            return Err(FragmentError::InvalidWindowSize);
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
    use std::collections::HashMap;
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
    pub struct FragmentReceiver {
        window_size: usize,
        rule_id: u8,
        tiles: HashMap<usize, Vec<u8>>,
        current_window: usize,
        all1_seen: bool,
        all1_window: usize,
        all1_payload: Vec<u8>,
        mic: [u8; MIC_LENGTH],
        pub done: bool,
        pub reassembled: Option<Vec<u8>>,
    }

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
                all1_seen: false,
                all1_window: 0,
                all1_payload: Vec::new(),
                mic: [0u8; MIC_LENGTH],
                done: false,
                reassembled: None,
            }
        }

        fn abs_window(&self, frag: &Fragment<'_>) -> usize {
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
            self.rule_id = frag.rule_id;
            let abs_window = self.abs_window(frag);
            self.current_window = abs_window;

            if frag.is_all_1() {
                self.all1_seen = true;
                self.all1_window = abs_window;
                self.all1_payload = frag.payload.to_vec();
                self.mic = frag.mic;
                return self.finalize();
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

            let mut indices: Vec<usize> = self.tiles.keys().cloned().collect();
            indices.sort_unstable();
            let expected: Vec<usize> = (0..indices.len()).collect();
            if indices != expected {
                return ReceiverResult {
                    ack: Some(nack),
                    reassembled: None,
                    mic_ok: None,
                };
            }

            let mut data: Vec<u8> = Vec::new();
            for i in &indices {
                data.extend_from_slice(self.tiles[i].as_slice());
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
        let n = frag.to_bytes(&mut buf).unwrap();
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
        let n = frag.to_bytes(&mut buf).unwrap();
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
    fn all1_without_mic_errors() {
        let frag = Fragment {
            rule_id: 1,
            window: 0,
            fcn: ALL_1_FCN,
            payload: b"x",
            mic: [0u8; MIC_LENGTH],
        };
        let mut buf = [0u8; 16];
        assert_eq!(frag.to_bytes(&mut buf), Err(FragmentError::MicMissing));
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
        let n = ack.to_bytes(&mut buf).unwrap();
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
}
